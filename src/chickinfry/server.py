"""Generated dispatch wires Operation codecs with public context factories.

Application serves size-limited HTTP requests, and create_worker_entrypoint
connects to the host-provided workers module without adding a host dependency
to the CPython installation.
"""

import json
import re
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from importlib import import_module
from typing import Generic, Protocol, TypeVar, cast
from urllib.parse import urlsplit

Input = TypeVar("Input")
Output = TypeVar("Output")
C = TypeVar("C")
D = TypeVar("D")
_C = TypeVar("_C", contravariant=True)
MAX_REQUEST_BYTES = 4 * 1024 * 1024
_STATUSES = frozenset({400, 401, 403, 404, 409, 413, 415, 429, 500, 503})


class ServerError(Exception):
    """An explicitly trusted business error; received SDK errors are not trusted automatically."""

    def __init__(self, code: str, status: int) -> None:
        self.code, self.status = code, status
        super().__init__("Operation failed.")


@dataclass(frozen=True, slots=True)
class User:
    id: str
    email: str


@dataclass(frozen=True, slots=True)
class Session:
    id: str
    user: User


@dataclass(frozen=True, slots=True)
class Context(Generic[D]):
    session: Session | None = None
    db: D | None = None


def require_session(context: Context[D]) -> Session:
    if context.session is None:
        raise ServerError("unauthenticated", 401)
    return context.session


class Request(Protocol):
    @property
    def method(self) -> str: ...
    @property
    def url(self) -> str: ...
    @property
    def headers(self) -> Mapping[str, str]: ...
    def chunks(self) -> AsyncIterator[bytes]: ...
    async def cancel(self) -> None: ...


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str]


class DispatchOperation(Protocol[_C]):
    def prepare(
        self, value: Mapping[str, object]
    ) -> Callable[[_C], Awaitable[object]]: ...


@dataclass(frozen=True, slots=True)
class Operation(Generic[Input, Output, C]):
    """Connects the generated input decoder, exact async method, and output encoder."""

    decode: Callable[[Mapping[str, object]], Input]
    invoke: Callable[[C, Input], Awaitable[Output]]
    encode: Callable[[Output], object]

    def prepare(self, value: Mapping[str, object]) -> Callable[[C], Awaitable[object]]:
        try:
            decoded = self.decode(value)
        except Exception:
            raise ServerError("invalid_input", 400) from None

        async def run(context: C) -> object:
            result = await self.invoke(context, decoded)
            try:
                return self.encode(result)
            except Exception:
                raise ServerError("operation_failed", 500) from None

        return run


@dataclass(frozen=True, slots=True)
class RequestScope(Generic[C]):
    """The factory exposes only the public context; close ends the request's DB connection."""

    context: C
    close: Callable[[], Awaitable[None]]


def _invalid_constant(value: str) -> object:
    raise ValueError("Non-standard JSON number.")


def _input_record(value: object) -> Mapping[str, object]:
    if not isinstance(value, dict) or any(not isinstance(key, str) for key in value):
        raise ServerError("invalid_input", 400)
    return cast(Mapping[str, object], value)


class Application(Generic[C]):
    """The scope factory authenticates after input validation and cleans up failures itself."""

    def __init__(
        self,
        operations: Mapping[str, DispatchOperation[C]],
        open_scope: Callable[[Request], Awaitable[RequestScope[C]]],
        *,
        origins: frozenset[str] = frozenset(),
        no_store: bool = False,
    ) -> None:
        if any(
            not re.fullmatch(r"[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*", key)
            for key in operations
        ):
            raise ValueError("Invalid operation name.")
        self.operations = dict(operations)
        self.open_scope = open_scope
        self.origins, self.no_store = origins, no_store

    async def fetch(self, request: Request) -> Response:
        headers = {"Content-Type": "application/json"}
        if self.no_store:
            headers["Cache-Control"] = "no-store"
        scope: RequestScope[C] | None = None
        try:
            origin = request.headers.get("origin")
            if origin is not None:
                if origin not in self.origins:
                    raise ServerError("origin_denied", 403)
                headers.update(
                    {"Access-Control-Allow-Origin": origin, "Vary": "Origin"}
                )
            if request.method == "OPTIONS":
                headers.update(
                    {
                        "Access-Control-Allow-Methods": "POST, OPTIONS",
                        "Access-Control-Allow-Headers": "Content-Type, Authorization",
                    }
                )
                return Response(204, b"", headers)
            url = urlsplit(request.url)
            if (
                request.method != "POST"
                or url.query
                or "?" in request.url
                or url.fragment
            ):
                raise ServerError("not_found", 404)
            operation = (
                self.operations.get(url.path[1:]) if url.path.startswith("/") else None
            )
            if operation is None:
                raise ServerError("not_found", 404)
            if (
                request.headers.get("content-type", "").split(";", 1)[0]
                != "application/json"
            ):
                raise ServerError("unsupported_media_type", 415)
            body = bytearray()
            try:
                async for chunk in request.chunks():
                    if len(body) + len(chunk) > MAX_REQUEST_BYTES:
                        raise ServerError("request_too_large", 413)
                    body.extend(chunk)
            except BaseException:
                try:
                    await request.cancel()
                except Exception:
                    pass
                raise
            try:
                value: object = json.loads(
                    body.decode("utf-8"), parse_constant=_invalid_constant
                )
            except (ValueError, UnicodeError, RecursionError):
                raise ServerError("invalid_json", 400) from None
            prepared = operation.prepare(_input_record(value))
            scope = await self.open_scope(request)
            output = await prepared(scope.context)
            encoded = json.dumps(
                output, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
            return Response(200, encoded, headers)
        except ServerError as error:
            safe = (
                isinstance(error.code, str)
                and re.fullmatch(r"[a-z_]{1,64}", error.code)
                and type(error.status) is int
                and (
                    error.status in _STATUSES
                    or (error.status == 501 and error.code == "not_implemented")
                )
            )
            code, status = (
                (error.code, error.status) if safe else ("operation_failed", 500)
            )
            if status == 501:
                return Response(501, b'{"error":"not_implemented"}', headers)
            return Response(status, json.dumps({"error": code}).encode(), headers)
        except Exception:
            return Response(500, b'{"error":"operation_failed"}', headers)
        finally:
            if scope is not None:
                try:
                    await scope.close()
                except Exception:
                    pass


def bearer(headers: Mapping[str, str]) -> str | None:
    value = headers.get("authorization")
    if value is None:
        return None
    match = re.fullmatch(r"Bearer ([A-Za-z0-9_-]{43})", value, re.IGNORECASE)
    if match is None:
        raise ServerError("invalid_token", 401)
    return match[1]


class _JSHeaders(Protocol):
    def get(self, key: str) -> str | None: ...


class _Bytes(Protocol):
    def to_py(self) -> bytes | bytearray | memoryview: ...


class _ReadResult(Protocol):
    done: bool
    value: _Bytes


class _Reader(Protocol):
    async def read(self) -> _ReadResult: ...
    async def cancel(self) -> None: ...
    def releaseLock(self) -> None: ...


class _Body(Protocol):
    def getReader(self) -> _Reader: ...


class _JSRequest(Protocol):
    method: str
    url: str
    headers: _JSHeaders
    body: _Body | None


@dataclass
class _HostRequest:
    source: _JSRequest
    reader: _Reader | None = field(init=False, default=None)

    @property
    def method(self) -> str:
        return self.source.method

    @property
    def url(self) -> str:
        return self.source.url

    @property
    def headers(self) -> Mapping[str, str]:
        return {
            key: value
            for key in ("origin", "content-type", "authorization")
            if (value := self.source.headers.get(key)) is not None
        }

    async def chunks(self) -> AsyncIterator[bytes]:
        if self.source.body is None:
            return
        reader = self.reader = self.source.body.getReader()
        try:
            while True:
                result = await reader.read()
                if result.done:
                    break
                yield bytes(result.value.to_py())
        finally:
            if self.reader is reader:
                self.reader = None
                reader.releaseLock()

    async def cancel(self) -> None:
        if self.reader is not None:
            reader, self.reader = self.reader, None
            try:
                await reader.cancel()
            finally:
                reader.releaseLock()


class _Worker(Protocol):
    env: object
    ctx: object


class _HostResponse(Protocol):
    def __call__(
        self, body: str | None, *, status: int, headers: Mapping[str, str]
    ) -> object: ...


def create_worker_entrypoint(
    factory: Callable[[object, object], Application[C]],
) -> type[object]:
    """Generated create_application returns a Default class composed with the factory.

    The factory receives the trusted environment and execution context per
    request and opens no connection at import time.
    """
    host = import_module("workers")
    base = cast(type[object], host.WorkerEntrypoint)
    response_factory = cast(_HostResponse, host.Response)

    async def fetch(self: _Worker, request: _JSRequest) -> object:
        response = await factory(self.env, self.ctx).fetch(_HostRequest(request))
        return response_factory(
            response.body.decode() if response.body else None,
            status=response.status,
            headers=response.headers,
        )

    return type("Default", (base,), {"fetch": fetch})
