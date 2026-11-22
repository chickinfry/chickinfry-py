"""Generated dispatch wires Operation codecs with public context factories.

Application serves size-limited HTTP requests, and create_worker_entrypoint
connects to the host-provided workers module without adding a host dependency
to the CPython installation.
"""

import asyncio
import json
import re
import sys
from collections.abc import (
    AsyncIterator,
    Awaitable,
    Callable,
    Iterator,
    Mapping,
    Sequence,
)
from dataclasses import dataclass, field
from importlib import import_module
from types import MappingProxyType
from typing import TYPE_CHECKING, Generic, Protocol, TypeVar, cast, overload
from urllib.parse import urlsplit

from ._error_details import FieldError as FieldError
from ._error_details import _fields, _message, _string

if TYPE_CHECKING:
    from .auth import AuthHooks, IdentityProvider

Input = TypeVar("Input")
Output = TypeVar("Output")
C = TypeVar("C")
S = TypeVar("S")
Options = TypeVar("Options")
_C = TypeVar("_C", contravariant=True)
MAX_REQUEST_BYTES = 4 * 1024 * 1024


class OperationError(Exception):
    """An explicitly trusted business error; received SDK errors are not trusted automatically."""

    def __init__(
        self,
        code: str,
        status: int,
        message: str | None = None,
        fields: tuple[FieldError, ...] = (),
    ) -> None:
        self.code, self.status = code, status
        self.message, self.fields = message, fields
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
class AuthContext(Generic[S]):
    session: S


class Request(Protocol):
    @property
    def method(self) -> str: ...
    @property
    def url(self) -> str: ...
    @property
    def headers(self) -> Mapping[str, str]: ...
    def chunks(self) -> AsyncIterator[bytes]: ...
    async def cancel(self) -> None: ...


@dataclass(frozen=True, slots=True, repr=False)
class RequestInfo:
    """Immutable request metadata, without a body reader or host references."""

    method: str
    path: str
    headers: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "headers",
            MappingProxyType(
                {
                    key.lower(): value
                    for key, value in self.headers.items()
                    if key.lower() != "proxy-authorization"
                }
            ),
        )

    @classmethod
    def from_request(cls, request: Request, *, uses_auth: bool) -> "RequestInfo":
        return cls(
            request.method,
            operation_path(urlsplit(request.url).path or "/"),
            {
                key: value
                for key, value in request.headers.items()
                if not uses_auth or key.lower() not in {"authorization", "cookie"}
            },
        )


# A web app address forwards /api/<service>.<operation> unchanged (SAME-ORIGIN-DEFAULT);
# every server language resolves it exactly as /<service>.<operation>.
_API_OPERATION_PATH = re.compile(r"/api/[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*")


def operation_path(path: str) -> str:
    """Return the operation path that a reserved /api path stands for."""
    return path[4:] if _API_OPERATION_PATH.fullmatch(path) else path


@dataclass(frozen=True, slots=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str]


class DispatchOperation(Protocol[_C]):
    """Receives raw JSON so authorization wrappers can defer input decoding."""

    @property
    def input_fields(self) -> frozenset[str]: ...
    def prepare(self, value: object) -> Callable[[_C], Awaitable[object]]: ...


@dataclass(frozen=True, slots=True)
class Operation(Generic[Input, Output, C]):
    """Connects the generated input decoder, exact async method, and output encoder."""

    decode: Callable[[Mapping[str, object]], Input]
    invoke: Callable[[C, Input], Awaitable[Output]]
    encode: Callable[[Output], object]
    input_fields: frozenset[str] = frozenset()

    def prepare(self, value: object) -> Callable[[C], Awaitable[object]]:
        try:
            decoded = self.decode(_input_record(value))
        except OperationError as error:
            if error.code == "request_too_large" and error.status == 413:
                raise
            raise OperationError("invalid_input", 400) from None
        except Exception:
            raise OperationError("invalid_input", 400) from None

        async def run(context: C) -> object:
            result = await self.invoke(context, decoded)
            try:
                return self.encode(result)
            except Exception:
                raise OperationError("operation_failed", 500) from None

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
        raise OperationError("invalid_input", 400)
    return cast(Mapping[str, object], value)


def _error_response(
    error: Exception, headers: Mapping[str, str], declared: object
) -> Response:
    try:
        if isinstance(error, OperationError):
            code, status = _string(error.code), error.status
            if (
                code is not None
                and re.fullmatch(r"[a-z_]{1,64}", code)
                and type(status) is int
                and 400 <= status <= 599
            ):
                body: dict[str, object] = {"error": code}
                try:
                    message = _message(error.message)
                except Exception:
                    message = None
                if message is not None:
                    body["message"] = message
                try:
                    fields = (
                        _fields(
                            error.fields,
                            declared
                            if isinstance(declared, frozenset)
                            else frozenset(),
                        )
                        if code == "invalid_input"
                        else ()
                    )
                except Exception:
                    fields = ()
                if fields:
                    body["fields"] = [
                        {"path": item.path, "code": item.code} for item in fields
                    ]
                return Response(
                    status, json.dumps(body, separators=(",", ":")).encode(), headers
                )
    except Exception:
        pass
    return Response(500, b'{"error":"operation_failed"}', headers)


class Application(Generic[C]):
    """Operation preparation controls validation before the request scope opens."""

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
        input_fields: frozenset[str] = frozenset()
        try:
            origin = request.headers.get("origin")
            if origin is not None:
                if origin not in self.origins:
                    raise OperationError("origin_denied", 403)
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
                raise OperationError("not_found", 404)
            path = operation_path(url.path)
            operation = self.operations.get(path[1:]) if path.startswith("/") else None
            if operation is None:
                raise OperationError("not_found", 404)
            if (
                request.headers.get("content-type", "").split(";", 1)[0]
                != "application/json"
            ):
                raise OperationError("unsupported_media_type", 415)
            body = bytearray()
            try:
                async for chunk in request.chunks():
                    if len(body) + len(chunk) > MAX_REQUEST_BYTES:
                        raise OperationError("request_too_large", 413)
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
                raise OperationError("invalid_json", 400) from None
            input_fields = operation.input_fields
            prepared = operation.prepare(value)
            scope = await self.open_scope(request)
            output = await prepared(scope.context)
            encoded = json.dumps(
                output, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            ).encode("utf-8")
            return Response(200, encoded, headers)
        except Exception as error:
            return _error_response(error, headers, input_fields)
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
        raise OperationError("invalid_token", 401)
    return match[1]


class _JSHeaders(Protocol):
    def get(self, key: str) -> str | None: ...
    def keys(self) -> Iterator[str]: ...


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
            key.lower(): value
            for key in self.source.headers.keys()
            if key.lower() != "proxy-authorization"
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


@dataclass(frozen=True, slots=True)
class _SetupFailure:
    cancelled: bool


# The realtime decision receives the application options, the request
# environment, the revalidated session, the verified WebSocket origin and app
# origin, and the channel.
RealtimeDecision = Callable[
    [object, object, Session | None, str | None, str, str], Awaitable[bool]
]


@overload
def create_worker_entrypoint(
    factory: Callable[[object, object], Application[C]],
    *,
    _secret_names: tuple[str, ...] = (),
    _vault: bool = False,
    _storage_names: tuple[str, ...] = (),
    _realtime: bool = False,
    _realtime_origins: frozenset[str] = frozenset(),
    _realtime_decide: RealtimeDecision | None = None,
) -> type[object]: ...


@overload
def create_worker_entrypoint(
    factory: Callable[[object, object, Options], Application[C]],
    *,
    setup: Callable[[], Awaitable[Options]],
    _secret_names: tuple[str, ...] = (),
    _vault: bool = False,
    _storage_names: tuple[str, ...] = (),
    _auth_config: str | None = None,
    _auth_hooks: Callable[[Options], "tuple[AuthHooks, Sequence[IdentityProvider]]"]
    | None = None,
    _realtime: bool = False,
    _realtime_origins: frozenset[str] = frozenset(),
    _realtime_decide: RealtimeDecision | None = None,
) -> type[object]: ...


def create_worker_entrypoint(
    factory: Callable[[object, object], Application[C]]
    | Callable[[object, object, Options], Application[C]],
    *,
    setup: Callable[[], Awaitable[Options]] | None = None,
    _secret_names: tuple[str, ...] = (),
    _vault: bool = False,
    _storage_names: tuple[str, ...] = (),
    _auth_config: str | None = None,
    _auth_hooks: Callable[[Options], "tuple[AuthHooks, Sequence[IdentityProvider]]"]
    | None = None,
    _realtime: bool = False,
    _realtime_origins: frozenset[str] = frozenset(),
    _realtime_decide: RealtimeDecision | None = None,
) -> type[object]:
    """Generated create_application returns a Default class composed with the factory.

    The factory receives the trusted environment and execution context per
    request and opens no connection at import time. Optional setup runs once
    per entrypoint instance, before its first application is created. Its result
    or failure is retained, and cancelling a waiter does not cancel setup.
    """
    host = import_module("workers")
    base = cast(type[object], host.WorkerEntrypoint)
    response_factory = cast(_HostResponse, host.Response)

    async def fetch(self: _Worker, request: _JSRequest) -> object:
        environment = self.env
        if sys.platform == "emscripten":
            environment = getattr(self.env, "CHIK_LOCAL_BINDINGS", self.env)
        incoming = request
        options: Options | None = None
        if setup is not None:
            task = cast(
                asyncio.Task[Options | _SetupFailure] | None,
                getattr(self, "_chickinfry_setup", None),
            )
            if task is None:

                async def initialize() -> Options | _SetupFailure:
                    try:
                        return await setup()
                    except (Exception, asyncio.CancelledError) as error:
                        # Retained exceptions can acquire request frames when awaited.
                        return _SetupFailure(isinstance(error, asyncio.CancelledError))

                task = asyncio.create_task(initialize())
                setattr(self, "_chickinfry_setup", task)
            resolved = await asyncio.shield(task)
            if isinstance(resolved, _SetupFailure):
                if resolved.cancelled:
                    raise asyncio.CancelledError from None
                raise RuntimeError("Application setup failed.") from None
            options = resolved
            if _realtime and sys.platform == "emscripten":
                from ._workerd import _realtime_authorize_path, _realtime_request

                # The engine callback carries its own proof and no session, so it
                # skips session authentication and is answered by the JS host.
                if _realtime_authorize_path(request):
                    return await _realtime_request(
                        incoming,
                        self.ctx,
                        environment,
                        options,
                        _auth_config,
                        _realtime_origins,
                        _realtime_decide,
                    )
            if (
                sys.platform == "emscripten"
                and _auth_config is not None
                and _auth_hooks is not None
            ):
                from ._workerd import _authenticate

                hooks, providers = _auth_hooks(options)
                response, request = await _authenticate(
                    request, _auth_config, hooks, providers
                )
                if response is not None:
                    return response
        if _realtime and sys.platform == "emscripten":
            from ._workerd import _realtime_request

            early = await _realtime_request(
                incoming,
                self.ctx,
                environment,
                options,
                _auth_config,
                _realtime_origins,
                _realtime_decide,
            )
            if early is not None:
                return early
        application = (
            cast(Callable[[object, object], Application[C]], factory)(
                environment, self.ctx
            )
            if setup is None
            else cast(Callable[[object, object, Options], Application[C]], factory)(
                environment, self.ctx, cast(Options, options)
            )
        )
        response = await application.fetch(_HostRequest(request))
        return response_factory(
            response.body.decode() if response.body else None,
            status=response.status,
            headers=response.headers,
        )

    if sys.platform == "emscripten":
        from ._workerd import _fetch

        original = fetch

        async def workerd_fetch(self: _Worker, request: _JSRequest) -> object:
            return await _fetch(
                original,
                self,
                request,
                _secret_names,
                _vault,
                auth=_auth_config is not None,
                storage_names=_storage_names,
            )

        return type("Default", (base,), {"fetch": workerd_fetch})

    return type("Default", (base,), {"fetch": fetch})
