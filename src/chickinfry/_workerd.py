import asyncio
import json
import math
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextvars import ContextVar
from datetime import date, datetime
from typing import Any, TypeVar
from uuid import UUID

from .orm import DatabasePort, format_timestamp
from .postgres import CommitOutcomeUnknown

T = TypeVar("T")
_MAX_SAFE = 9007199254740991


class _DatabaseFailure(Exception):
    def __init__(self, sqlstate: str | None = None) -> None:
        self.sqlstate = sqlstate
        super().__init__("Database operation failed.")


class _HostRequest:
    def __init__(self, bridge: Any, rid: int) -> None:
        self.bridge, self.rid = bridge, rid
        self.closed = False

    async def finish(self, cancel: bool = False) -> None:
        self.closed = True
        await self.bridge.finish(self.rid, cancel)


_request: ContextVar[_HostRequest | None] = ContextVar(
    "chickinfry_host_request", default=None
)
_active: ContextVar[frozenset[int]] = ContextVar(
    "chickinfry_host_transactions", default=frozenset()
)


def _parameter(value: object) -> object:
    if isinstance(value, datetime):
        return format_timestamp(value)
    if type(value) is date:
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if value is None or type(value) in (str, bool):
        return value
    if (
        (type(value) is int or type(value) is float)
        and abs(value) <= _MAX_SAFE
        and math.isfinite(value)
    ):
        return value
    raise ValueError("A safe database parameter is required.")


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("Invalid database response.")
        output[key] = value
    return output


class _HostPort:
    def __init__(self, _dsn: str | None = None) -> None:
        state = _request.get()
        if state is None or state.closed:
            raise RuntimeError("An active database request is required.")
        self._state = state
        self._closed = False
        self._lock = asyncio.Lock()

    def _check(self) -> None:
        if self._closed or self._state.closed or _request.get() is not self._state:
            raise RuntimeError("The database request is no longer active.")

    async def _call(self, op: str, **fields: object) -> dict[str, Any]:
        self._check()
        frame = json.dumps(
            {"rid": self._state.rid, "op": op, **fields},
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
        ).encode()
        try:
            data = await self._state.bridge.db(frame)
            if len(data) > 4 << 20:
                raise ValueError
            result = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_object,
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
            )
            self._check()
            if not isinstance(result, dict):
                raise ValueError
            if "error" in result:
                if set(result) != {"error"}:
                    raise ValueError
                error = result["error"]
                if error == "commit_unknown":
                    self._closed = True
                    raise CommitOutcomeUnknown()
                if isinstance(error, str) and re.fullmatch(r"[A-Z0-9]{5}", error):
                    raise _DatabaseFailure(error)
                raise _DatabaseFailure()
            return result
        except asyncio.CancelledError:
            await self._state.finish(True)
            raise
        except (CommitOutcomeUnknown, _DatabaseFailure):
            raise
        except Exception:
            raise _DatabaseFailure() from None

    async def _query(
        self, op: str, sql: str, parameters: Sequence[object], **fields: object
    ) -> Sequence[Mapping[str, object]]:
        result = await self._call(
            op, sql=sql, params=[_parameter(value) for value in parameters], **fields
        )
        if (
            set(result) != {"rows"}
            or not isinstance(result["rows"], list)
            or any(not isinstance(row, dict) for row in result["rows"])
        ):
            raise _DatabaseFailure()
        return result["rows"]

    async def query(
        self, sql: str, parameters: Sequence[object]
    ) -> Sequence[Mapping[str, object]]:
        self._check()
        if id(self) in _active.get():
            raise RuntimeError(
                "Root database reentry inside a transaction is not supported."
            )
        async with self._lock:
            return await self._query("query", sql, parameters)

    async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
        self._check()
        if id(self) in _active.get():
            raise RuntimeError("Nested transactions are not supported.")
        async with self._lock:
            response = await self._call("begin")
            lease = response.get("lease")
            if (
                set(response) != {"lease"}
                or type(lease) is not int
                or not 0 < lease <= _MAX_SAFE
            ):
                raise _DatabaseFailure()
            tx = _Transaction(self, lease)
            marker = _active.set(_active.get() | {id(self)})
            committing = False
            try:
                value = await work(tx)
                tx.active = False
                committing = True
                if await self._call("commit", lease=lease) != {}:
                    raise _DatabaseFailure()
                return value
            except BaseException as error:
                tx.active = False
                if isinstance(error, asyncio.CancelledError):
                    await self._state.finish(True)
                    raise
                if not committing and not self._state.closed:
                    try:
                        if await self._call("rollback", lease=lease) != {}:
                            raise _DatabaseFailure()
                    except BaseException:
                        await self._state.finish(True)
                raise
            finally:
                tx.active = False
                _active.reset(marker)

    async def close(self) -> None:
        self._closed = True


class _Transaction:
    def __init__(self, root: _HostPort, lease: int) -> None:
        self.root, self.lease = root, lease
        self.active = True
        self._lock = asyncio.Lock()

    async def query(
        self, sql: str, parameters: Sequence[object]
    ) -> Sequence[Mapping[str, object]]:
        async with self._lock:
            if not self.active:
                raise RuntimeError("The transaction is no longer active.")
            return await self.root._query("exec", sql, parameters, lease=self.lease)

    async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
        raise RuntimeError("Nested transactions are not supported.")


class _JSBridge:
    def __init__(self, host: Any, ffi: Any, js: Any) -> None:
        self.host, self.ffi, self.js = host, ffi, js

    async def db(self, frame: bytes) -> bytes:
        # Copy before yielding; no Python buffer is retained across the Promise.
        data = self.js.Uint8Array.new(self.ffi.to_js(memoryview(frame)))
        result = await getattr(self.js.globalThis, "__chik").db(data)
        return bytes(result.to_py())

    async def finish(self, rid: int, cancel: bool) -> None:
        await self.host.finish(rid, cancel)


async def _fetch(
    fetch: Callable[..., Awaitable[object]], worker: Any, request: Any
) -> object:
    import sys
    from importlib import import_module

    workers = import_module("workers")
    ffi = import_module("pyodide.ffi")
    js = import_module("js")
    host = workers.import_from_javascript("_chik/host.js")
    pyodide = import_module("pyodide")
    host.verify(sys.version.split()[0], pyodide.__version__)
    host.prepare(worker.env)
    state = _HostRequest(_JSBridge(host, ffi, js), host.start(request.js_object.signal))
    marker = _request.set(state)
    try:
        return await fetch(worker, request)
    except BaseException:
        await state.finish(True)
        raise
    finally:
        try:
            await state.finish()
        finally:
            _request.reset(marker)
