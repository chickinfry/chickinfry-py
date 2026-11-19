import asyncio
import io
import json
import logging
import math
import os
import re
import sys
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
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
    def __init__(
        self, bridge: Any, rid: int, wait_until: Callable[[Awaitable[None]], None]
    ) -> None:
        self.bridge, self.rid = bridge, rid
        self.wait_until = wait_until
        self.closed = False
        self.output: dict[str, io.StringIO | None] = {}

    def finish(self, cancel: bool = False) -> None:
        if self.closed:
            return
        for level, stream in self.output.items():
            if stream is not None:
                _log(level, stream.getvalue().removesuffix("\n"))
        self.output.clear()
        self.closed = True
        finish = self.bridge.finish(self.rid, cancel)
        try:
            self.wait_until(finish)
        except Exception:
            finish.close()


_request: ContextVar[_HostRequest | None] = ContextVar(
    "chickinfry_host_request", default=None
)
_active: ContextVar[frozenset[int]] = ContextVar(
    "chickinfry_host_transactions", default=frozenset()
)

_LOG_LEVELS = frozenset(("debug", "info", "warn", "error"))
_LOG_LIMIT = 4 << 20


def _json_value(value: object, depth: int) -> bool:
    if depth > 64:
        return False
    if value is None or type(value) in (str, int, float, bool):
        return True
    if type(value) is list:
        return all(_json_value(item, depth + 1) for item in value)
    if type(value) is dict:
        return all(
            type(key) is str and _json_value(item, depth + 1)
            for key, item in value.items()
        )
    return False


def _log(level: str, message: str, fields: object = None) -> None:
    state = _request.get()
    if state is None or state.closed:
        return
    try:
        if (
            type(level) is not str
            or level not in _LOG_LEVELS
            or type(message) is not str
        ):
            return
        record: dict[str, object] = {
            "rid": state.rid,
            "level": level,
            "message": message,
        }
        if fields is not None:
            if type(fields) is not dict or not _json_value(fields, 1):
                return
            record["fields"] = fields
        frame = json.dumps(
            record, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode()
        if len(frame) <= _LOG_LIMIT:
            state.bridge.log(state.rid, frame)
    except Exception:
        pass


def _bind_log() -> Callable[[str, str, object], None]:
    owner = _request.get()

    def write(level: str, message: str, fields: object) -> None:
        if owner is _request.get():
            _log(level, message, fields)

    return write


_unscoped_output = False
_output_blocked: Callable[[], None] | None = None


def _report_blocked_output() -> None:
    global _unscoped_output
    if _output_blocked is None:
        _unscoped_output = True
        return
    try:
        _output_blocked()
    except Exception:
        pass


class _LogStream(io.TextIOBase):
    encoding = "utf-8"

    def __init__(self, level: str) -> None:
        self.level = level

    def writable(self) -> bool:
        return True

    def write(self, text: str, /) -> int:
        size = len(text)
        state = _request.get()
        if state is None or state.closed:
            _report_blocked_output()
            return size
        if self.level not in state.output:
            state.output[self.level] = io.StringIO()
        stream = state.output[self.level]
        if stream is not None:
            if stream.tell() + size <= _LOG_LIMIT:
                stream.write(text)
            else:
                state.output[self.level] = None
        return size

    def flush(self) -> None:
        # Buffer until completion so secrets spanning writes and line breaks are redacted.
        pass


class _RequestLogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord) -> None:
        state = _request.get()
        if state is None or state.closed:
            _report_blocked_output()
            return
        level = (
            "error"
            if record.levelno >= logging.ERROR
            else "warn"
            if record.levelno >= logging.WARNING
            else "info"
            if record.levelno >= logging.INFO
            else "debug"
        )
        try:
            _log(level, self.format(record))
        except Exception:
            pass


def _install_standard_logging() -> None:
    # Native writes can bypass these descriptors and are blocked by the collector.
    sink = os.open(os.devnull, os.O_WRONLY)
    try:
        for fd in (1, 2):
            os.dup2(sink, fd)
    finally:
        os.close(sink)
    sys.stdout = _LogStream("info")
    sys.stderr = _LogStream("error")
    setattr(sys, "__stdout__", sys.stdout)
    setattr(sys, "__stderr__", sys.stderr)
    logging.getLogger().addHandler(_RequestLogHandler())
    logging.getLogger().setLevel(logging.INFO)


if sys.platform == "emscripten":
    _install_standard_logging()


def _wait_until(work: Coroutine[None, None, None]) -> None:
    state = _request.get()
    if state is None or state.closed:
        raise RuntimeError("An active request is required.")
    background = _HostRequest(
        state.bridge, state.bridge.background(state.rid), state.wait_until
    )

    async def run() -> None:
        marker = _request.set(background)
        try:
            await work
        finally:
            background.finish()
            _request.reset(marker)

    scheduled = run()
    try:
        state.wait_until(scheduled)
    except Exception:
        scheduled.close()
        background.finish(True)
        raise


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
            self._state.finish(True)
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
                    self._state.finish(True)
                    raise
                if not committing and not self._state.closed:
                    try:
                        if await self._call("rollback", lease=lease) != {}:
                            raise _DatabaseFailure()
                    except BaseException:
                        self._state.finish(True)
                raise
            finally:
                tx.active = False
                _active.reset(marker)

    async def close(self) -> None:
        self._closed = True

    def terminate(self) -> None:
        self._closed = True
        self._state.finish(True)


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

    def finish(self, rid: int, cancel: bool) -> Coroutine[None, None, None]:
        pending = self.host.finish(rid, cancel)

        async def wait() -> None:
            await pending

        return wait()

    def background(self, rid: int) -> int:
        return int(self.host.background(rid))

    def log(self, rid: int, frame: bytes) -> None:
        data = self.js.Uint8Array.new(self.ffi.to_js(memoryview(frame)))
        self.host.log(rid, data)


async def _fetch(
    fetch: Callable[..., Awaitable[object]],
    worker: Any,
    request: Any,
    secret_names: tuple[str, ...] = (),
    vault: bool = False,
) -> object:
    global _output_blocked, _unscoped_output
    from importlib import import_module

    workers = import_module("workers")
    ffi = import_module("pyodide.ffi")
    js = import_module("js")
    host = workers.import_from_javascript("_chik/host.js")
    pyodide = import_module("pyodide")
    host.verify(sys.version.split()[0], pyodide.__version__)
    host.prepare(worker.env, ffi.to_js(list(secret_names)), vault)
    if _output_blocked is None:
        _output_blocked = host.outputBlocked
    if _unscoped_output:
        _unscoped_output = False
        _report_blocked_output()
    state = _HostRequest(
        _JSBridge(host, ffi, js),
        host.start(request.js_object.signal, request.js_object.headers),
        worker.ctx.waitUntil,
    )
    marker = _request.set(state)
    try:
        return await fetch(worker, request)
    except BaseException:
        state.finish(True)
        raise
    finally:
        try:
            state.finish()
        finally:
            _request.reset(marker)
