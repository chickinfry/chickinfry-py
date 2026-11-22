import asyncio
import gc
import json
import re
import subprocess
import sys
import weakref
from collections.abc import AsyncIterator, Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import timedelta, timezone
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast

import pytest

from chickinfry import AsyncHttpTransport, HttpTransport
from chickinfry._auth_database import Database, create_database
from chickinfry.auth import Auth, _SessionResult
from chickinfry.errors import OperationError as ReceivedOperationError
from chickinfry.orm import format_timestamp, parse_timestamp
from chickinfry.server import (
    Application,
    FieldError,
    Operation,
    OperationError,
    Request,
    RequestInfo,
    RequestScope,
    _Body,
    _Bytes,
    _HostRequest,
    _JSHeaders,
    bearer,
    create_worker_entrypoint,
)

from .fixtures.plain.sdk import AsyncClient, Client, ProbeEchoInput
from .peer import Peer, Received, respond
from .server_fixture import Harness, records


@dataclass(frozen=True, slots=True, repr=False)
class _Scope:
    session: _SessionResult | None = None


@dataclass
class BytesRequest:
    parts: list[bytes]
    method: str = "POST"
    url: str = "https://example.test/probe.echo"
    headers: Mapping[str, str] = field(
        default_factory=lambda: {"content-type": "application/json"}
    )
    cancelled: bool = False
    reads: int = 0

    async def chunks(self) -> AsyncIterator[bytes]:
        for part in self.parts:
            self.reads += 1
            yield part

    async def cancel(self) -> None:
        self.cancelled = True


def decode(value: Mapping[str, object]) -> str:
    text = value.get("wire_value")
    if not isinstance(text, str):
        raise ValueError("Missing string.")
    return text


def encode(value: Mapping[str, object]) -> object:
    return {"wire_value": decode(value)}


class Probe:
    def __init__(self) -> None:
        self.calls = self.opened = self.closed = 0
        self.failure: Exception | None = None

    async def open(self, request: Request) -> RequestScope[_Scope]:
        self.opened += 1
        assert bearer(request.headers) is None

        async def close() -> None:
            self.closed += 1

        return RequestScope(_Scope(), close)

    async def invoke(self, context: _Scope, value: str) -> Mapping[str, object]:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return {"wire_value": value, "internal_note": "hidden"}

    def app(self) -> Application[_Scope]:
        return Application(
            {"probe.echo": Operation(decode, self.invoke, encode)},
            self.open,
            origins=frozenset({"https://allowed.test"}),
            no_store=True,
        )


def decode_id(value: Mapping[str, object]) -> str:
    id = value.get("id")
    if not isinstance(id, str) or not re.fullmatch(
        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
        id,
        re.IGNORECASE,
    ):
        raise ValueError("An API ID requires a UUID string.")
    return id


@pytest.mark.parametrize("failed", [False, True])
async def test_api_id_preserves_uuid_before_handler(failed: bool) -> None:
    probe = Probe()
    received: list[str] = []

    async def handler(context: _Scope, id: str) -> Mapping[str, object]:
        received.append(id)
        if failed:
            raise ValueError("private business detail")
        return {"id": id}

    app = Application(
        {
            "probe.id": Operation(
                decode_id, handler, lambda value: {"id": decode_id(value)}
            )
        },
        probe.open,
    )
    response = await app.fetch(
        BytesRequest(
            [b'{"id":"ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"}'],
            url="https://example.test/probe.id",
        )
    )
    assert received == ["ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"]
    assert response.status == (500 if failed else 200)
    assert json.loads(response.body) == (
        {"error": "operation_failed"}
        if failed
        else {"id": "ABCDEFAB-CDEF-ABCD-EFAB-CDEFABCDEFAB"}
    )


@pytest.mark.parametrize("value", [{}, {"id": None}, {"id": 12}, {"id": "not-a-uuid"}])
async def test_api_id_invalid_input_rejected(value: Mapping[str, object]) -> None:
    probe = Probe()
    received: list[str] = []

    async def handler(context: _Scope, id: str) -> Mapping[str, object]:
        received.append(id)
        return {"id": id}

    app = Application(
        {"probe.id": Operation(decode_id, handler, lambda value: value)}, probe.open
    )
    response = await app.fetch(
        BytesRequest([json.dumps(value).encode()], url="https://example.test/probe.id")
    )
    assert response.status == 400 and json.loads(response.body) == {
        "error": "invalid_input"
    }
    assert received == [] and probe.opened == 0


@pytest.mark.parametrize(
    "body,code",
    [
        (b"null", "invalid_input"),
        (b"[]", "invalid_input"),
        (b"1", "invalid_input"),
        (b"{}", "invalid_input"),
        (b'{"wire_value":null}', "invalid_input"),
        (b'{"wire_value":12}', "invalid_input"),
        (b"\xff", "invalid_json"),
        (b'{"wire_value":NaN}', "invalid_json"),
        (b'{"wire_value":Infinity}', "invalid_json"),
    ],
)
async def test_input_rejected_without_effects(body: bytes, code: str) -> None:
    probe = Probe()
    response = await probe.app().fetch(BytesRequest([body]))
    assert response.status == 400 and json.loads(response.body) == {"error": code}
    assert probe.calls == probe.opened == 0


@pytest.mark.parametrize("body", [b"null", b"[]", b"1"])
async def test_deferred_decode_receives_raw_input_before_session_guard(
    body: bytes,
) -> None:
    probe = Probe()
    operation = Operation(decode, probe.invoke, encode)
    received: list[object] = []

    class ProtectedOperation:
        input_fields = operation.input_fields

        def prepare(self, value: object) -> Callable[[_Scope], Awaitable[object]]:
            received.append(value)

            async def run(context: _Scope) -> object:
                if context.session is None:
                    raise OperationError("unauthenticated", 401)
                return await operation.prepare(value)(context)

            return run

    app = Application({"probe.echo": ProtectedOperation()}, probe.open)
    response = await app.fetch(BytesRequest([body]))
    assert response.status == 401
    assert json.loads(response.body) == {"error": "unauthenticated"}
    assert received == [json.loads(body)]
    assert probe.opened == probe.closed == 1 and probe.calls == 0


@pytest.mark.parametrize(
    "size,status", [(4194303, 200), (4194304, 200), (4194305, 413)]
)
async def test_streamed_utf8_request_boundary(size: int, status: int) -> None:
    probe = Probe()
    prefix, suffix = b'{"wire_value":"', b'"}'
    count = size - len(prefix) - len(suffix)
    body = (
        prefix
        + "\ud55c\U0001f389".encode() * (count // 7)
        + b"x" * (count % 7)
        + suffix
    )
    request = BytesRequest(
        [body[:100], body[100:4194304], body[4194304:], b" "]
        if status == 413
        else [body[:100], body[100:]]
    )
    response = await probe.app().fetch(request)
    assert response.status == status
    if status == 200:
        assert set(json.loads(response.body)) == {"wire_value"}
        assert probe.calls == probe.closed == 1
    else:
        assert (
            request.cancelled
            and request.reads == 3
            and probe.calls == probe.opened == 0
        )


@pytest.mark.parametrize(
    "failure,status,code",
    [
        (ValueError("private detail"), 500, "operation_failed"),
        (ReceivedOperationError("permission_denied", 403), 500, "operation_failed"),
        (OperationError("permission_denied", 403), 403, "permission_denied"),
        (OperationError("unsafe detail", 403), 500, "operation_failed"),
        (OperationError("too_long_" * 9, 403), 500, "operation_failed"),
        (OperationError("permission_denied", 418), 418, "permission_denied"),
        (OperationError("x", 422), 422, "x"),
        (OperationError("x", 400), 400, "x"),
        (OperationError("x", 599), 599, "x"),
        (OperationError("x", 399), 500, "operation_failed"),
        (OperationError("x", 600), 500, "operation_failed"),
        (OperationError("x", cast(int, True)), 500, "operation_failed"),
        (OperationError("x", cast(int, False)), 500, "operation_failed"),
        (OperationError("x", cast(int, "422")), 500, "operation_failed"),
        (OperationError("x", cast(int, 422.0)), 500, "operation_failed"),
        (OperationError("x", cast(int, None)), 500, "operation_failed"),
        (OperationError("x", cast(int, float("nan"))), 500, "operation_failed"),
        (OperationError("x", cast(int, float("inf"))), 500, "operation_failed"),
        (OperationError("x\n", 422), 500, "operation_failed"),
        pytest.param(
            OperationError("not_implemented", 501),
            501,
            "not_implemented",
            id="catches_explicit_501_downgrade_or_changed_body",
        ),
        pytest.param(
            NotImplementedError("private detail"),
            500,
            "operation_failed",
            id="catches_builtin_not_implemented_promoted_to_501",
        ),
        pytest.param(
            OperationError("other_code", 501),
            501,
            "other_code",
            id="preserves_custom_code_at_501",
        ),
    ],
)
async def test_error_boundary(failure: Exception, status: int, code: str) -> None:
    probe = Probe()
    probe.failure = failure
    response = await probe.app().fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert response.status == status and json.loads(response.body) == {"error": code}
    assert probe.opened == probe.closed == 1
    assert response.headers["Cache-Control"] == "no-store"
    assert not any(name.lower() == "set-cookie" for name in response.headers)


@pytest.mark.parametrize("message", [None, "", "Quantity must be 10 or less."])
async def test_error_message(message: str | None) -> None:
    probe = Probe()
    probe.failure = OperationError("x", 422, message)
    response = await probe.app().fetch(BytesRequest([b'{"wire_value":"ok"}']))
    expected: dict[str, object] = {"error": "x"}
    if message is not None:
        expected["message"] = message
    assert response.status == 422 and json.loads(response.body) == expected
    assert str(probe.failure) == "Operation failed."


@pytest.mark.parametrize(
    "message,fields,declared,code,status,expected",
    [
        (
            "Safe",
            (FieldError("wire_value", "too_large"),),
            frozenset({"wire_value"}),
            "invalid_input",
            422,
            {
                "error": "invalid_input",
                "message": "Safe",
                "fields": [{"path": "wire_value", "code": "too_large"}],
            },
        ),
        (
            "Safe",
            (FieldError("wire_value", "too_large"),),
            frozenset(),
            "invalid_input",
            422,
            {"error": "invalid_input", "message": "Safe"},
        ),
        (
            "Safe",
            (FieldError("unknown", "too_large"),),
            frozenset({"wire_value"}),
            "invalid_input",
            422,
            {"error": "invalid_input", "message": "Safe"},
        ),
        (
            "Safe",
            (FieldError("wire_value", "too_large"),),
            frozenset({"wire_value"}),
            "x",
            422,
            {"error": "x", "message": "Safe"},
        ),
        (
            "Safe",
            (FieldError("wire_value", "too_large"),),
            frozenset({"wire_value"}),
            "invalid_input",
            600,
            {"error": "operation_failed"},
        ),
        (
            "bad\nmessage",
            (FieldError("wire_value", "too_large"),),
            frozenset({"wire_value"}),
            "invalid_input",
            422,
            {
                "error": "invalid_input",
                "fields": [{"path": "wire_value", "code": "too_large"}],
            },
        ),
        (
            "Safe",
            (FieldError("wire_value", "bad\n"),),
            frozenset({"wire_value"}),
            "invalid_input",
            422,
            {"error": "invalid_input", "message": "Safe"},
        ),
    ],
)
async def test_error_details(
    message: str,
    fields: tuple[FieldError, ...],
    declared: frozenset[str],
    code: str,
    status: int,
    expected: dict[str, object],
) -> None:
    probe = Probe()
    probe.failure = OperationError(code, status, message, fields)
    app = Application(
        {"probe.echo": Operation(decode, probe.invoke, encode, declared)}, probe.open
    )
    response = await app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert response.status == (500 if status == 600 else status)
    assert json.loads(response.body) == expected


@pytest.mark.parametrize(
    "message",
    ["a" * 1025, "\ud800", "\x00", "\x7f", "\x85", "\u2028", "\u2029", cast(str, 42)],
)
async def test_invalid_error_message_is_omitted(message: str) -> None:
    probe = Probe()
    probe.failure = OperationError("x", 422, message)
    response = await probe.app().fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert response.status == 422 and json.loads(response.body) == {"error": "x"}


@pytest.mark.parametrize(
    "fields",
    [
        (FieldError("wire_value", "too_large"),) * 33,
        (FieldError("wire_value", ""),),
        (FieldError("wire_value", "x" * 65),),
        (FieldError("wire_value", "INVALID"),),
        (FieldError("wire_value", "bad1"),),
        (FieldError("wire_value", "ok"), FieldError("wire_value", "bad\n")),
        cast(tuple[FieldError, ...], "wrong"),
        cast(
            tuple[FieldError, ...],
            ({"path": "wire_value", "code": "ok", "value": "private"},),
        ),
    ],
)
async def test_invalid_field_list_is_discarded_atomically(
    fields: tuple[FieldError, ...],
) -> None:
    probe = Probe()
    probe.failure = OperationError("invalid_input", 422, "Safe", fields)
    app = Application(
        {
            "probe.echo": Operation(
                decode, probe.invoke, encode, frozenset({"wire_value"})
            )
        },
        probe.open,
    )
    response = await app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert response.status == 422
    assert json.loads(response.body) == {"error": "invalid_input", "message": "Safe"}


async def test_error_optional_limits_are_inclusive() -> None:
    probe = Probe()
    message = "\u00e9" * 512
    fields = (FieldError("wire_value", "x" * 64),) * 32
    probe.failure = OperationError("invalid_input", 422, message, fields)
    app = Application(
        {
            "probe.echo": Operation(
                decode, probe.invoke, encode, frozenset({"wire_value"})
            )
        },
        probe.open,
    )
    response = await app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    body = json.loads(response.body)
    assert response.status == 422 and body["message"] == message
    assert body["fields"] == [{"path": "wire_value", "code": "x" * 64}] * 32


async def test_routes_cors_and_auth_before_handler() -> None:
    """Catch a missing session check allowing a protected handler to return 501."""
    probe = Probe()
    app = probe.app()
    for method, path in (
        ("GET", "probe.echo"),
        ("POST", "missing.operation"),
        ("POST", "probe.echo?foo=bar"),
        ("POST", "probe.echo?"),
        ("POST", "api/"),
        ("POST", "api/api/probe.echo"),
        ("POST", "apiprobe.echo"),
    ):
        assert (
            await app.fetch(
                BytesRequest([b"{}"], method=method, url="https://example.test/" + path)
            )
        ).status == 404
    assert (
        await app.fetch(BytesRequest([b"{}"], headers={"content-type": "text/plain"}))
    ).status == 415
    denied = BytesRequest([b"{}"], headers={"origin": "https://denied.test"})
    assert (await app.fetch(denied)).status == 403
    preflight = await app.fetch(
        BytesRequest([], method="OPTIONS", headers={"origin": "https://allowed.test"})
    )
    assert (
        preflight.status == 204
        and preflight.headers["Access-Control-Allow-Origin"] == "https://allowed.test"
    )
    assert probe.calls == 0
    invalid = await app.fetch(
        BytesRequest(
            [b'{"wire_value":"ok"}'],
            headers={
                "content-type": "application/json",
                "authorization": "Bearer malformed",
            },
        )
    )
    assert invalid.status == 401 and probe.calls == 0
    assert not any(name.lower() == "set-cookie" for name in invalid.headers)
    success = await app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert success.status == 200
    assert not any(name.lower() == "set-cookie" for name in success.headers)
    # A web app address forwards the reserved /api path to the same operation.
    prefixed = await app.fetch(
        BytesRequest(
            [b'{"wire_value":"ok"}'], url="https://example.test/api/probe.echo"
        )
    )
    assert prefixed.status == 200 and prefixed.body == success.body

    probe.failure = OperationError("not_implemented", 501)

    async def protected(context: _Scope, text: str) -> Mapping[str, object]:
        if context.session is None:
            raise OperationError("unauthenticated", 401)
        return await probe.invoke(context, text)

    protected_app = Application(
        {"probe.echo": Operation(decode, protected, encode)}, probe.open
    )
    denied_session = await protected_app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert denied_session.status == 401 and json.loads(denied_session.body) == {
        "error": "unauthenticated"
    }
    assert probe.calls == 2
    assert not any(name.lower() == "set-cookie" for name in denied_session.headers)


async def test_native_refresh_failure_never_sets_cookie(db: Harness) -> None:
    """M08: detect cookie deletion on an actual native refresh failure response."""
    core = Auth(db.port(), create_database, now=db.now)

    async def scope(request: Request) -> RequestScope[_Scope]:
        async def close() -> None:
            pass

        return RequestScope(_Scope(), close)

    async def refresh(context: _Scope, value: str) -> Mapping[str, object]:
        return (await core.refresh(value)).to_wire()

    app = Application(
        {"auth.refresh": Operation(decode, refresh, lambda value: value)}, scope
    )
    response = await app.fetch(
        BytesRequest(
            [b'{"wire_value":"malformed"}'], url="https://example.test/auth.refresh"
        )
    )
    assert response.status == 401 and json.loads(response.body) == {
        "error": "invalid_token"
    }
    assert not any(name.lower() == "set-cookie" for name in response.headers)


@pytest.mark.parametrize(
    "row_seconds,idle_seconds,absolute_seconds,expected_seconds",
    [
        pytest.param(900, 7200, 0, 900, id="row"),
        pytest.param(7200, 3600, 0, 3600, id="idle"),
        pytest.param(10800, 7200, 3600, 3600, id="absolute"),
    ],
)
async def test_auth_session_effective_expiry(
    db: Harness,
    row_seconds: int,
    idle_seconds: int,
    absolute_seconds: int,
    expected_seconds: int,
) -> None:
    db.instant += timedelta(microseconds=123456)
    core = Auth(db.port(), create_database, now=db.now)
    tokens = await core.signup("session@example.test", "a long test password")
    await Database(db.port()).sessions.update(
        {"id": tokens.session_id},
        {"expires_at": format_timestamp(db.now() + timedelta(seconds=row_seconds))},
    )
    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        idle_timeout_seconds=idle_seconds,
        absolute_lifetime_seconds=absolute_seconds,
    )

    async def scope(request: Request) -> RequestScope[_Scope]:
        token = bearer(request.headers)
        assert token is not None

        async def close() -> None:
            pass

        return RequestScope(_Scope(session=await core.session(token)), close)

    async def session(context: _Scope, value: Mapping[str, object]) -> _SessionResult:
        if context.session is None:
            raise OperationError("unauthenticated", 401)
        return context.session

    def encode_session(value: _SessionResult) -> Mapping[str, object]:
        return {
            "id": value.session.user.id,
            "email": value.session.user.email,
            "session_id": value.session.id,
            "expires_at": value.expires_at,
        }

    app = Application(
        {"auth.session": Operation(lambda value: value, session, encode_session)}, scope
    )
    response = await app.fetch(
        BytesRequest(
            [b"{}"],
            url="https://example.test/auth.session",
            headers={
                "content-type": "application/json",
                "authorization": "Bearer " + tokens.access_token,
            },
        )
    )
    expected = format_timestamp(db.now() + timedelta(seconds=expected_seconds))
    assert response.status == 200
    assert json.loads(response.body) == {
        "id": tokens.user_id,
        "email": "session@example.test",
        "session_id": tokens.session_id,
        "expires_at": expected,
    }
    assert expected.endswith(".123456Z")
    parsed = parse_timestamp(json.loads(response.body)["expires_at"])
    assert parsed.microsecond == 123456 and parsed.tzinfo is timezone.utc
    assert not any(name.lower() == "set-cookie" for name in response.headers)


@pytest.mark.parametrize("mode", ["success", "handler_failure", "bad_output"])
async def test_all_outcomes_close_real_port(db: Harness, mode: str) -> None:
    opened = []
    backends = []

    async def scope(request: Request) -> RequestScope[_Scope]:
        port = db.port()
        opened.append(port)
        await records(port).find_many()
        backends.append(
            (await port.query("select pg_backend_pid() as pid", ()))[0]["pid"]
        )
        return RequestScope(_Scope(), port.close)

    async def broken(context: _Scope, text: str) -> Mapping[str, object]:
        if mode == "success":
            return {"wire_value": text}
        if mode == "handler_failure":
            raise RuntimeError("hidden detail")
        return {"wire_value": None, "internal_note": "hidden"}

    app = Application({"probe.echo": Operation(decode, broken, encode)}, scope)
    response = await app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert response.status == (200 if mode == "success" else 500)
    if mode != "success":
        assert json.loads(response.body) == {"error": "operation_failed"}
    assert len(opened) == 1 and opened[0]._closed and opened[0]._connection is None
    observer = db.port()
    activity = await observer.query(
        "select count(*) as count from pg_stat_activity where pid=$1", (backends[0],)
    )
    assert activity[0]["count"] == 0


async def test_cancel_closes_scope(db: Harness) -> None:
    begun = asyncio.Event()
    ports = []

    async def scope(request: Request) -> RequestScope[_Scope]:
        port = db.port()
        ports.append(port)
        await records(port).find_many()
        return RequestScope(_Scope(), port.close)

    async def wait(context: _Scope, text: str) -> Mapping[str, object]:
        begun.set()
        await asyncio.Future[None]()
        return {}

    app = Application({"probe.echo": Operation(decode, wait, encode)}, scope)
    task = asyncio.create_task(app.fetch(BytesRequest([b'{"wire_value":"ok"}'])))
    await begun.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ports[0]._closed and ports[0]._connection is None


def test_client_import_never_loads_server_dependencies() -> None:
    script = """
import sys
import importlib.abc
class Guard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "asyncpg" or fullname.startswith("chickinfry.server") or fullname.startswith("chickinfry.auth") or fullname.startswith("chickinfry.postgres"):
            raise AssertionError("Client imported server modules")
sys.meta_path.insert(0, Guard())
from chickinfry import HttpTransport, AsyncHttpTransport, MemoryStore
assert "asyncpg" not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=Path(__file__).parent.parent,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr


@dataclass
class WorkersHeaders:
    values: Mapping[str, str]

    def keys(self) -> Iterator[str]:
        return iter(self.values)

    def get(self, key: str) -> str | None:
        lowered = key.lower()
        return next(
            (value for key, value in self.values.items() if key.lower() == lowered),
            None,
        )


@dataclass
class WorkersBytes:
    data: bytes

    def to_py(self) -> bytes:
        return self.data


@dataclass
class WorkersReadResult:
    done: bool
    value: _Bytes


@dataclass
class WorkersReader:
    payload: bytes
    drained: bool = False

    async def read(self) -> WorkersReadResult:
        if self.drained:
            return WorkersReadResult(True, WorkersBytes(b""))
        self.drained = True
        return WorkersReadResult(False, WorkersBytes(self.payload))

    async def cancel(self) -> None:
        return None

    def releaseLock(self) -> None:
        return None


@dataclass
class WorkersBody:
    payload: bytes

    def getReader(self) -> WorkersReader:
        return WorkersReader(self.payload)


@dataclass
class WorkersRequest:
    method: str
    url: str
    headers: _JSHeaders
    body: _Body | None


def workers_response(
    body: str | None, *, status: int, headers: Mapping[str, str]
) -> object:
    return (body, status, headers)


class WorkersHost(ModuleType):
    WorkerEntrypoint: type[object]
    Response: Callable[..., object]


class WorkersEntry(Protocol):
    env: object
    ctx: object

    def fetch(self, request: WorkersRequest) -> Awaitable[object]: ...


@pytest.mark.parametrize("uses_auth", [False, True])
async def test_workers_entry_admits_only_safe_request_headers(
    monkeypatch: pytest.MonkeyPatch,
    uses_auth: bool,
) -> None:
    source = WorkersRequest(
        method="POST",
        url="https://example.test/probe.echo",
        headers=WorkersHeaders(
            {
                "Proxy-Authorization": "dummy",
                "Cookie": "dummy",
                "Authorization": "dummy",
                "Origin": "https://allowed.test",
                "Content-Type": "application/json",
                "X-Custom": "dummy",
            }
        ),
        body=WorkersBody(b'{"wire_value":"ok"}'),
    )
    assert set(_HostRequest(source).headers) == {
        "origin",
        "content-type",
        "authorization",
        "cookie",
        "x-custom",
    }

    received: list[RequestInfo] = []

    async def scope(request: Request) -> RequestScope[RequestInfo]:
        info = RequestInfo.from_request(request, uses_auth=uses_auth)

        async def close() -> None:
            return None

        return RequestScope(info, close)

    async def invoke(context: RequestInfo, value: str) -> Mapping[str, object]:
        received.append(context)
        return {"wire_value": value}

    def factory(env: object, ctx: object) -> Application[RequestInfo]:
        return Application(
            {"probe.echo": Operation(decode, invoke, encode)},
            scope,
            origins=frozenset({"https://allowed.test"}),
        )

    host = WorkersHost("workers")
    host.WorkerEntrypoint = type("WorkerEntrypoint", (), {})
    host.Response = workers_response
    monkeypatch.setitem(sys.modules, "workers", host)
    entry = cast(WorkersEntry, create_worker_entrypoint(factory)())
    entry.env = object()
    entry.ctx = object()
    await entry.fetch(source)
    assert len(received) == 1
    info = received[0]
    assert set(info.headers) == (
        {"origin", "content-type", "x-custom"}
        if uses_auth
        else {"origin", "content-type", "x-custom", "authorization", "cookie"}
    )
    if not uses_auth:
        assert all(info.headers[key] == "dummy" for key in ("authorization", "cookie"))
    assert info.headers["x-custom"] == "dummy"
    assert info.method == source.method and info.path == "/probe.echo"
    assert not any(
        hasattr(info, name) for name in ("url", "source", "body", "env", "ctx")
    )


@pytest.mark.parametrize(
    ("url", "path"),
    [
        ("https://example.test/items/a%2Fb?view=full#detail", "/items/a%2Fb"),
        ("https://example.test", "/"),
        ("https://example.test/api/probe.echo", "/probe.echo"),
        ("https://example.test/api/realtime", "/api/realtime"),
    ],
)
def test_request_info_extracts_only_the_path(url: str, path: str) -> None:
    assert (
        RequestInfo.from_request(BytesRequest([], url=url), uses_auth=False).path
        == path
    )


def test_request_info_copies_and_freezes_metadata() -> None:
    headers = {"X-Custom": "original", "PrOxY-AuThOrIzAtIoN": "dummy"}
    info = RequestInfo("POST", path="/probe.echo", headers=headers)
    headers["X-Custom"] = "changed"
    assert dict(info.headers) == {"x-custom": "original"}
    assert "original" not in repr(info) and "/probe.echo" not in repr(info)
    with pytest.raises(TypeError):
        cast(dict[str, str], info.headers)["x-custom"] = "changed"


@pytest.mark.parametrize("failed", [False, True])
async def test_workers_setup_is_shared_retained_and_per_instance(
    monkeypatch: pytest.MonkeyPatch,
    failed: bool,
) -> None:
    host = WorkersHost("workers")
    host.WorkerEntrypoint = type("WorkerEntrypoint", (), {})
    host.Response = workers_response
    monkeypatch.setitem(sys.modules, "workers", host)
    begun, release = asyncio.Event(), asyncio.Event()
    setups = 0
    factories: list[tuple[object, object, str]] = []
    probe = Probe()

    async def setup() -> str:
        nonlocal setups
        setups += 1
        begun.set()
        await release.wait()
        if failed:
            raise ValueError("Startup failed.")
        return "configured"

    def factory(env: object, ctx: object, options: str) -> Application[_Scope]:
        factories.append((env, ctx, options))
        return probe.app()

    entry_class = create_worker_entrypoint(factory, setup=setup)
    entry = cast(WorkersEntry, entry_class())
    entry.env, entry.ctx = object(), object()
    request = WorkersRequest(
        "POST",
        "https://example.test/probe.echo",
        WorkersHeaders({"content-type": "application/json"}),
        WorkersBody(b'{"wire_value":"ok"}'),
    )
    first = asyncio.ensure_future(entry.fetch(request))
    second = asyncio.ensure_future(entry.fetch(request))
    await begun.wait()
    assert setups == 1 and factories == [] and probe.opened == 0
    first.cancel()
    with pytest.raises(asyncio.CancelledError):
        await first
    release.set()
    if failed:
        with pytest.raises(RuntimeError, match="Application setup failed"):
            await second
        with pytest.raises(RuntimeError, match="Application setup failed"):
            await entry.fetch(request)
        assert setups == 1 and factories == [] and probe.opened == 0
    else:
        await second
        entry.env, entry.ctx = object(), object()
        await entry.fetch(request)
        assert setups == 1 and len(factories) == 2
        assert factories[-1] == (entry.env, entry.ctx, "configured")
        assert probe.calls == probe.opened == probe.closed == 2
    restarted = cast(WorkersEntry, entry_class())
    restarted.env, restarted.ctx = object(), object()
    if failed:
        with pytest.raises(RuntimeError, match="Application setup failed"):
            await restarted.fetch(request)
    else:
        await restarted.fetch(request)
    assert setups == 2


@pytest.mark.parametrize("cancelled", [False, True])
async def test_workers_failed_setup_releases_requests(
    monkeypatch: pytest.MonkeyPatch, cancelled: bool
) -> None:
    host = WorkersHost("workers")
    host.WorkerEntrypoint = type("WorkerEntrypoint", (), {})
    host.Response = workers_response
    monkeypatch.setitem(sys.modules, "workers", host)
    setups = factories = 0
    probe = Probe()
    requests: list[weakref.ReferenceType[WorkersRequest]] = []
    failures: list[weakref.ReferenceType[BaseException]] = []

    class SetupError(ValueError):
        pass

    class SetupCancelled(asyncio.CancelledError):
        pass

    async def setup() -> str:
        nonlocal setups
        setups += 1
        error = SetupCancelled("dummy") if cancelled else SetupError("dummy")
        cause = SetupError("dummy")
        failures.extend((weakref.ref(error), weakref.ref(cause)))
        raise error from cause

    def factory(env: object, ctx: object, options: str) -> Application[_Scope]:
        nonlocal factories
        factories += 1
        return probe.app()

    entry = cast(WorkersEntry, create_worker_entrypoint(factory, setup=setup)())
    entry.env, entry.ctx = object(), object()

    async def fetch_once() -> None:
        request = WorkersRequest(
            "POST",
            "https://example.test/probe.echo",
            WorkersHeaders({"authorization": "dummy", "cookie": "dummy"}),
            WorkersBody(b"dummy"),
        )
        requests.append(weakref.ref(request))
        try:
            await entry.fetch(request)
        except (Exception, asyncio.CancelledError):
            pass
        else:
            pytest.fail("Failed setup allowed a request to succeed.")

    for _ in range(4):
        await fetch_once()
    gc.collect()
    task = cast(asyncio.Task[object], getattr(entry, "_chickinfry_setup"))
    live_requests = sum(reference() is not None for reference in requests)
    fetch_frames = sum(
        frame.f_code.co_name == "fetch" and "request" in frame.f_locals
        for frame in task.get_stack()
    )
    assert (live_requests, fetch_frames) == (0, 0)
    assert all(reference() is None for reference in failures)
    assert setups == 1 and factories == probe.opened == probe.calls == 0
    assert not task.cancelled() and task.exception() is None
    assert task.get_stack() == []
    state = task.result()
    assert not isinstance(state, BaseException)
    for name in ("__traceback__", "__cause__", "__context__"):
        assert getattr(state, name, None) is None


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_server_error_reaches_generated_client(mode: str) -> None:
    probe = Probe()
    probe.failure = OperationError(
        "invalid_input", 422, "Safe", (FieldError("wire_value", "too_large"),)
    )
    app = Application(
        {
            "probe.echo": Operation(
                decode, probe.invoke, encode, frozenset({"wire_value"})
            )
        },
        probe.open,
    )

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        response = await app.fetch(BytesRequest([request.body]))
        await respond(writer, response.body, status=response.status)

    async with Peer(handler) as peer:
        with pytest.raises(ReceivedOperationError) as caught:
            if mode == "sync":
                with HttpTransport(peer.origin) as transport:
                    await asyncio.to_thread(
                        Client(transport).probe.echo, ProbeEchoInput(wire_value="ok")
                    )
            else:
                async with AsyncHttpTransport(peer.origin) as transport_async:
                    await AsyncClient(transport_async).probe.echo(
                        ProbeEchoInput(wire_value="ok")
                    )
        error = caught.value
        assert error.code == "invalid_input" and error.status == 422
        assert error.response_message == "Safe"
        assert error.fields == (FieldError("wire_value", "too_large"),)
        assert not isinstance(error, OperationError)
        assert len(peer.received) == probe.calls == probe.closed == 1
        assert not error._outcome_unknown


@pytest.mark.parametrize(
    "kind",
    ["path", "message", "fields", "declarations", "metadata_none", "metadata_list"],
)
async def test_error_boundary_uses_plain_value_snapshots(kind: str) -> None:
    class FakePath(str):
        def __hash__(self) -> int:
            return hash("wire_value")

        def __eq__(self, other: object) -> bool:
            return True

    class ShortEncoding(str):
        def encode(self, encoding: str = "utf-8", errors: str = "strict") -> bytes:
            return b"x"

    class FakeCount(tuple[FieldError, ...]):
        def __len__(self) -> int:
            return 0

    class FakeDeclarations(frozenset[str]):
        def __contains__(self, value: object) -> bool:
            return True

    declared: frozenset[str] = frozenset({"wire_value"})
    fields: tuple[FieldError, ...] = (FieldError("wire_value", "required"),)
    message = "Safe"
    expected: dict[str, object] = {"error": "invalid_input", "message": "Safe"}
    if kind == "path":
        fields = (FieldError(FakePath("undeclared"), "required"),)
    elif kind == "message":
        message = ShortEncoding("x" * 1025)
        expected = {
            "error": "invalid_input",
            "fields": [{"path": "wire_value", "code": "required"}],
        }
    elif kind == "fields":
        fields = FakeCount(fields * 33)
    elif kind == "declarations":
        declared = FakeDeclarations({"wire_value"})
        fields = (FieldError("undeclared", "required"),)
    elif kind == "metadata_none":
        declared = cast(frozenset[str], None)
    else:
        declared = cast(frozenset[str], ["wire_value"])
    probe = Probe()
    probe.failure = OperationError("invalid_input", 422, message, fields)
    app = Application(
        {"probe.echo": Operation(decode, probe.invoke, encode, declared)}, probe.open
    )
    response = await app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert response.status == 422 and json.loads(response.body) == expected
    assert probe.closed == 1


@pytest.mark.parametrize("attribute", ["code", "status", "message", "fields"])
@pytest.mark.parametrize("mode", ["deleted", "raises"])
async def test_error_boundary_contains_attribute_failures(
    attribute: str, mode: str
) -> None:
    class BrokenError(OperationError):
        def __getattribute__(self, name: str) -> object:
            if mode == "raises" and name == attribute:
                raise RuntimeError("private detail")
            return super().__getattribute__(name)

    error = BrokenError(
        "invalid_input", 422, "Safe", (FieldError("wire_value", "required"),)
    )
    if mode == "deleted":
        delattr(error, attribute)
    probe = Probe()
    probe.failure = error
    app = Application(
        {
            "probe.echo": Operation(
                decode, probe.invoke, encode, frozenset({"wire_value"})
            )
        },
        probe.open,
    )
    response = await app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    expected: dict[str, object] = {"error": "invalid_input"}
    if attribute in {"code", "status"}:
        expected = {"error": "operation_failed"}
        assert response.status == 500
    else:
        assert response.status == 422
        if attribute != "message":
            expected["message"] = "Safe"
        if attribute != "fields":
            expected["fields"] = [{"path": "wire_value", "code": "required"}]
    assert json.loads(response.body) == expected and probe.closed == 1


async def test_error_boundary_contains_serialization_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> str:
        raise RuntimeError("private detail")

    probe = Probe()
    probe.failure = OperationError("x", 422, "Safe")
    monkeypatch.setattr("chickinfry.server.json.dumps", fail)
    response = await probe.app().fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert response.status == 500 and response.body == b'{"error":"operation_failed"}'
    assert probe.closed == 1


async def test_error_detail_cancellation_still_propagates() -> None:
    class CancelledDetail(OperationError):
        def __getattribute__(self, name: str) -> object:
            if name == "message":
                raise asyncio.CancelledError
            return super().__getattribute__(name)

    probe = Probe()
    probe.failure = CancelledDetail("x", 422)
    with pytest.raises(asyncio.CancelledError):
        await probe.app().fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert probe.closed == 1
