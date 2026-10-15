import asyncio
import json
import subprocess
import sys
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from chickinfry._auth_database import create_database
from chickinfry.auth import Auth
from chickinfry.errors import OperationError
from chickinfry.server import (
    Application,
    Context,
    Operation,
    Request,
    RequestScope,
    ServerError,
    bearer,
    require_session,
)

from .server_fixture import Harness, records


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

    async def open(self, request: Request) -> RequestScope[Context[None]]:
        self.opened += 1
        assert bearer(request.headers) is None

        async def close() -> None:
            self.closed += 1

        return RequestScope(Context(), close)

    async def invoke(self, context: Context[None], value: str) -> Mapping[str, object]:
        self.calls += 1
        if self.failure is not None:
            raise self.failure
        return {"wire_value": value, "internal_note": "hidden"}

    def app(self) -> Application[Context[None]]:
        return Application(
            {"probe.echo": Operation(decode, self.invoke, encode)},
            self.open,
            origins=frozenset({"https://allowed.test"}),
            no_store=True,
        )


def decode_id(value: Mapping[str, object]) -> str:
    id = value.get("id")
    if not isinstance(id, str):
        raise ValueError("An API ID requires a string.")
    return id


@pytest.mark.parametrize("failed", [False, True])
async def test_api_id_preserves_non_uuid_string_before_handler(failed: bool) -> None:
    probe = Probe()
    received: list[str] = []

    async def handler(context: Context[None], id: str) -> Mapping[str, object]:
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
        BytesRequest([b'{"id":"not-a-uuid"}'], url="https://example.test/probe.id")
    )
    assert received == ["not-a-uuid"]
    assert response.status == (500 if failed else 200)
    assert json.loads(response.body) == (
        {"error": "operation_failed"} if failed else {"id": "not-a-uuid"}
    )


@pytest.mark.parametrize("value", [{}, {"id": None}, {"id": 12}])
async def test_api_id_missing_null_number_rejected(value: Mapping[str, object]) -> None:
    probe = Probe()
    received: list[str] = []

    async def handler(context: Context[None], id: str) -> Mapping[str, object]:
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


@pytest.mark.parametrize(
    "size,status", [(4194303, 200), (4194304, 200), (4194305, 413)]
)
async def test_streamed_utf8_request_boundary(size: int, status: int) -> None:
    probe = Probe()
    prefix, suffix = b'{"wire_value":"', b'"}'
    count = size - len(prefix) - len(suffix)
    body = prefix + "한🎉".encode() * (count // 7) + b"x" * (count % 7) + suffix
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
        (OperationError("permission_denied", 403), 500, "operation_failed"),
        (ServerError("permission_denied", 403), 403, "permission_denied"),
        (ServerError("unsafe detail", 403), 500, "operation_failed"),
        (ServerError("too_long_" * 9, 403), 500, "operation_failed"),
        (ServerError("permission_denied", 418), 500, "operation_failed"),
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


async def test_routes_cors_and_auth_before_handler() -> None:
    probe = Probe()
    app = probe.app()
    for method, path in (
        ("GET", "probe.echo"),
        ("POST", "missing.operation"),
        ("POST", "probe.echo?foo=bar"),
        ("POST", "probe.echo?"),
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

    async def protected(context: Context[None], text: str) -> Mapping[str, object]:
        require_session(context)
        return {"wire_value": text}

    protected_app = Application(
        {"probe.echo": Operation(decode, protected, encode)}, probe.open
    )
    denied_session = await protected_app.fetch(BytesRequest([b'{"wire_value":"ok"}']))
    assert denied_session.status == 401
    assert not any(name.lower() == "set-cookie" for name in denied_session.headers)


async def test_native_refresh_failure_never_sets_cookie(db: Harness) -> None:
    """M08: detect cookie deletion on an actual native refresh failure response."""
    core = Auth(db.port(), create_database, now=db.now)

    async def scope(request: Request) -> RequestScope[Context[None]]:
        async def close() -> None:
            pass

        return RequestScope(Context(), close)

    async def refresh(context: Context[None], value: str) -> Mapping[str, object]:
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


@pytest.mark.parametrize("mode", ["success", "handler_failure", "bad_output"])
async def test_all_outcomes_close_real_port(db: Harness, mode: str) -> None:
    opened = []
    backends = []

    async def scope(request: Request) -> RequestScope[Context[None]]:
        port = db.port()
        opened.append(port)
        await records(port).find_many()
        backends.append(
            (await port.query("select pg_backend_pid() as pid", ()))[0]["pid"]
        )
        return RequestScope(Context(), port.close)

    async def broken(context: Context[None], text: str) -> Mapping[str, object]:
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

    async def scope(request: Request) -> RequestScope[Context[None]]:
        port = db.port()
        ports.append(port)
        await records(port).find_many()
        return RequestScope(Context(), port.close)

    async def wait(context: Context[None], text: str) -> Mapping[str, object]:
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
from chickinfry import HTTP, AsyncHTTP, SessionStore
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
