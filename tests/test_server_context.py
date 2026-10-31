import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

import pytest

from chickinfry._auth_database import create_database
from chickinfry.auth import Auth
from chickinfry.orm import Repository
from chickinfry.server import (
    Application,
    AuthContext,
    Operation,
    OperationError,
    Request,
    RequestInfo,
    RequestScope,
    Session,
    bearer,
)

from .server_context import Context, DatabaseContext, ProtectedContext, PublicContext
from .server_fixture import Harness, Record, records
from .test_server_dispatch import BytesRequest

ROOT = Path(__file__).resolve().parent.parent


def test_strict_mypy_rejects_nullable_protected_context(tmp_path: Path) -> None:
    fixture = tmp_path / "context_contract.py"
    positive = """from chickinfry.server import AuthContext, RequestInfo, Session
from chickinfry.orm import Repository
from tests.server_context import ProtectedContext, PublicContext
from tests.server_fixture import Record

def public(db: Repository[Record], request: RequestInfo) -> PublicContext:
    absent: AuthContext[Session | None] = AuthContext(None)
    return PublicContext(auth=absent, db=db, request=request)

def protected(db: Repository[Record], request: RequestInfo, session: Session) -> ProtectedContext:
    return ProtectedContext(auth=AuthContext(session), db=db, request=request)

def user(ctx: ProtectedContext) -> str:
    return ctx.auth.session.user.id
"""
    negative = """
def rejects_none(db: Repository[Record], request: RequestInfo) -> ProtectedContext:
    absent: AuthContext[Session | None] = AuthContext(None)
    return ProtectedContext(auth=absent, db=db, request=request)
"""
    command = [
        sys.executable,
        "-m",
        "mypy",
        "--strict",
        "--explicit-package-bases",
        "--config-file",
        str(ROOT / "pyproject.toml"),
        "--cache-dir",
        str(tmp_path / "mypy"),
        str(fixture),
    ]
    env = {**os.environ, "MYPYPATH": str(ROOT / "src")}
    rejected = positive.split("\ndef public", 1)[0] + negative
    fixture.write_text(rejected)
    invalid = subprocess.run(
        command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60
    )
    assert invalid.returncode == 1, invalid.stdout + invalid.stderr
    line = len(rejected.splitlines())
    assert re.findall(
        r"^.+:(\d+): error: .*\[([a-z-]+)\]$", invalid.stdout, re.MULTILINE
    ) == [(str(line), "arg-type")]
    assert '"AuthContext[Session | None]"' in invalid.stdout
    assert '"AuthContext[Session]"' in invalid.stdout
    fixture.write_text(positive)
    valid = subprocess.run(
        command, cwd=ROOT, env=env, capture_output=True, text=True, timeout=60
    )
    assert valid.returncode == 0, valid.stdout + valid.stderr


@dataclass(frozen=True, slots=True, repr=False)
class _AuthScope:
    db: Repository[Record]
    session: Session | None
    request: RequestInfo


@pytest.mark.parametrize("public", [False, True])
@pytest.mark.parametrize(
    "credential", ["absent", "valid", "invalid", "database_failure"]
)
async def test_auth_context_dispatch(
    db: Harness, public: bool, credential: str
) -> None:
    tokens = await Auth(db.port(), create_database, now=db.now).signup(
        "context@example.test", "a long test password"
    )
    ports = []
    calls = []

    async def scope(request: Request) -> RequestScope[_AuthScope]:
        token = bearer(request.headers)
        port = db.port()
        ports.append(port)
        try:
            if credential == "database_failure":
                await port.close()
            session = (
                await Auth(port, create_database, now=db.now).session(token)
                if token is not None
                else None
            )
            return RequestScope(
                _AuthScope(
                    records(port),
                    session,
                    RequestInfo.from_request(request, uses_auth=True),
                ),
                port.close,
            )
        except BaseException:
            await port.close()
            raise

    async def protected(ctx: ProtectedContext) -> str:
        calls.append("protected")
        assert ctx.auth.session.id == tokens.session_id
        assert ctx.auth.session.user.id == tokens.user_id
        assert ctx.auth.session.expires_at == tokens.expires_at
        await ctx.db.insert({"label": ctx.auth.session.user.id})
        return ctx.auth.session.user.email

    async def published(ctx: PublicContext) -> str:
        calls.append("public")
        if ctx.auth.session is None:
            return "anonymous"
        assert ctx.auth.session.id == tokens.session_id
        return ctx.auth.session.user.email

    async def invoke(scope: _AuthScope, value: object) -> str:
        if public:
            return await published(
                PublicContext(
                    auth=AuthContext(scope.session), db=scope.db, request=scope.request
                )
            )
        session = scope.session
        if session is None:
            raise OperationError("unauthenticated", 401)
        return await protected(
            ProtectedContext(
                auth=AuthContext(session), db=scope.db, request=scope.request
            )
        )

    app = Application(
        {
            "probe.echo": Operation(
                lambda value: value, invoke, lambda value: {"email": value}
            )
        },
        scope,
    )
    headers = {"content-type": "application/json"}
    if credential != "absent":
        token = "A" * 43 if credential == "invalid" else tokens.access_token
        headers["authorization"] = "Bearer " + token
    response = await app.fetch(BytesRequest([b"{}"], headers=headers))
    expected = (
        500
        if credential == "database_failure"
        else (
            401
            if credential == "invalid" or (credential == "absent" and not public)
            else 200
        )
    )
    assert response.status == expected
    assert calls == (["public" if public else "protected"] if expected == 200 else [])
    assert len(await records(db.port()).find_many()) == int(
        not public and expected == 200
    )
    assert len(ports) == 1 and ports[0]._closed and ports[0]._connection is None
    if expected == 200:
        assert json.loads(response.body) == {
            "email": "anonymous" if credential == "absent" else "context@example.test"
        }
    elif credential == "absent":
        assert json.loads(response.body) == {"error": "unauthenticated"}


@pytest.mark.parametrize("database", [False, True])
async def test_no_auth_context_with_or_without_database(
    db: Harness, database: bool
) -> None:
    ports = []

    async def scope(request: Request) -> RequestScope[Context | DatabaseContext]:
        info = RequestInfo.from_request(request, uses_auth=False)
        if database:
            port = db.port()
            ports.append(port)
            return RequestScope(
                DatabaseContext(db=records(port), request=info), port.close
            )

        async def close() -> None:
            pass

        return RequestScope(Context(request=info), close)

    async def invoke(ctx: Context | DatabaseContext, value: object) -> str:
        assert not hasattr(ctx, "auth") and not hasattr(ctx, "session")
        assert ("db" in type(ctx).__dataclass_fields__) == database
        assert ctx.request.headers["authorization"] == "Partner dummy"
        assert ctx.request.headers["cookie"] == "customer=dummy"
        assert ctx.request.headers["x-custom"] == "ordinary"
        if isinstance(ctx, DatabaseContext):
            await ctx.db.insert({"label": "no-auth"})
        return "ok"

    app = Application(
        {
            "probe.echo": Operation(
                lambda value: value, invoke, lambda value: {"value": value}
            )
        },
        scope,
    )
    request = BytesRequest(
        [b"{}"],
        headers={
            "content-type": "application/json",
            "authorization": "Partner dummy",
            "cookie": "customer=dummy",
            "x-custom": "ordinary",
        },
    )
    assert (await app.fetch(request)).status == 200
    for name in ("auth.session", "auth.signin", "auth.signup"):
        request.url = "https://example.test/" + name
        assert (await app.fetch(request)).status == 404
    assert len(await records(db.port()).find_many()) == int(database)
    assert all(port._closed and port._connection is None for port in ports)
