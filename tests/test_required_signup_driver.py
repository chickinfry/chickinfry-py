import asyncio
import json
import secrets
import sys
import time
from typing import cast

import pytest

from chickinfry import HttpTransport

from .peer import Peer, Received, json_bytes, respond
from .test_conformance_driver import handshake


@pytest.mark.parametrize("environment", ["python-sync", "python-async"])
@pytest.mark.parametrize(
    "signin_reply", ["invalid_credentials", "missing", "wrong_type"]
)
async def test_driver_uses_required_sdk_and_exposes_signup_results(
    environment: str,
    signin_reply: str,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from conformance.driver import credentials
    from conformance.driver.transport import restore

    from .fixtures.auth import sdk as off_sdk

    sdk = pytest.importorskip("chickinfry_client_required_auth")

    monkeypatch.setitem(sys.modules, "credentials", credentials)
    monkeypatch.setitem(sys.modules, "chickinfry_client_auth", off_sdk)
    monkeypatch.setitem(sys.modules, "chickinfry_client_required_auth", sdk)
    from conformance.driver.main import Driver

    values = {"access": secrets.token_urlsafe(32), "refresh": secrets.token_urlsafe(32)}
    native: dict[str, object] = {
        "access_token": values["access"],
        "refresh_token": values["refresh"],
        "expires_at": "2099-01-02T00:00:00Z",
        "refresh_expires_at": "2099-02-01T00:00:00Z",
        "user_id": "user",
        "session_id": "session",
        "email_verified": True,
    }

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.signup":
            await respond(
                writer, json_bytes({"accepted": True, "attempt": "signup-attempt"})
            )
        elif request.path == "/auth.send_verification_email":
            await respond(writer, json_bytes({"accepted": True}))
        elif request.path == "/auth.signin":
            if signin_reply == "invalid_credentials":
                await respond(
                    writer, json_bytes({"error": "invalid_credentials"}), status=401
                )
            else:
                malformed = dict(native)
                if signin_reply == "missing":
                    malformed.pop("email_verified")
                else:
                    malformed["email_verified"] = "true"
                await respond(writer, json_bytes(malformed))
        else:
            await respond(writer, json_bytes(native))

    async with Peer(handler) as peer:
        instance = Driver(credentials.CredentialStore(values))
        instance.handshake(handshake(environment))
        sequence = 0

        async def issue(command: str, args: dict[str, object]) -> dict[str, object]:
            nonlocal sequence
            sequence += 1
            await instance.execute(
                f"c:{sequence}",
                command,
                {"caseId": "C-11", "timeoutMs": 5000, "clientRef": "client", **args},
                time.monotonic() + 5,
            )
            return cast(dict[str, object], json.loads(capsys.readouterr().out))

        try:
            created = await issue(
                "client.create",
                {
                    "fixture": "requiredAuth",
                    "origin": peer.origin,
                    "requestTimeoutMs": 1000,
                },
            )
            assert created["error"] is None
            signup = await issue(
                "client.call",
                {
                    "operation": "auth.signup",
                    "input": {"email": "a@example.test", "password": "unused"},
                },
            )
            assert signup["error"] is None
            assert bool(
                cast(dict[str, object], signup["result"])["output"]
                == {"accepted": True, "attempt": "signup-attempt"}
            )
            resent = await issue(
                "client.call",
                {"operation": "auth.send_verification_email", "input": {}},
            )
            assert resent["error"] is None
            assert bool(
                json.loads(peer.received[-1].body) == {"attempt": "signup-attempt"}
            )
            invalid = await issue(
                "client.call",
                {
                    "operation": "auth.signin",
                    "input": {"email": "a@example.test", "password": "unused"},
                },
            )
            error = cast(dict[str, object], invalid["error"])
            if signin_reply == "invalid_credentials":
                assert (
                    error["code"] == "invalid_credentials"
                    and error["httpStatus"] == 401
                )
            else:
                assert error["code"] == "internal"
            retained = await issue(
                "client.call",
                {"operation": "auth.send_verification_email", "input": {}},
            )
            assert retained["error"] is None
            verified = await issue(
                "client.call",
                {"operation": "auth.verify_email", "input": {"code": "123456"}},
            )
            assert verified["error"] is None
            result = cast(dict[str, object], verified["result"])
            assert cast(dict[str, object], result["output"])["email_verified"] is True
            assert result["credentialRefs"] == {
                "access_token": "access",
                "refresh_token": "refresh",
            }
            before = len(peer.received)
            both = await issue(
                "client.call",
                {
                    "operation": "auth.verify_email",
                    "input": {
                        "attempt": "a",
                        "email": "b@example.test",
                        "code": "123456",
                    },
                },
            )
            assert cast(dict[str, object], both["error"])["code"] == "invalid_argument"
            assert len(peer.received) == before
            for target in (
                {"email": "single@example.test"},
                {"attempt": "explicit-attempt"},
            ):
                single = await issue(
                    "client.call",
                    {
                        "operation": "auth.verify_email",
                        "input": {"code": "123456", **target},
                    },
                )
                assert single["error"] is None
                assert bool(
                    json.loads(peer.received[-1].body) == {"code": "123456", **target}
                )
        finally:
            for client in instance.clients.values():
                if isinstance(client.owner, HttpTransport):
                    client.owner.close()
                else:
                    await client.owner.aclose()
            restore()
