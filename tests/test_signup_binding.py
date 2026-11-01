import asyncio
import json
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from dataclasses import asdict

import pytest

from chickinfry import (
    AsyncHttpTransport,
    ClientError,
    HttpTransport,
    OperationError,
    SignupBinding,
)

from .peer import Peer, Received, json_bytes, respond
from .test_session import credentials


@pytest.fixture(params=["sync", "async"])
async def invoke(
    request: pytest.FixtureRequest,
) -> AsyncIterator[Callable[[str, Mapping[str, object]], Awaitable[object]]]:
    from chickinfry import SignupBinding

    binding = SignupBinding()
    attempts = 0

    async def handler(received: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal attempts
        if received.path == "/auth.signup":
            attempts += 1
            await respond(
                writer, json_bytes({"accepted": True, "attempt": f"signup-{attempts}"})
            )
        elif received.path == "/auth.verify_email":
            if json.loads(received.body).get("code") == "000000":
                await respond(writer, json_bytes({"error": "invalid_code"}), status=400)
                return
            await respond(
                writer, json_bytes({**asdict(credentials()), "email_verified": True})
            )
        elif received.path == "/auth.signin":
            await respond(
                writer, json_bytes({"error": "invalid_credentials"}), status=401
            )
        else:
            await respond(writer, received.body)

    async with Peer(handler) as peer:
        async with AsyncHttpTransport(peer.origin, persist=False) as async_transport:
            with HttpTransport(peer.origin, persist=False) as sync_transport:

                async def call(operation: str, payload: Mapping[str, object]) -> object:
                    if request.param == "sync":
                        return await asyncio.to_thread(
                            binding.invoke, sync_transport, operation, payload
                        )
                    return await binding.invoke_async(
                        async_transport, operation, payload
                    )

                setattr(call, "requests", peer.received)
                yield call


@pytest.mark.parametrize(
    "operation", ["auth.verify_email", "auth.send_verification_email"]
)
async def test_conflicting_targets_send_nothing(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]], operation: str
) -> None:
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        await invoke(operation, {"attempt": "explicit", "email": "a@example.invalid"})
    assert getattr(invoke, "requests") == []


@pytest.mark.parametrize(
    "operation", ["auth.verify_email", "auth.send_verification_email"]
)
async def test_missing_target_without_signup_sends_nothing(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]], operation: str
) -> None:
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        await invoke(operation, {})
    assert getattr(invoke, "requests") == []


@pytest.mark.parametrize(
    "target", [{"attempt": "explicit"}, {"email": "a@example.invalid"}]
)
@pytest.mark.parametrize(
    "operation", ["auth.verify_email", "auth.send_verification_email"]
)
async def test_omitted_target_is_absent_from_request_body(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]],
    operation: str,
    target: dict[str, object],
) -> None:
    await invoke("auth.signup", {"email": "a@example.invalid", "password": "unused"})
    payload = dict(target)
    await invoke(operation, payload)
    assert payload == target
    assert bool(json.loads(getattr(invoke, "requests")[-1].body) == target)


@pytest.mark.parametrize(
    "operation", ["auth.verify_email", "auth.send_verification_email"]
)
async def test_accepted_signup_supplies_the_last_attempt(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]], operation: str
) -> None:
    await invoke("auth.signup", {"email": "a@example.invalid", "password": "unused"})
    result = await invoke(
        "auth.signup", {"email": "a@example.invalid", "password": "unused"}
    )
    assert bool(result == {"accepted": True, "attempt": "signup-2"})
    payload: dict[str, object] = (
        {"code": "123456"} if operation == "auth.verify_email" else {}
    )
    await invoke(operation, payload)
    assert "attempt" not in payload
    assert bool(
        json.loads(getattr(invoke, "requests")[-1].body)
        == {**payload, "attempt": "signup-2"}
    )


async def test_pending_signin_keeps_the_public_server_error(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]],
) -> None:
    with pytest.raises(
        OperationError,
        check=lambda error: error.code == "invalid_credentials" and error.status == 401,
    ):
        await invoke(
            "auth.signin", {"email": "a@example.invalid", "password": "unused"}
        )


async def test_failed_verification_retains_attempt_until_success(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]],
) -> None:
    await invoke("auth.signup", {"email": "a@example.invalid", "password": "unused"})
    with pytest.raises(
        OperationError,
        check=lambda error: error.code == "invalid_code" and error.status == 400,
    ):
        await invoke("auth.verify_email", {"code": "000000"})
    await invoke("auth.verify_email", {"code": "123456"})
    assert bool(
        json.loads(getattr(invoke, "requests")[-1].body)
        == {"code": "123456", "attempt": "signup-1"}
    )
    count = len(getattr(invoke, "requests"))
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        await invoke("auth.send_verification_email", {})
    assert len(getattr(invoke, "requests")) == count


@pytest.mark.parametrize("old_mode,new_mode", [("sync", "async"), ("async", "sync")])
async def test_old_verification_preserves_new_signup_across_modes(
    old_mode: str, new_mode: str
) -> None:
    binding = SignupBinding()
    verifying = asyncio.Event()
    release = asyncio.Event()
    attempts = 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal attempts
        if request.path == "/auth.signup":
            attempts += 1
            await respond(
                writer, json_bytes({"accepted": True, "attempt": f"signup-{attempts}"})
            )
        elif request.path == "/auth.verify_email":
            if json.loads(request.body).get("attempt") == "signup-1":
                verifying.set()
                await release.wait()
            await respond(
                writer, json_bytes({**asdict(credentials()), "email_verified": True})
            )
        else:
            await respond(writer, json_bytes({"accepted": True}))

    async with Peer(handler) as peer:
        async with AsyncHttpTransport(peer.origin, persist=False) as async_transport:
            with HttpTransport(peer.origin, persist=False) as sync_transport:

                async def call(
                    mode: str, operation: str, payload: Mapping[str, object]
                ) -> object:
                    if mode == "sync":
                        return await asyncio.to_thread(
                            binding.invoke, sync_transport, operation, payload
                        )
                    return await binding.invoke_async(
                        async_transport, operation, payload
                    )

                signup = {"email": "a@example.invalid", "password": "unused"}
                await call(old_mode, "auth.signup", signup)
                task = asyncio.create_task(
                    call(old_mode, "auth.verify_email", {"code": "123456"})
                )
                await asyncio.wait_for(verifying.wait(), 5)
                try:
                    await asyncio.wait_for(call(new_mode, "auth.signup", signup), 5)
                finally:
                    release.set()
                    await asyncio.wait_for(task, 5)
                await call(new_mode, "auth.send_verification_email", {})
                assert bool(
                    json.loads(peer.received[-1].body) == {"attempt": "signup-2"}
                )
                await call(new_mode, "auth.verify_email", {"code": "123456"})
                before = len(peer.received)
                with pytest.raises(
                    ClientError, check=lambda error: error.code == "invalid_argument"
                ):
                    await call(new_mode, "auth.send_verification_email", {})
                assert len(peer.received) == before
