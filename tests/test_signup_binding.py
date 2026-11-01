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
from chickinfry.wire import read_record

from .peer import Peer, Received, json_bytes, respond
from .test_session import credentials


@pytest.fixture(params=["sync", "async"])
async def invoke(
    request: pytest.FixtureRequest,
) -> AsyncIterator[Callable[[str, Mapping[str, object]], Awaitable[object]]]:
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
            email = json.loads(received.body).get("email")
            if json.loads(received.body).get("password") == "accepted":
                await respond(
                    writer,
                    json_bytes({**asdict(credentials()), "email_verified": True}),
                )
                return
            if email == "unverified@example.invalid":
                await respond(
                    writer, json_bytes({"error": "email_not_verified"}), status=403
                )
                return
            await respond(
                writer, json_bytes({"error": "invalid_credentials"}), status=401
            )
        else:
            await respond(
                writer,
                json_bytes({"status": "signed_out"})
                if received.path == "/auth.logout"
                else received.body,
            )

    async with Peer(handler) as peer:
        async with AsyncHttpTransport(peer.origin, persist=False) as async_transport:
            with HttpTransport(peer.origin, persist=False) as sync_transport:

                async def call(operation: str, payload: Mapping[str, object]) -> object:
                    if request.param == "sync":
                        return await asyncio.to_thread(
                            binding.invoke,
                            sync_transport,
                            operation,
                            payload,
                            read_record,
                        )
                    return await binding.invoke_async(
                        async_transport, operation, payload, read_record
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


@pytest.mark.parametrize(
    "operation,email",
    [
        ("auth.logout", ""),
        ("auth.signin", "a@example.invalid"),
        ("auth.signin", " A@EXAMPLE.INVALID "),
        ("auth.signin", "\ufeffA@EXAMPLE.INVALID\u00a0"),
    ],
)
async def test_successful_authentication_change_clears_pending_attempt(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]],
    operation: str,
    email: str,
) -> None:
    await invoke("auth.signup", {"email": "a@example.invalid", "password": "unused"})
    await invoke(
        operation,
        {"email": email, "password": "accepted"} if operation == "auth.signin" else {},
    )
    count = len(getattr(invoke, "requests"))
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        await invoke("auth.verify_email", {"code": "123456"})
    assert len(getattr(invoke, "requests")) == count


async def test_signin_with_another_email_preserves_pending_attempt(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]],
) -> None:
    await invoke("auth.signup", {"email": "a@example.invalid", "password": "unused"})
    await invoke("auth.signin", {"email": "b@example.invalid", "password": "accepted"})
    await invoke("auth.send_verification_email", {})
    assert bool(
        json.loads(getattr(invoke, "requests")[-1].body) == {"attempt": "signup-1"}
    )


async def test_failed_signin_retains_pending_attempt(
    invoke: Callable[[str, Mapping[str, object]], Awaitable[object]],
) -> None:
    await invoke("auth.signup", {"email": "a@example.invalid", "password": "unused"})
    with pytest.raises(
        OperationError,
        check=lambda error: error.code == "email_not_verified" and error.status == 403,
    ):
        await invoke(
            "auth.signin", {"email": "unverified@example.invalid", "password": "unused"}
        )
    await invoke("auth.send_verification_email", {})
    assert bool(
        json.loads(getattr(invoke, "requests")[-1].body) == {"attempt": "signup-1"}
    )


@pytest.mark.parametrize("same_email", [False, True], ids=["other-email", "same-email"])
@pytest.mark.parametrize("old_mode,new_mode", [("sync", "async"), ("async", "sync")])
async def test_verification_clears_only_the_snapshotted_email_across_modes(
    old_mode: str, new_mode: str, same_email: bool
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
                            binding.invoke,
                            sync_transport,
                            operation,
                            payload,
                            read_record,
                        )
                    return await binding.invoke_async(
                        async_transport, operation, payload, read_record
                    )

                signup = {"email": "a@example.invalid", "password": "unused"}
                await call(old_mode, "auth.signup", signup)
                task = asyncio.create_task(
                    call(old_mode, "auth.verify_email", {"code": "123456"})
                )
                await asyncio.wait_for(verifying.wait(), 5)
                try:
                    await asyncio.wait_for(
                        call(
                            new_mode,
                            "auth.signup",
                            {
                                **signup,
                                "email": signup["email"]
                                if same_email
                                else "b@example.invalid",
                            },
                        ),
                        5,
                    )
                finally:
                    release.set()
                    await asyncio.wait_for(task, 5)
                if same_email:
                    before = len(peer.received)
                    with pytest.raises(
                        ClientError,
                        check=lambda error: error.code == "invalid_argument",
                    ):
                        await call(new_mode, "auth.verify_email", {"code": "123456"})
                    assert len(peer.received) == before
                    return
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


@pytest.mark.parametrize(
    "signup_mode,clear_mode", [("sync", "async"), ("async", "sync")]
)
@pytest.mark.parametrize(
    "action,seed,other_email",
    [
        ("logout", True, False),
        ("logout", False, True),
        ("signin", True, False),
        ("signin", True, True),
        ("signin", False, False),
        ("verify", True, False),
        ("verify", True, True),
        ("verify-email", False, False),
        ("verify-unknown", True, False),
    ],
)
async def test_pending_signup_cannot_revive_a_cleared_email(
    signup_mode: str, clear_mode: str, action: str, seed: bool, other_email: bool
) -> None:
    binding = SignupBinding()
    started = asyncio.Event()
    release = asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.signup":
            delayed = json.loads(request.body).get("password") == "delayed"
            if delayed:
                started.set()
                await release.wait()
            await respond(
                writer,
                json_bytes(
                    {"accepted": True, "attempt": "late" if delayed else "first"}
                ),
            )
        elif request.path == "/auth.logout":
            await respond(writer, json_bytes({"status": "signed_out"}))
        elif request.path == "/auth.send_verification_email":
            await respond(writer, json_bytes({"accepted": True}))
        else:
            await respond(
                writer, json_bytes({**asdict(credentials()), "email_verified": True})
            )

    async with Peer(handler) as peer:
        async with AsyncHttpTransport(peer.origin, persist=False) as async_transport:
            with HttpTransport(peer.origin, persist=False) as sync_transport:

                async def call(
                    mode: str, operation: str, payload: Mapping[str, object]
                ) -> object:
                    if mode == "sync":
                        return await asyncio.to_thread(
                            binding.invoke,
                            sync_transport,
                            operation,
                            payload,
                            read_record,
                        )
                    return await binding.invoke_async(
                        async_transport, operation, payload, read_record
                    )

                if seed:
                    await call(
                        signup_mode,
                        "auth.signup",
                        {"email": "a@example.invalid", "password": "unused"},
                    )
                pending = asyncio.create_task(
                    call(
                        signup_mode,
                        "auth.signup",
                        {
                            "email": "b@example.invalid"
                            if other_email
                            else "a@example.invalid",
                            "password": "delayed",
                        },
                    )
                )
                await asyncio.wait_for(started.wait(), 5)
                try:
                    if action == "logout":
                        await call(clear_mode, "auth.logout", {})
                    elif action == "signin":
                        await call(
                            clear_mode,
                            "auth.signin",
                            {"email": " A@EXAMPLE.INVALID ", "password": "accepted"},
                        )
                    else:
                        target: dict[str, object] = {"code": "123456"}
                        if action == "verify-email":
                            target["email"] = " A@EXAMPLE.INVALID "
                        elif action == "verify-unknown":
                            target["attempt"] = "unknown"
                        await call(clear_mode, "auth.verify_email", target)
                        if action == "verify-unknown":
                            await call(clear_mode, "auth.send_verification_email", {})
                            assert bool(
                                json.loads(peer.received[-1].body)
                                == {"attempt": "first"}
                            )
                finally:
                    release.set()
                    await asyncio.wait_for(pending, 5)
                if action != "logout" and (other_email or action == "verify-unknown"):
                    await call(clear_mode, "auth.send_verification_email", {})
                    assert bool(
                        json.loads(peer.received[-1].body) == {"attempt": "late"}
                    )
                else:
                    before = len(peer.received)
                    with pytest.raises(
                        ClientError,
                        check=lambda error: error.code == "invalid_argument",
                    ):
                        await call(clear_mode, "auth.verify_email", {"code": "123456"})
                    assert len(peer.received) == before
