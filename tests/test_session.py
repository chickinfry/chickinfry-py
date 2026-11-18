import asyncio
import gc
import secrets
from dataclasses import asdict, replace

import pytest

from chickinfry import (
    AsyncHttpTransport,
    ClientError,
    MemoryStore,
    OperationError,
    SessionCredentials,
)

from .peer import Peer, Received, json_bytes, respond


def credentials() -> SessionCredentials:
    return SessionCredentials(
        access_token=secrets.token_urlsafe(32),
        refresh_token=secrets.token_urlsafe(32),
        expires_at="2026-10-13T12:34:56.123456Z",
        refresh_expires_at="2026-10-20T12:34:56Z",
        user_id="user",
        session_id="session",
    )


def test_store_snapshot_generation_and_secret_repr() -> None:
    original = credentials()
    store = MemoryStore("HTTPS://example.com:443/", original)
    old = store.credentials()
    assert old is not None
    assert bool(
        original.access_token not in repr(old)
        and original.refresh_token not in repr(old)
    )
    store.replace(original)
    new = store.credentials()
    assert new is not old
    store.clear(old)
    assert store.credentials() is new
    assert new is not None
    store.clear(new)
    assert store.credentials() is None
    with pytest.raises(
        ClientError, check=lambda error: error.code == "failed_precondition"
    ):
        store.replace(replace(original, access_token=original.access_token + "\n"))
    with pytest.raises(
        ClientError, check=lambda error: error.code == "failed_precondition"
    ):
        store.replace(replace(original, expires_at=""))
    assert store.credentials() is None


@pytest.mark.parametrize(
    ("status", "code", "operation", "refreshes", "requests"),
    [
        (401, "invalid_token", "thing.run", 1, 2),
        (401, "invalid_token", "probe.list", 1, 2),
        (401, "other_error", "thing.run", 0, 1),
        (403, "invalid_token", "thing.run", 0, 1),
        (500, "invalid_token", "thing.run", 0, 1),
        (401, "invalid_token", "auth.refresh", 0, 1),
    ],
)
async def test_refresh_trigger_and_identical_original_bytes(
    status: int,
    code: str,
    operation: str,
    refreshes: int,
    requests: int,
) -> None:
    old, rotated = credentials(), credentials()
    payload: dict[str, object] = {
        "timestamp": "2026-10-13T12:34:56.123456Z",
        "text": "\ud55c",
    }
    original_body = json_bytes(payload)
    refresh_count = 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal refresh_count
        if request.path == "/auth.refresh" and operation != "auth.refresh":
            refresh_count += 1
            assert "authorization" not in request.headers
            assert bool(
                request.body == json_bytes({"refresh_token": old.refresh_token})
            )
            await respond(writer, json_bytes(asdict(rotated)))
        else:
            if operation == "auth.refresh":
                assert "authorization" not in request.headers
            payload["text"] = "changed after first send"
            await respond(writer, json_bytes({"error": code}), status=status)

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as owner:
        store = MemoryStore(peer.origin, old)
        transport = owner.with_session(store)
        invoke = (
            getattr(transport, "invoke_public")
            if operation == "probe.list"
            else transport.invoke
        )
        with pytest.raises(OperationError) as caught:
            await invoke(operation, payload)
        assert caught.value.status == status and caught.value.code == code
        assert refresh_count == refreshes
        business = [item for item in peer.received if item.path == "/" + operation]
        assert len(business) == requests
        assert all(item.body == original_body for item in business)
        if refreshes:
            assert bool(
                business[-1].headers["authorization"]
                == "Bearer " + rotated.access_token
            )


@pytest.mark.parametrize("mode", ["anonymous", "bearer"])
async def test_non_session_transport_does_not_refresh(mode: str) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer, b'{"error":"invalid_token"}', status=401)

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as owner:
        transport = (
            owner
            if mode == "anonymous"
            else owner.with_bearer(secrets.token_urlsafe(32))
        )
        with pytest.raises(OperationError):
            await transport.invoke("thing.run", {})
        assert len(peer.received) == 1


@pytest.mark.parametrize(
    "outcome", ["success", "rejected", "network", "server", "malformed", "timeout"]
)
async def test_single_flight_across_owners_and_late_401(outcome: str) -> None:
    old, rotated = credentials(), credentials()
    first_count = 0
    refresh_count = 0
    all_started = asyncio.Event()
    release_late = asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal first_count, refresh_count
        if request.path == "/auth.refresh":
            refresh_count += 1
            await asyncio.sleep(0.01)
            if outcome == "network":
                return
            if outcome == "timeout":
                await request.reader.read()
                return
            if outcome == "rejected":
                await respond(writer, b'{"error":"invalid_token"}', status=401)
            elif outcome == "server":
                await respond(writer, b'{"error":"operation_failed"}', status=500)
            elif outcome == "malformed":
                await respond(writer, b'{"access_token":null}')
            else:
                await respond(writer, json_bytes(asdict(rotated)))
        elif request.headers.get("authorization") == "Bearer " + old.access_token:
            first_count += 1
            if first_count == 6:
                all_started.set()
            await all_started.wait()
            if request.path == "/thing.late":
                await release_late.wait()
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            assert bool(
                request.headers.get("authorization") == "Bearer " + rotated.access_token
            )
            await respond(writer, b'{"ok":"yes"}')

    async with (
        Peer(handler) as peer,
        AsyncHttpTransport(peer.origin, timeout=0.4) as left,
        AsyncHttpTransport(peer.origin, timeout=0.4) as right,
    ):
        store = MemoryStore(peer.origin, old)
        copies = [left.with_session(store), right.with_session(store)]

        async def run(index: int) -> str:
            try:
                await copies[index % 2].invoke(
                    "thing.late" if index == 5 else "thing.run", {}
                )
                return "success"
            except OperationError as failure:
                return failure.code
            except ClientError as failure:
                return failure.code
            finally:
                if index != 5:
                    release_late.set()

        results = await asyncio.wait_for(
            asyncio.gather(*(run(index) for index in range(6))), 2
        )
        expected = {
            "success": "success",
            "rejected": "invalid_token",
            "network": "unavailable",
            "server": "operation_failed",
            "malformed": "internal",
            "timeout": "deadline_exceeded",
        }[outcome]
        assert results == [expected] * 6
        assert refresh_count == 1
        assert len(peer.received) == (13 if outcome == "success" else 7)
        current = store.credentials()
        if outcome == "rejected":
            assert current is None
        else:
            assert current is not None
            assert bool(
                current.access_token
                == (rotated.access_token if outcome == "success" else old.access_token)
            )
        assert not store._flights and not store._active


async def test_cancelled_waiter_does_not_cancel_shared_refresh() -> None:
    old, rotated = credentials(), credentials()
    started = asyncio.Event()
    release = asyncio.Event()
    requests = 0
    refresh_count = 0
    two_started = asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal requests, refresh_count
        if request.path == "/auth.refresh":
            refresh_count += 1
            started.set()
            await release.wait()
            await respond(writer, json_bytes(asdict(rotated)))
        elif request.headers["authorization"] == "Bearer " + old.access_token:
            requests += 1
            if requests == 2:
                two_started.set()
            await two_started.wait()
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            await respond(writer)

    async with (
        Peer(handler) as peer,
        AsyncHttpTransport(peer.origin) as left,
        AsyncHttpTransport(peer.origin) as right,
    ):
        store = MemoryStore(peer.origin, old)
        first = asyncio.create_task(left.with_session(store).invoke("thing.run", {}))
        second = asyncio.create_task(right.with_session(store).invoke("thing.run", {}))
        await asyncio.wait_for(started.wait(), 1)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
        release.set()
        assert await asyncio.wait_for(second, 1) == {}
        assert refresh_count == 1
        assert len(peer.received) == 4


@pytest.mark.parametrize(
    ("action", "outcome"),
    [
        ("login", "success"),
        ("login", "rejected"),
        ("logout", "success"),
        ("logout", "rejected"),
        ("same_login", "success"),
        ("same_login", "rejected"),
    ],
)
async def test_late_refresh_does_not_overwrite_login_or_logout(
    action: str, outcome: str
) -> None:
    old, rotated, latest = credentials(), credentials(), credentials()
    started, release = asyncio.Event(), asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            started.set()
            await release.wait()
            if outcome == "success":
                await respond(writer, json_bytes(asdict(rotated)))
            else:
                await respond(writer, b'{"error":"invalid_token"}', status=401)
        elif not release.is_set():
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            expected = old if action == "same_login" else latest
            assert bool(
                request.headers["authorization"] == "Bearer " + expected.access_token
            )
            await respond(writer)

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as owner:
        store = MemoryStore(peer.origin, old)
        first_snapshot = store.credentials()
        assert first_snapshot is not None
        task = asyncio.create_task(
            owner.with_session(store).invoke("thing.run", b'{  "text":  "\\uD55C" }')
        )
        await asyncio.wait_for(started.wait(), 1)
        if action == "logout":
            store.clear(first_snapshot)
        else:
            store.replace(old if action == "same_login" else latest)
        after_change = store.credentials()
        release.set()
        with pytest.raises(
            OperationError, check=lambda error: error.code == "invalid_token"
        ):
            await task
        assert store.credentials() is after_change
        assert len(peer.received) == 2


@pytest.mark.parametrize(
    "field",
    [
        "access_token",
        "refresh_token",
        "expires_at",
        "refresh_expires_at",
        "user_id",
        "session_id",
    ],
)
@pytest.mark.parametrize("bad", ["missing", "null", "wrong_type", "empty"])
async def test_refresh_all_required_fields_and_credentials_preserved(
    field: str, bad: str
) -> None:
    old, rotated = credentials(), credentials()
    record: dict[str, object] = dict(asdict(rotated))
    if bad == "missing":
        del record[field]
    else:
        record[field] = None if bad == "null" else 7 if bad == "wrong_type" else ""

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            await respond(writer, json_bytes(record))
        else:
            await respond(writer, b'{"error":"invalid_token"}', status=401)

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as owner:
        store = MemoryStore(peer.origin, old)
        snapshot = store.credentials()
        with pytest.raises(
            ClientError, check=lambda error: error.code == "internal"
        ) as caught:
            await owner.with_session(store).invoke("thing.run", {})
        assert caught.value.status == 200
        assert store.credentials() is snapshot
        assert len(peer.received) == 2


@pytest.mark.parametrize("previous_flight", ["none", "success", "rejected"])
async def test_new_login_before_401_does_not_replay(
    previous_flight: str,
) -> None:
    old, latest = credentials(), credentials()
    started, release = asyncio.Event(), asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            if previous_flight == "success":
                await respond(writer, json_bytes(asdict(latest)))
            else:
                await respond(writer, b'{"error":"invalid_token"}', status=401)
        elif request.headers["authorization"] == "Bearer " + old.access_token:
            if request.path == "/thing.run":
                started.set()
                await release.wait()
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            assert bool(
                request.headers["authorization"] == "Bearer " + latest.access_token
            )
            await respond(writer)

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as owner:
        store = MemoryStore(peer.origin, old)
        task = asyncio.create_task(owner.with_session(store).invoke("thing.run", {}))
        await asyncio.wait_for(started.wait(), 1)
        if previous_flight != "none":
            if previous_flight == "rejected":
                with pytest.raises(
                    OperationError, check=lambda error: error.code == "invalid_token"
                ):
                    await owner.with_session(store).invoke("thing.early", {})
            else:
                assert await owner.with_session(store).invoke("thing.early", {}) == {}
        store.replace(latest)
        release.set()
        with pytest.raises(
            OperationError, check=lambda error: error.code == "invalid_token"
        ):
            await task
        assert (
            len(peer.received)
            == {"none": 1, "success": 4, "rejected": 3}[previous_flight]
        )
        assert sum(item.path == "/auth.refresh" for item in peer.received) == (
            previous_flight != "none"
        )


async def test_total_deadline_limits_wait_for_other_owners_refresh() -> None:
    old, rotated = credentials(), credentials()
    started, release = asyncio.Event(), asyncio.Event()
    refresh_count = 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal refresh_count
        if request.path == "/auth.refresh":
            refresh_count += 1
            started.set()
            await release.wait()
            await respond(writer, json_bytes(asdict(rotated)))
        elif request.headers["authorization"] == "Bearer " + old.access_token:
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            await respond(writer)

    async with (
        Peer(handler) as peer,
        AsyncHttpTransport(peer.origin, timeout=1) as slow,
        AsyncHttpTransport(peer.origin, timeout=0.05) as fast,
    ):
        store = MemoryStore(peer.origin, old)
        slow_task = asyncio.create_task(
            slow.with_session(store).invoke("thing.run", {})
        )
        await asyncio.wait_for(started.wait(), 1)
        begin = asyncio.get_running_loop().time()
        with pytest.raises(
            ClientError, check=lambda error: error.code == "deadline_exceeded"
        ):
            await fast.with_session(store).invoke("thing.run", {})
        assert asyncio.get_running_loop().time() - begin < 0.4
        release.set()
        assert await slow_task == {}
        assert refresh_count == 1


async def test_orphaned_refresh_failure_is_consumed_and_reclaimed() -> None:
    old = credentials()
    started, release = asyncio.Event(), asyncio.Event()
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    unhandled: list[dict[str, object]] = []

    def on_error(loop: asyncio.AbstractEventLoop, context: dict[str, object]) -> None:
        unhandled.append(context)

    loop.set_exception_handler(on_error)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            started.set()
            await release.wait()
            return
        await respond(writer, b'{"error":"invalid_token"}', status=401)

    try:
        async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as owner:
            store = MemoryStore(peer.origin, old)
            task = asyncio.create_task(
                owner.with_session(store).invoke("thing.run", {})
            )
            await asyncio.wait_for(started.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            flights = list(store._flights.values())
            release.set()
            await asyncio.gather(*flights, return_exceptions=True)
            await asyncio.sleep(0)
            assert not store._flights and not store._active
        gc.collect()
        await asyncio.sleep(0)
        assert not unhandled
    finally:
        loop.set_exception_handler(previous)
