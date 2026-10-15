import asyncio
import threading
import time
from collections.abc import Coroutine, Generator
from concurrent.futures import ThreadPoolExecutor
from contextvars import Context
from dataclasses import asdict
from typing import TypeVar, cast

import httpx
import pytest

from chickinfry import HTTP, AsyncHTTP, ClientError, OperationError, SessionStore

from .deadline import Clock
from .peer import Peer, Received, json_bytes, respond
from .test_session import credentials

_T = TypeVar("_T")


@pytest.mark.parametrize(
    ("status", "code", "operation", "refreshes", "requests"),
    [
        (401, "invalid_token", "thing.run", 1, 2),
        (401, "other_error", "thing.run", 0, 1),
        (403, "invalid_token", "thing.run", 0, 1),
        (401, "invalid_token", "auth.refresh", 0, 1),
    ],
)
async def test_sync_refresh_only_once_and_first_bytes(
    status: int, code: str, operation: str, refreshes: int, requests: int
) -> None:
    old, rotated = credentials(), credentials()
    refresh_count = 0
    body = b'{  "text": "\\uD55C", "time": "2026-10-13T12:34:56.123456Z" }'

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
            await respond(writer, json_bytes({"error": code}), status=status)

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            with pytest.raises(OperationError) as caught:
                await asyncio.to_thread(
                    owner.with_session(store).invoke, operation, body
                )
            assert caught.value.status == status and caught.value.code == code
            business = [item for item in peer.received if item.path == "/" + operation]
            assert len(business) == requests and all(
                item.body == body for item in business
            )
            assert refresh_count == refreshes


@pytest.mark.parametrize(
    "outcome", ["success", "rejected", "network", "server", "malformed", "timeout"]
)
async def test_sync_threads_share_one_result_including_late_401(
    outcome: str, deadline_tolerance: float
) -> None:
    old, rotated = credentials(), credentials()
    all_started, release_late = asyncio.Event(), asyncio.Event()
    received_first = 0
    refresh_count = 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal received_first, refresh_count
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
        elif request.headers["authorization"] == "Bearer " + old.access_token:
            received_first += 1
            if received_first == 6:
                all_started.set()
            await all_started.wait()
            if request.path == "/thing.late":
                await release_late.wait()
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            assert bool(
                request.headers["authorization"] == "Bearer " + rotated.access_token
            )
            await respond(writer)

    loop = asyncio.get_running_loop()
    async with Peer(handler) as peer:
        with (
            HTTP(peer.origin, timeout=0.4) as left,
            HTTP(peer.origin, timeout=0.4) as right,
        ):
            store = SessionStore(peer.origin, old)
            snapshot = store.credentials()
            copies = [left.with_session(store), right.with_session(store)]
            barrier = threading.Barrier(6)

            def call(index: int) -> ClientError | None:
                barrier.wait()
                try:
                    copies[index % 2].invoke(
                        "thing.late" if index == 5 else "thing.run", {}
                    )
                    return None
                except ClientError as failure:
                    return failure
                finally:
                    if index != 5:
                        loop.call_soon_threadsafe(release_late.set)

            def calls() -> list[ClientError | None]:
                with ThreadPoolExecutor(max_workers=6) as executor:
                    return list(executor.map(call, range(6)))

            results = await asyncio.wait_for(asyncio.to_thread(calls), 2)
            expected = {
                "success": None,
                "rejected": "invalid_token",
                "network": "network_error",
                "server": "operation_failed",
                "malformed": "invalid_response",
                "timeout": "timeout",
            }[outcome]
            assert [
                (error.code if isinstance(error, OperationError) else error.reason)
                if error is not None
                else None
                for error in results
            ] == [expected] * 6
            if outcome != "success":
                assert len({id(error) for error in results}) == 6
            assert refresh_count == 1
            assert len(peer.received) == (13 if outcome == "success" else 7)
            current = store.credentials()
            if outcome == "rejected":
                assert current is None
            elif outcome == "success":
                assert current is not None and bool(
                    current.access_token == rotated.access_token
                )
            else:
                assert current is snapshot
            with store._locked():
                remaining_flights = list(store._sync_flights.values())
            for flight in remaining_flights:
                assert flight.thread is not None
                await asyncio.to_thread(
                    flight.thread.join,
                    max(0.0, flight.deadline + deadline_tolerance - time.monotonic()),
                )
                assert not flight.thread.is_alive()
            assert not store._active and not store._sync_flights


@pytest.mark.parametrize(
    ("action", "outcome"),
    [
        ("login", "success"),
        ("login", "rejected"),
        ("same_login", "success"),
        ("same_login", "rejected"),
        ("logout", "success"),
        ("logout", "rejected"),
    ],
)
async def test_sync_other_thread_login_logout_preserves_generation(
    action: str, outcome: str
) -> None:
    old, rotated, latest = credentials(), credentials(), credentials()
    started, release = asyncio.Event(), asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            started.set()
            await release.wait()
            await respond(
                writer,
                json_bytes(asdict(rotated))
                if outcome == "success"
                else b'{"error":"invalid_token"}',
                status=200 if outcome == "success" else 401,
            )
        elif not release.is_set():
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            expected = old if action == "same_login" else latest
            assert bool(
                request.headers["authorization"] == "Bearer " + expected.access_token
            )
            await respond(writer)

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            signed = owner.with_session(store)
            original = store.credentials()
            assert original is not None
            task = asyncio.create_task(
                asyncio.to_thread(signed.invoke, "thing.run", {})
            )
            await asyncio.wait_for(started.wait(), 1)
            if action == "logout":
                await asyncio.to_thread(store.clear, original)
            else:
                await asyncio.to_thread(
                    store.replace, old if action == "same_login" else latest
                )
            changed = store.credentials()
            release.set()
            if outcome == "rejected" or action == "logout":
                with pytest.raises(
                    OperationError, check=lambda error: error.code == "invalid_token"
                ):
                    await task
            else:
                assert await task == {}
            assert store.credentials() is changed
            assert not store._active and not store._sync_flights


async def test_sync_short_waiter_fixed_deadline_does_not_cancel_producer(
    monkeypatch: pytest.MonkeyPatch, sync_clock: Clock
) -> None:
    old, rotated = credentials(), credentials()
    started, release = threading.Event(), threading.Event()
    refresh_count = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal refresh_count
        if request.url.path == "/auth.refresh":
            refresh_count += 1
            started.set()
            assert release.wait(5)
            return httpx.Response(
                200, stream=httpx.ByteStream(json_bytes(asdict(rotated)))
            )
        if request.headers["authorization"] == "Bearer " + old.access_token:
            return httpx.Response(
                401, stream=httpx.ByteStream(b'{"error":"invalid_token"}')
            )
        return httpx.Response(200, stream=httpx.ByteStream(b"{}"))

    with (
        HTTP("http://127.0.0.1", timeout=1) as leader,
        HTTP("http://127.0.0.1", timeout=0.06) as short,
    ):
        for owner in (leader, short):
            assert owner._client is not None
            owner._client.close()
            owner._client = httpx.Client(transport=httpx.MockTransport(handler))
        store = SessionStore("http://127.0.0.1", old)
        snapshot = store.credentials()
        first = asyncio.create_task(
            asyncio.to_thread(leader.with_session(store).invoke, "thing.run", {})
        )
        waits: list[float | None] = []
        wait = store._condition.wait
        caller: int | None = None

        def wake(timeout: float | None = None) -> bool:
            if threading.get_ident() != caller:
                return wait(timeout)
            waits.append(timeout)
            assert len(waits) <= 3, "Spurious wakeup restarted the waiter deadline"
            assert timeout is not None
            sync_clock.advance(min(0.06, timeout))
            return True

        def invoke() -> object:
            nonlocal caller
            caller = threading.get_ident()
            return short.with_session(store).invoke("thing.run", {})

        # Real waits only guard thread liveness; all deadline assertions use virtual time.
        try:
            assert await asyncio.to_thread(started.wait, 5)
            monkeypatch.setattr(store._condition, "wait", wake)
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "timeout"
            ):
                await asyncio.to_thread(invoke)
            assert waits == pytest.approx([0.18, 0.12, 0.06])
            assert sync_clock.now == pytest.approx(0.18)
            assert store.credentials() is snapshot
            assert not first.done()
            with store._locked():
                flight = next(iter(store._sync_flights.values()))
                assert not flight.settled and not flight.producer_done
        finally:
            release.set()
            assert await asyncio.wait_for(first, 5) == {}
        assert refresh_count == 1
        assert store.credentials() == rotated


async def test_sync_keyboard_interrupt_waiter_leaves_other_waiter_running(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            signed = owner.with_session(store)
            first = asyncio.create_task(
                asyncio.to_thread(signed.invoke, "thing.run", {})
            )
            await asyncio.wait_for(started.wait(), 1)
            original_wait = store._condition.wait

            def interrupted(timeout: float | None = None) -> bool:
                if threading.current_thread().name == "interrupted-caller":
                    raise KeyboardInterrupt
                return original_wait(timeout)

            monkeypatch.setattr(store._condition, "wait", interrupted)

            def call() -> bool:
                threading.current_thread().name = "interrupted-caller"
                try:
                    signed.invoke("thing.run", {})
                except KeyboardInterrupt:
                    return True
                return False

            assert await asyncio.to_thread(call)
            release.set()
            assert await first == {}
            assert refresh_count == 1 and not store._active


@pytest.mark.parametrize("fault", ["start", "network_exception"])
async def test_sync_producer_failure_wakes_and_preserves_credentials(
    monkeypatch: pytest.MonkeyPatch, fault: str, capsys: pytest.CaptureFixture[str]
) -> None:
    old = credentials()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer, b'{"error":"invalid_token"}', status=401)

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            signed = owner.with_session(store)
            original_snapshot = store.credentials()
            original_start = threading.Thread.start

            def fail_start(thread: threading.Thread) -> None:
                raise RuntimeError(old.access_token)

            import socket

            original_resolve = socket.getaddrinfo

            def fail_resolve(
                host: str,
                port: int,
                family: int = 0,
                type: int = 0,
                proto: int = 0,
                flags: int = 0,
            ) -> list[
                tuple[
                    socket.AddressFamily,
                    socket.SocketKind,
                    int,
                    str,
                    tuple[str, int] | tuple[str, int, int, int] | tuple[int, bytes],
                ]
            ]:
                if threading.current_thread().name.startswith("Thread-"):
                    raise ArithmeticError(old.refresh_token)
                return cast(
                    list[
                        tuple[
                            socket.AddressFamily,
                            socket.SocketKind,
                            int,
                            str,
                            tuple[str, int]
                            | tuple[str, int, int, int]
                            | tuple[int, bytes],
                        ]
                    ],
                    original_resolve(host, port, family, type, proto, flags),
                )

            def call() -> ClientError | None:
                if fault == "start":
                    monkeypatch.setattr(threading.Thread, "start", fail_start)
                else:
                    monkeypatch.setattr(socket, "getaddrinfo", fail_resolve)
                try:
                    signed.invoke("thing.run", {})
                except ClientError as failure:
                    return failure
                finally:
                    monkeypatch.setattr(threading.Thread, "start", original_start)
                    monkeypatch.setattr(socket, "getaddrinfo", original_resolve)
                return None

            result = await asyncio.to_thread(call)
            assert result is not None and result.reason == "network_error"
            assert bool(
                old.access_token not in repr(result)
                and old.refresh_token not in repr(result)
            )
            assert store.credentials() is original_snapshot
            assert not store._active and not store._sync_flights
    output = capsys.readouterr()
    assert bool(
        old.access_token not in output.out + output.err
        and old.refresh_token not in output.out + output.err
    )


@pytest.mark.parametrize("first_mode", ["sync", "async"])
async def test_store_mode_never_changes_after_clear_replace_or_close(
    first_mode: str,
) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    async with Peer(handler) as peer:
        store = SessionStore(peer.origin, credentials())
        sync, asynchronous = HTTP(peer.origin), AsyncHTTP(peer.origin)
        if first_mode == "sync":
            sync.with_session(store)
        else:
            asynchronous.with_session(store)
        snapshot = store.credentials()
        assert snapshot is not None
        store.clear(snapshot)
        store.replace(credentials())
        sync.close()
        await asynchronous.aclose()
        with HTTP(peer.origin) as next_sync:
            async with AsyncHTTP(peer.origin) as next_async:
                with pytest.raises(
                    ClientError, check=lambda error: error.reason == "invalid_session"
                ):
                    if first_mode == "sync":
                        next_async.with_session(store)
                    else:
                        next_sync.with_session(store)
        assert not peer.received


async def test_store_mode_attachment_is_atomic_between_threads() -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    async with Peer(handler) as peer:
        store = await asyncio.to_thread(SessionStore, peer.origin, credentials())
        sync, asynchronous = HTTP(peer.origin), AsyncHTTP(peer.origin)
        barrier = threading.Barrier(2)

        def attach(mode: str) -> str:
            barrier.wait()
            try:
                if mode == "sync":
                    sync.with_session(store)
                else:
                    asynchronous.with_session(store)
                return mode
            except ClientError as failure:
                return failure.reason

        def run() -> list[str]:
            with ThreadPoolExecutor(max_workers=2) as executor:
                return list(executor.map(attach, ["sync", "async"]))

        outcomes = await asyncio.to_thread(run)
        assert outcomes.count("invalid_session") == 1
        assert sum(value in {"sync", "async"} for value in outcomes) == 1
        assert not peer.received
        sync.close()
        await asynchronous.aclose()


async def test_sync_expired_flight_retains_producer_and_discards_late_success(
    monkeypatch: pytest.MonkeyPatch, sync_clock: Clock
) -> None:
    old, rotated, latest = credentials(), credentials(), credentials()
    got_result, release = threading.Event(), threading.Event()
    requests: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/auth.refresh":
            return httpx.Response(
                200, stream=httpx.ByteStream(json_bytes(asdict(rotated)))
            )
        return httpx.Response(
            401, stream=httpx.ByteStream(b'{"error":"invalid_token"}')
        )

    with HTTP("http://127.0.0.1", timeout=0.20) as owner:
        assert owner._client is not None
        owner._client.close()
        owner._client = httpx.Client(transport=httpx.MockTransport(handler))
        store = SessionStore("http://127.0.0.1", old)
        snapshot = store.credentials()
        signed = owner.with_session(store)
        original = owner._attempt
        producer: threading.Thread | None = None

        def delayed(
            operation: str,
            body: bytes,
            token: str | None,
            deadline: float,
            *,
            credentials: bool = False,
        ) -> object:
            nonlocal producer
            result = original(operation, body, token, deadline, credentials=credentials)
            if operation == "auth.refresh":
                producer = threading.current_thread()
                got_result.set()
                assert release.wait(5)
            return result

        waits: list[float | None] = []

        def wake(timeout: float | None = None) -> bool:
            assert got_result.wait(5)
            waits.append(timeout)
            assert len(waits) <= 4, "Spurious wakeup restarted the flight deadline"
            assert timeout is not None
            sync_clock.advance(min(0.05, timeout))
            return True

        monkeypatch.setattr(owner, "_attempt", delayed)
        monkeypatch.setattr(store._condition, "wait", wake)
        call = asyncio.create_task(asyncio.to_thread(signed.invoke, "thing.run", {}))
        try:
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "timeout"
            ):
                await asyncio.wait_for(call, 5)
            assert waits == pytest.approx([0.20, 0.15, 0.10, 0.05])
            assert sync_clock.now == pytest.approx(0.20)
            with store._locked():
                assert len(store._sync_flights) == 1
                flight = next(iter(store._sync_flights.values()))
                assert flight.settled and not flight.producer_done
                assert flight.thread is producer
            assert store.credentials() is snapshot
            await asyncio.to_thread(store.replace, latest)
            changed = store.credentials()
        finally:
            release.set()
            if producer is not None:
                await asyncio.to_thread(producer.join, 5)
        assert producer is not None and not producer.is_alive()
        assert store.credentials() is changed
        assert not store._sync_flights and not store._active
        assert requests == ["/thing.run", "/auth.refresh"]


@pytest.mark.parametrize("old_flight", [False, True])
async def test_sync_new_login_before_late_401_skips_old_refresh(
    old_flight: bool,
) -> None:
    old, latest = credentials(), credentials()
    started, release = asyncio.Event(), asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        elif request.headers["authorization"] == "Bearer " + old.access_token:
            if request.path == "/thing.late":
                started.set()
                await release.wait()
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            assert bool(
                request.headers["authorization"] == "Bearer " + latest.access_token
            )
            await respond(writer)

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            signed = owner.with_session(store)
            call = asyncio.create_task(
                asyncio.to_thread(signed.invoke, "thing.late", {})
            )
            await asyncio.wait_for(started.wait(), 1)
            if old_flight:
                with pytest.raises(OperationError):
                    await asyncio.to_thread(signed.invoke, "thing.early", {})
            await asyncio.to_thread(store.replace, latest)
            release.set()
            assert await call == {}
            assert (
                sum(request.path == "/auth.refresh" for request in peer.received)
                == old_flight
            )
            assert not store._active and not store._sync_flights


@pytest.mark.parametrize("invalid", ["origin", "credentials"])
async def test_failed_attachment_does_not_pin_mode(invalid: str) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    async with Peer(handler) as peer:
        store = SessionStore(
            peer.origin, credentials() if invalid == "origin" else None
        )
        with HTTP(peer.origin) as sync:
            if invalid == "origin":
                with pytest.raises(
                    ClientError, check=lambda error: error.reason == "origin_mismatch"
                ):
                    AsyncHTTP("https://example.com").with_session(store)
                sync.with_session(store)
                assert store._mode == "sync"
            else:
                with pytest.raises(
                    ClientError, check=lambda error: error.reason == "invalid_session"
                ):
                    sync.with_session(store)
                store.replace(credentials())
                asynchronous = AsyncHTTP(peer.origin)
                asynchronous.with_session(store)
                assert store._mode == "async"
                await asynchronous.aclose()
            assert not peer.received


async def test_async_refresh_task_factory_runs_outside_store_lock() -> None:
    old, rotated = credentials(), credentials()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            await respond(writer, json_bytes(asdict(rotated)))
        elif request.headers["authorization"] == "Bearer " + old.access_token:
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            await respond(writer)

    async with Peer(handler) as peer:
        async with AsyncHTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            signed = owner.with_session(store)
            available: list[bool] = []
            loop = asyncio.get_running_loop()
            previous = loop.get_task_factory()

            def factory(
                loop: asyncio.AbstractEventLoop,
                coroutine: Generator[asyncio.Future[object] | None, None, _T]
                | Coroutine[object, object, _T],
                **kwargs: object,
            ) -> asyncio.Task[_T]:
                def probe() -> None:
                    acquired = store._condition.acquire(blocking=False)
                    available.append(acquired)
                    if acquired:
                        store._condition.release()

                checker = threading.Thread(target=probe)
                checker.start()
                checker.join(1)
                context = kwargs.get("context")
                assert isinstance(coroutine, Coroutine)
                return asyncio.Task(
                    coroutine,
                    loop=loop,
                    context=context if isinstance(context, Context) else None,
                )

            loop.set_task_factory(factory)
            try:
                assert await signed.invoke("thing.run", {}) == {}
            finally:
                loop.set_task_factory(previous)
            assert available and all(available)
