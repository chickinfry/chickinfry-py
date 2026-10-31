"""An independent census reads live payload objects, not the hook's registry."""

import asyncio
import dis
import json
import socket
import sys
import threading
import time
import tracemalloc
import weakref
from collections.abc import Callable
from pathlib import Path
from types import FrameType
from typing import Any

import httpx
import pytest

from chickinfry import AsyncHttpTransport, ClientError, HttpTransport
from chickinfry._conformance import _Observation, _observer
from conformance.driver.transport import Events, Transport, prepare, trace

from .fixtures.plain.sdk import AsyncClient, Client, ProbeEchoInput
from .peer import Peer, Received


class Census:
    def __init__(self) -> None:
        self.cores: weakref.WeakSet[Any] = weakref.WeakSet()
        self.generators: weakref.WeakSet[Any] = weakref.WeakSet()
        self.protocols: weakref.WeakSet[Any] = weakref.WeakSet()
        self.responses: weakref.WeakSet[Any] = weakref.WeakSet()
        self.peak = 0
        self.current = 0
        self.positive: set[str] = set()
        self.before_split: dict[int, tuple[int, int]] = {}
        self.max_queue = 0
        self.sockets: dict[int, Any] = {}

    def sample(self, frame: FrameType, result: object) -> None:
        objects: dict[int, int] = {}
        visited: set[int] = set()

        def inspect(value: Any, role: str) -> None:
            if id(value) in visited:
                return
            visited.add(id(value))
            if isinstance(value, memoryview):
                inspect(value.obj, role)
            elif isinstance(value, str):
                count = value.count("\x01")
                objects[id(value)] = count
                if count:
                    self.positive.add(role)
            elif type(value).__name__ == "_Observation":
                for detail in value.details:
                    inspect(detail, "observation")
            elif isinstance(value, (bytes, bytearray)):
                # The fixture's payload byte never occurs in its HTTP framing.
                count = value.count(b"\x01")
                objects[id(value)] = count
                if count:
                    self.positive.add(role)
            elif hasattr(value, "_h11_state"):
                if value not in self.cores:
                    factory = value._receive_response_body
                    original = getattr(factory, "__func__", factory)
                    bound = hasattr(factory, "__self__")
                    reference = weakref.ref(value)

                    def observed_body(request: Any) -> Any:
                        current = reference()
                        assert current is not None, (
                            "The observed connection disappeared"
                        )
                        generator = (
                            original(current, request=request)
                            if bound
                            else original(request=request)
                        )
                        self.generators.add(generator)
                        return generator

                    value._receive_response_body = observed_body
                self.cores.add(value)
                inspect(value._h11_state._receive_buffer._data, "h11")
                stream = value._network_stream
                socket = stream.get_extra_info("socket")
                if socket is not None:
                    self.sockets[id(socket)] = socket
                if hasattr(stream, "_stream") and hasattr(stream._stream, "_protocol"):
                    self.protocols.add(stream._stream._protocol)
            elif hasattr(value, "read_queue"):
                self.protocols.add(value)
                self.max_queue = max(self.max_queue, len(value.read_queue))
                for chunk in value.read_queue:
                    inspect(chunk, "queue")
            elif isinstance(value, httpx.Response):
                self.responses.add(value)
                inspect(vars(value).get("_content"), "httpx")
            elif type(value).__name__ == "_Body":
                inspect(value._body, "sdk")
            elif type(value).__name__ == "Data":
                inspect(value.data, "event")

        for generator in self.generators:
            held = getattr(generator, "ag_frame", None) or getattr(
                generator, "gi_frame", None
            )
            if held is not None:
                for key, value in held.f_locals.items():
                    inspect(value, key)
        failure = sys.exception()
        if isinstance(failure, json.JSONDecodeError):
            inspect(failure.doc, "json-error")
        active: FrameType | None = frame
        while active is not None:
            if active.f_code.co_filename == __file__ and active.f_code.co_name in {
                "controlled_read",
                "coalesced",
            }:
                break
            for key, value in active.f_locals.items():
                inspect(value, key)
            active = active.f_back
        for core in self.cores:
            inspect(core._h11_state._receive_buffer._data, "h11")
        for protocol in self.protocols:
            self.max_queue = max(self.max_queue, len(protocol.read_queue))
            for chunk in protocol.read_queue:
                inspect(chunk, "queue")
        for response in self.responses:
            inspect(vars(response).get("_content"), "httpx")
        inspect(result, "finish" if frame.f_code.co_name == "finish" else "return")
        self.current = sum(objects.values())
        self.peak = max(self.peak, self.current)
        if frame.f_code.co_name == "receive" and "chunk" in frame.f_locals:
            values = frame.f_locals
            if "leftover" not in values:
                chunk = values["chunk"]
                self.before_split[id(frame)] = (id(chunk), chunk.count(b"\x01"))
            elif id(frame) in self.before_split:
                identity, count = self.before_split[id(frame)]
                # Tuple assignment creates both observed slices before releasing its input.
                if identity not in objects:
                    self.peak = max(self.peak, self.current + count)

    def assert_closed(self) -> None:
        assert self.sockets, "No real socket was observed"
        assert all(socket.fileno() == -1 for socket in self.sockets.values()), (
            "A completed reader retained an open socket"
        )


@pytest.mark.parametrize("environment", ["sync", "async"])
@pytest.mark.parametrize("size", [4093, 8191, 16381, 32749, 2 * 32749 + 8191])
@pytest.mark.parametrize("status", [302, 200])
@pytest.mark.parametrize("chunked", [False, True])
async def test_live_redirect_byte_census(
    environment: str,
    size: int,
    status: int,
    chunked: bool,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    prefetch: bool = False,
) -> None:
    observation = _Observation(time.monotonic() + 10, call_id="c:census")
    ledger = Events()
    measured = Transport(observation, ledger)
    measured.calibrating = True
    census = Census()
    publish = measured.publish

    def checked_publish(phase: str, observed_at: float | None = None) -> None:
        if phase == "reader-closed":
            census.assert_closed()
        publish(phase, observed_at)
        if prefetch and phase == "headers":
            census.sample(sys._getframe(1), None)
            comparisons.append(
                ("completed HTTPX store", measured.retained, census.current)
            )

    monkeypatch.setattr(measured, "publish", checked_publish)
    comparisons: list[tuple[str, int, int]] = []
    previous = sys.gettrace()
    selected = {
        "_receivebuffer.py",
        "http11.py",
        "_asyncio.py",
        "_http_common.py",
        "_conformance.py",
        "_models.py",
        "decoder.py",
        "__init__.py",
    }

    def independent(
        frame: FrameType, event: str, arg: object
    ) -> Callable[..., Any] | None:
        trace(frame, event, arg)
        if frame.f_code.co_filename.rsplit("/", 1)[-1] not in selected:
            return None
        if frame.f_code.co_name in {"read", "aread"} and not isinstance(
            frame.f_locals.get("self"), httpx.Response
        ):
            return None
        if frame.f_code.co_name in {
            "__iadd__",
            "__bytes__",
            "_extract",
            "maybe_extract_at_most",
            "receive",
            "data_received",
            "_receive_event",
            "_receive_response_headers",
            "handle_request",
            "handle_async_request",
            "_receive_response_body",
            "feed",
            "finish",
            "read",
            "aread",
            "record_body",
            "_detail",
            "loads",
            "decode",
            "raw_decode",
            "_json_value",
        }:
            census.sample(frame, arg if event == "return" else None)
            if not prefetch and not (
                event == "line" and frame.f_code.co_filename.endswith("/http11.py")
            ):
                comparisons.append(
                    (
                        f"{frame.f_code.co_name}:{frame.f_lineno}:{event}",
                        measured.retained,
                        census.current,
                    )
                )
        return independent

    from anyio._backends._asyncio import StreamProtocol

    from chickinfry._sync_network import _remaining, _Stream

    framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {size}"
    prefix = f"HTTP/1.1 {status} Result\r\n{framing}\r\nLocation: /sink\r\nConnection: close\r\n\r\n".encode()
    chunk_header = f"{size:x}\r\n".encode() if chunked else b""
    suffix = b"\r\n0\r\n\r\n" if chunked else b""
    total = len(prefix) + len(chunk_header) + size + len(suffix)
    original_received = StreamProtocol.data_received
    pending: weakref.WeakKeyDictionary[Any, list[bytes]] = weakref.WeakKeyDictionary()

    def coalesced(protocol: Any, data: bytes) -> None:
        parts = pending.setdefault(protocol, [])
        parts.append(data)
        if sum(map(len, parts)) == total:
            combined = b"".join(parts)
            pending.pop(protocol)
            if total <= 65536 and size >= 8191:
                boundary = len(prefix) + len(chunk_header) + 4093
                original_received(protocol, combined[:boundary])
                original_received(protocol, combined[boundary:])
            else:
                original_received(protocol, combined)

    remaining_wire = total

    def controlled_read(
        stream: _Stream, max_bytes: int, timeout: float | None = None
    ) -> bytes:
        nonlocal remaining_wire
        target = min(max_bytes, remaining_wire)
        remaining_wire -= target
        parts: list[bytes] = []
        remaining = target
        with stream._io() as sock:
            while remaining:
                sock.settimeout(_remaining(timeout))
                part = sock.recv(remaining)
                assert part, "Fixture ended before its fixed read boundary"
                parts.append(part)
                remaining -= len(part)
        data = b"".join(parts)
        parts.clear()
        measured.notify("wire", (stream, data))
        return data

    prepare()
    monkeypatch.setattr(_Stream, "read", controlled_read)
    monkeypatch.setattr(StreamProtocol, "data_received", coalesced)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(prefix + chunk_header + b"\x01" * size + suffix)
        await writer.drain()

    observation.transport = measured.notify
    registration = _observer.set(observation)
    try:
        async with Peer(handler) as peer:
            if environment == "sync":
                with HttpTransport(peer.origin, timeout=2) as owner:
                    if prefetch:
                        owner._http_client().event_hooks["response"].append(
                            lambda response: response.read()
                        )
                    prepare()

                    def invoke() -> None:
                        before = sys.gettrace()
                        sys.settrace(independent)
                        try:
                            with pytest.raises(ClientError) as caught:
                                Client(owner).probe.echo(
                                    ProbeEchoInput(wire_value="ok")
                                )
                            assert caught.value.code == "internal", (
                                f"Census outcome differs: read={measured.read}, wire={measured.wire.offset}, expected={size}, checkpoints={len(comparisons)}"
                            )
                        finally:
                            sys.settrace(before)

                    await asyncio.to_thread(invoke)
            else:
                async with AsyncHttpTransport(peer.origin, timeout=2) as async_owner:
                    import anyio

                    anyio.get_cancelled_exc_class()
                    if prefetch:

                        async def preloaded(response: httpx.Response) -> None:
                            await response.aread()

                        async_owner._http_client().event_hooks["response"].append(
                            preloaded
                        )
                    prepare()
                    sys.settrace(independent)
                    with pytest.raises(ClientError) as caught:
                        await AsyncClient(async_owner).probe.echo(
                            ProbeEchoInput(wire_value="ok")
                        )
                    assert caught.value.code == "internal", (
                        f"Census outcome differs: read={measured.read}, wire={measured.wire.offset}, expected={size}, checkpoints={len(comparisons)}"
                    )
        assert comparisons, "No live buffer checkpoint was reached"
        for checkpoint, reported, actual in comparisons:
            assert reported == actual, (
                f"{checkpoint}: retained byte mismatch: reported={reported}, census={actual}, delta={actual - reported}"
            )
        assert "h11" in census.positive, "The parser never retained body bytes"
        if environment == "async":
            assert "queue" in census.positive, (
                "The AnyIO queue never retained body bytes"
            )
        if prefetch:
            assert "httpx" in census.positive, (
                "The HTTPX completed store was not positive"
            )
            assert measured.complete is False, (
                "A read/aread peak was incorrectly certified"
            )
        if status == 200:
            assert {"sdk", "finish"} <= census.positive, (
                "SDK accumulation or its final copy was not observed"
            )
        if environment == "async" and 8191 <= size <= 32749:
            assert census.max_queue >= 2, "No overlapping queue items were observed"
        if environment == "async" and size > 65536:
            assert "leftover" in census.positive, (
                "The split's leftover was not observed"
            )
        assert census.peak > 0, "No body storage was observed"
        if not prefetch:
            assert measured.peak == census.peak, (
                f"peak byte mismatch: reported={measured.peak}, census={census.peak}"
            )
    finally:
        _observer.reset(registration)
        sys.settrace(previous)


@pytest.mark.parametrize("environment", ["sync", "async"])
@pytest.mark.parametrize("chunked", [False, True])
async def test_transport_allocation_crosscheck(
    environment: str, chunked: bool, tmp_path: Path
) -> None:
    # Allocation tracing and the exact census must not spend the same SDK deadline.
    size = 2 * 32749 + 8191
    framing = "Transfer-Encoding: chunked" if chunked else f"Content-Length: {size}"
    prefix = f"HTTP/1.1 200 Result\r\n{framing}\r\nConnection: close\r\n\r\n".encode()
    chunk_header = f"{size:x}\r\n".encode() if chunked else b""
    suffix = b"\r\n0\r\n\r\n" if chunked else b""

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(prefix + chunk_header + b"\x01" * size + suffix)
        await writer.drain()

    tracing_allocations = tracemalloc.is_tracing()
    try:
        async with Peer(handler) as peer:
            if environment == "sync":
                with HttpTransport(peer.origin, timeout=2) as owner:
                    owner._http_client()
                    if not tracing_allocations:
                        tracemalloc.start(1)
                    allocation_baseline = tracemalloc.take_snapshot()

                    def invoke() -> None:
                        with pytest.raises(ClientError) as caught:
                            Client(owner).probe.echo(ProbeEchoInput(wire_value="ok"))
                        assert caught.value.code == "internal"

                    await asyncio.to_thread(invoke)
            else:
                async with AsyncHttpTransport(peer.origin, timeout=2) as async_owner:
                    import anyio

                    anyio.get_cancelled_exc_class()
                    async_owner._http_client()
                    if not tracing_allocations:
                        tracemalloc.start(1)
                    allocation_baseline = tracemalloc.take_snapshot()
                    with pytest.raises(ClientError) as caught:
                        await AsyncClient(async_owner).probe.echo(
                            ProbeEchoInput(wire_value="ok")
                        )
                    assert caught.value.code == "internal"
        filters = [
            tracemalloc.Filter(True, f"*/{name}/*", all_frames=True)
            for name in ("chickinfry", "httpx", "httpcore", "h11", "anyio")
        ]
        allocations = (
            tracemalloc.take_snapshot()
            .filter_traces(filters)
            .compare_to(allocation_baseline.filter_traces(filters), "lineno")
        )
        (tmp_path / "allocation-crosscheck.json").write_text(
            json.dumps(
                [
                    {
                        "file": "/".join(Path(item.traceback[-1].filename).parts[-2:]),
                        "line": item.traceback[-1].lineno,
                        "bytes": item.size_diff,
                        "count": item.count_diff,
                    }
                    for item in allocations
                    if item.size_diff > 0
                ]
            )
        )
    finally:
        if not tracing_allocations and tracemalloc.is_tracing():
            tracemalloc.stop()


@pytest.mark.parametrize("registry", ["plain", "spans"])
async def test_reused_body_copy_identity_updates_the_current_census(
    registry: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = Transport.sample
    reused = 0

    def sampled(
        self: Transport,
        frame: FrameType,
        returned: object = None,
        ingress: bool = False,
    ) -> None:
        nonlocal reused
        if (
            frame.f_code.co_name == "_receive_response_body"
            and isinstance(returned, bytes)
            and len(returned) == 8247
        ):
            # Model the last copy reusing a freed first-chunk address.
            if registry == "plain":
                self.plain[id(returned)] = 65442
            else:
                self.spans[id(returned)] = (0, 65536)
            reused += 1
        original(self, frame, returned, ingress)

    monkeypatch.setattr(Transport, "sample", sampled)
    await test_live_redirect_byte_census(
        "sync", 73689, 200, True, monkeypatch, tmp_path
    )
    assert reused == 1, "The last body copy was not observed"


@pytest.mark.parametrize("environment", ["sync", "async"])
async def test_httpx_completed_store_census(
    environment: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    await test_live_redirect_byte_census(
        environment, 8191, 302, False, monkeypatch, tmp_path, prefetch=True
    )


@pytest.mark.parametrize("environment", ["sync", "async"])
async def test_census_avoids_whole_heap_work_in_sdk_requests(
    environment: str, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import gc

    heap_scans = 0
    original = Transport.sample
    before_ingress = 0

    def forbidden(*objects: object) -> list[object]:
        nonlocal heap_scans
        heap_scans += 1
        raise RuntimeError("Whole-heap inspection entered a request")

    def sampled(
        self: Transport,
        frame: FrameType,
        returned: object = None,
        ingress: bool = False,
    ) -> None:
        nonlocal before_ingress
        if self.wire.offset == 0 and frame.f_code.co_name != "data_received":
            before_ingress += 1
        original(self, frame, returned, ingress)

    monkeypatch.setattr(gc, "get_referrers", forbidden)
    monkeypatch.setattr(Transport, "sample", sampled)
    try:
        await test_live_redirect_byte_census(
            environment, 8191, 200, False, monkeypatch, tmp_path
        )
    finally:
        assert heap_scans == 0, "Whole-heap work entered a timed SDK request"
        assert before_ingress == 0, "Frame census ran before response ingress"


async def test_event_time_precedes_census_calculation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    previous = sys.gettrace()
    previous_thread = threading.gettrace()
    try:
        prepare()
        observation = _Observation(time.monotonic() + 10, call_id="c:clock")
        ledger = Events()
        measured = Transport(observation, ledger)
        measured.start = 0
        clock = [50.0]
        reader_returns: list[float] = []

        def delayed(
            frame: FrameType, returned: object = None, ingress: bool = False
        ) -> None:
            if frame.f_code is httpx.Response.aclose.__code__ and dis.opname[
                frame.f_code.co_code[frame.f_lasti]
            ].startswith("RETURN"):
                reader_returns.append(clock[0] * 1000)
            clock[0] += 2.5

        monkeypatch.setattr(measured, "sample", delayed)
        monkeypatch.setattr(time, "monotonic", lambda: clock[0])
        measured.publish("headers")
        measured.publish("cancel-requested")
        assert measured.events[0]["elapsedMs"] == 50000
        assert measured.events[1]["elapsedMs"] == 52500
        measured.defer = True
        measured.publish("headers")
        measured.publish("cancel-requested")
        measured.publish("completed")
        elapsed = [event["elapsedMs"] for event in measured.events]
        assert elapsed == sorted(elapsed)
        assert elapsed[2:] == [55000, 55000, 55000]

        stream = httpx.ByteStream(b"")
        network = socket.socket()
        network.close()
        response = httpx.Response(
            302, stream=stream, extensions={"network_stream": network}
        )
        measured.current_connection = measured.connection_key(network)
        measured.wire.offset = 1
        measured.stopped = measured.socket_closed = True
        observation.transport = measured.notify
        token = _observer.set(observation)
        try:
            sys.settrace(trace)
            await response.aclose()
        finally:
            _observer.reset(token)
        assert response.is_closed
        assert len(reader_returns) == 1
        assert [event["phase"] for event in measured.events[-2:]] == [
            "cancel-observed",
            "reader-closed",
        ]
        assert [event["elapsedMs"] for event in measured.events[-2:]] == (
            reader_returns * 2
        )
    finally:
        sys.settrace(previous)
        threading.settrace(previous_thread)


async def test_concurrent_publish_preserves_time_and_nonblocking_snapshot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = _Observation(time.monotonic() + 10, call_id="c:publish")
    ledger = Events()
    measured = Transport(observation, ledger)
    observation.transport = measured.notify
    ledger.calls[observation.call_id] = measured
    measured.start = 0
    census_entered = threading.Event()
    release_census = threading.Event()
    completion_attempted = threading.Event()
    publication_lock = threading.RLock()
    failures: list[BaseException] = []
    clock = [10.0]
    sample = measured.sample

    class ObservedLock:
        def __enter__(self) -> None:
            if threading.current_thread() is completion:
                completion_attempted.set()
            publication_lock.acquire()

        def __exit__(self, *args: object) -> None:
            publication_lock.release()

    def paused_census(
        frame: FrameType, returned: object = None, ingress: bool = False
    ) -> None:
        sample(frame, returned, ingress)
        if threading.current_thread() is producer:
            census_entered.set()
            assert release_census.wait(5), "The publisher was not released"

    def produce() -> None:
        try:
            observation.notify("read", b"x")
        except BaseException as error:
            failures.append(error)

    def complete() -> None:
        try:
            measured.publish("completed")
        except BaseException as error:
            failures.append(error)
        finally:
            completion_attempted.set()

    producer = threading.Thread(target=produce)
    completion = threading.Thread(target=complete)
    monkeypatch.setattr(measured, "publication_lock", ObservedLock(), raising=False)
    monkeypatch.setattr(measured, "sample", paused_census)
    monkeypatch.setattr(time, "monotonic", lambda: clock[0])
    producer.start()
    try:
        assert census_entered.wait(5), "The producer did not enter its census"
        clock[0] = 20.0
        completion.start()
        assert completion_attempted.wait(5), "Completion did not attempt publication"
        snapshot = ledger.snapshot(observation.call_id, 0)
        snapshot_events = snapshot["events"]
        assert isinstance(snapshot_events, list)
        assert snapshot["throughSequence"] == len(snapshot_events)
    finally:
        release_census.set()
        producer.join(5)
        if completion.ident is not None:
            completion.join(5)
    assert not producer.is_alive() and not completion.is_alive()
    assert not failures
    events = ledger.snapshot(observation.call_id, 0)["events"]
    assert isinstance(events, list)
    assert {event["phase"] for event in events} == {"read", "completed"}
    assert len(events) == 2
    assert [event["sequence"] for event in events] == [1, 2]
    elapsed = [event["elapsedMs"] for event in events]
    assert elapsed == sorted(elapsed), "Concurrent publication reversed event time"


@pytest.mark.parametrize("environment", ["sync", "async"])
@pytest.mark.parametrize("method", ["stream", "raw", "bytes", "text", "lines", "read"])
async def test_every_body_read_path_publishes_once(
    environment: str, method: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    from chickinfry._http_common import _Body
    from chickinfry._sync_network import _deadline

    payload = b"body-read\n"
    observation = _Observation(time.monotonic() + 10, call_id="c:body-read")
    measured = Transport(observation, Events())
    first_read = asyncio.Event()
    loop = asyncio.get_running_loop()
    publish = measured.publish

    def observed(phase: str, observed_at: float | None = None) -> None:
        publish(phase, observed_at)
        if phase == "read":
            loop.call_soon_threadsafe(first_read.set)

    monkeypatch.setattr(measured, "publish", observed)
    observation.transport = measured.notify
    token = _observer.set(observation)
    deadline_token = _deadline.set(observation.deadline)
    before, threads_before = sys.gettrace(), threading.gettrace()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(
            b"HTTP/1.1 302 Result\r\nLocation: /sink\r\nContent-Length: 10\r\n\r\n"
            + payload[:4]
        )
        await writer.drain()
        await asyncio.wait_for(first_read.wait(), 5)
        writer.write(payload[4:])
        await writer.drain()

    try:
        prepare()
        async with Peer(handler) as peer:

            def entered(response: httpx.Response) -> None:
                observation.notify("entered")
                observation.notify("headers", response)
                observation.notify("redirect", response)

            def sync_read() -> None:
                with HttpTransport(peer.origin) as owner:
                    with owner._http_client().stream("POST", peer.origin) as response:
                        entered(response)
                        if method == "read":
                            assert response.read() == payload
                            assert response.read() == payload
                        elif method == "stream":
                            assert isinstance(response.stream, httpx.SyncByteStream)
                            assert b"".join(response.stream) == payload
                        else:
                            list(getattr(response, "iter_" + method)())
                        assert measured.read == len(payload), "A real read was hidden"
                        _Body("identity", 302).feed(payload)

            if environment == "sync":
                await asyncio.to_thread(sync_read)
            else:
                async with AsyncHttpTransport(peer.origin) as owner:
                    async with owner._http_client().stream(
                        "POST", peer.origin
                    ) as response:
                        entered(response)
                        if method == "read":
                            assert await response.aread() == payload
                            assert await response.aread() == payload
                        else:
                            iterator = (
                                response.stream
                                if method == "stream"
                                else getattr(response, "aiter_" + method)()
                            )
                            assert hasattr(iterator, "__aiter__")
                            async for _ in iterator:
                                pass
                        assert measured.read == len(payload), "A real read was hidden"
                        _Body("identity", 302).feed(payload)
    finally:
        sys.settrace(before)
        threading.settrace(threads_before)
        _observer.reset(token)
        _deadline.reset(deadline_token)
    reads = [event for event in measured.events if event["phase"] == "read"]
    assert len(reads) == 2, "A real read was hidden or counted twice"
    assert [event["readBytes"] for event in reads] == [4, len(payload)]
    assert measured.read == len(payload)
    assert reads[0]["sequence"] > next(
        event["sequence"]
        for event in measured.events
        if event["phase"] == "cancel-requested"
    )
