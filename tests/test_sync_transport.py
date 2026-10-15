import asyncio
import gzip
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from typing_extensions import Buffer

from chickinfry import (
    HTTP,
    ClientError,
    OperationError,
    SessionStore,
    _sync_http,
    _sync_network,
)
from chickinfry._sync_network import _Transport
from chickinfry.wire import read_record, read_string

from .deadline import Clock
from .peer import Peer, Received, respond
from .test_session import credentials


async def test_sync_copies_security_and_owner_lifetime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(
            writer, request.body, headers={"Set-Cookie": "private=value; Path=/"}
        )

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    tokens = [secrets.token_urlsafe(32) for _ in range(2)]
    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, credentials())
            copies = [owner.with_bearer(token) for token in tokens] + [
                owner.with_session(store)
            ]
            for client in [owner, *copies, owner]:
                result = read_record(
                    await asyncio.to_thread(
                        client.invoke,
                        "thing.run",
                        {"time": "2026-10-13T12:34:56.123456Z"},
                    )
                )
                assert read_string(result["time"]) == "2026-10-13T12:34:56.123456Z"
            assert all(
                request.method == "POST"
                and request.path == "/thing.run"
                and "cookie" not in request.headers
                for request in peer.received
            )
            assert (
                "authorization" not in peer.received[0].headers
                and "authorization" not in peer.received[-1].headers
            )
            assert all(
                bool(request.headers["authorization"] == "Bearer " + token)
                for request, token in zip(peer.received[1:3], tokens, strict=True)
            )
            assert all(
                not hasattr(copy, "close") and not hasattr(copy, "with_bearer")
                for copy in copies
            )
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "invalid_token"
            ):
                owner.with_bearer(tokens[0] + "\n")
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "origin_mismatch"
            ):
                owner.with_session(SessionStore("https://example.com", credentials()))
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "invalid_origin"
            ):
                HTTP("http://localhost")
        owner.close()
        with pytest.raises(
            ClientError, check=lambda error: error.reason == "transport_closed"
        ):
            copies[0].invoke("thing.run", {})


@pytest.mark.parametrize(
    ("status", "body", "expected"),
    [
        (429, b'{"error":"rate_limited"}', "rate_limited"),
        (503, b"server detail", "invalid_response"),
        (401, b'{"error":"invalid_token\\n"}', "invalid_response"),
        (307, b"secret detail", "redirect_not_allowed"),
        (200, b"bad JSON detail", "invalid_response"),
    ],
)
async def test_sync_errors_no_redirect_or_replay(
    status: int, body: bytes, expected: str
) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(
            writer,
            body,
            status=status,
            headers={"Location": peer.origin + "/thing.run"},
        )

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            with pytest.raises(ClientError) as caught:
                await asyncio.to_thread(owner.invoke, "thing.run", {})
            assert caught.value.status == status
            actual = (
                caught.value.code
                if isinstance(caught.value, OperationError)
                else caught.value.reason
            )
            assert actual == expected
            assert "detail" not in str(caught.value) + repr(caught.value)
            assert len(peer.received) == 1


@pytest.mark.parametrize(
    ("compressed", "extra", "status"),
    [(False, 0, 200), (False, 1, 200), (True, 0, 200), (True, 1, 500)],
)
async def test_sync_stream_limit_and_other_calls_survive(
    compressed: bool, extra: int, status: int
) -> None:
    payload = b'{"text":"' + b"a" * (1024 * 1024 - 11 + extra) + b'"}'
    disconnected = asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/thing.small":
            await respond(writer)
        elif compressed:
            await respond(
                writer,
                gzip.compress(payload),
                headers={"Content-Encoding": "gzip"},
                status=status,
                chunked=True,
            )
        else:
            writer.write(
                f"HTTP/1.1 {status} OK\r\nTransfer-Encoding: chunked\r\n\r\n".encode()
            )
            writer.write(f"{len(payload):x}\r\n".encode() + payload + b"\r\n")
            if not extra:
                writer.write(b"0\r\n\r\n")
            await writer.drain()
            if extra:
                try:
                    await request.reader.read()
                except ConnectionError:
                    pass
                disconnected.set()

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            if extra:
                with pytest.raises(
                    ClientError,
                    check=lambda error: error.reason == "response_too_large",
                ):
                    await asyncio.to_thread(owner.invoke, "thing.large", {})
                if not compressed:
                    await asyncio.wait_for(disconnected.wait(), 1)
            else:
                result = read_record(
                    await asyncio.to_thread(owner.invoke, "thing.large", {})
                )
                assert len(read_string(result["text"])) == 1024 * 1024 - 11
            assert await asyncio.to_thread(owner.invoke, "thing.small", {}) == {}
            assert len(peer.received) == 2


async def test_sync_utf8_request_boundary_before_network() -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    limit = 4 * 1024 * 1024
    body = (
        b'{"text":"'
        + "한".encode() * ((limit - 11) // 3)
        + b"a" * ((limit - 11) % 3)
        + b'"}'
    )
    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            assert await asyncio.to_thread(owner.invoke, "thing.run", body) == {}
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "request_too_large"
            ):
                owner.invoke("thing.run", body + b" ")
            assert len(peer.received) == 1 and len(peer.received[0].body) == limit


async def test_sync_real_clock_timeout_sanity() -> None:
    disconnected = asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        try:
            await request.reader.read()
        except ConnectionError:
            pass
        disconnected.set()

    async with Peer(handler) as peer:
        with HTTP(peer.origin, timeout=1.0) as owner:
            begin = time.monotonic()
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "timeout"
            ):
                await asyncio.wait_for(
                    asyncio.to_thread(owner.invoke, "thing.run", {}), 20
                )
            # Coarse real-clock sanity only; virtual-clock tests prove precise budgets.
            assert 0.5 <= time.monotonic() - begin < 20
            await asyncio.wait_for(disconnected.wait(), 20)
            assert len(peer.received) == 1


@pytest.mark.parametrize(
    "kind", ["headers", "informational", "chunks", "chunk_metadata"]
)
@pytest.mark.parametrize("tier", ["request", "whole"])
def test_sync_repeated_reads_keep_one_deadline(
    kind: str,
    tier: str,
    monkeypatch: pytest.MonkeyPatch,
    sync_clock: Clock,
) -> None:
    timeouts: list[float | None] = []
    prefix = {
        "headers": b"HTTP/1.1 200 OK\r\nX-Slow: ",
        "informational": b"HTTP/1.1 100 Continue\r\n\r\n",
        "chunks": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
        "chunk_metadata": b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;ext=",
    }
    fragment = {
        "headers": b"x",
        "informational": b"HTTP/1.1 100 Continue\r\n\r\n",
        "chunks": b"1\r\na\r\n",
        "chunk_metadata": b"x",
    }

    class ObservedSocket(socket.socket):
        def send(self, data: Buffer, flags: int = 0) -> int:
            return memoryview(data).nbytes

        def recv(self, bufsize: int, flags: int = 0) -> bytes:
            timeouts.append(self.gettimeout())
            assert len(timeouts) <= 4, "Read restarted the deadline"
            sync_clock.advance(0.05)
            return prefix[kind] if len(timeouts) == 1 else fragment[kind]

    with (
        ObservedSocket() as sock,
        HTTP("http://127.0.0.1", timeout=0.20 if tier == "request" else 10.0) as owner,
    ):
        monkeypatch.setattr(
            _sync_network._Backend,
            "connect_tcp",
            lambda backend, *args, **kwargs: _sync_network._Stream(sock, backend),
        )
        with pytest.raises(ClientError, check=lambda error: error.reason == "timeout"):
            if tier == "request":
                owner.invoke("thing.run", {})
            else:
                owner._attempt("thing.run", b"{}", None, 0.20)
        assert timeouts == pytest.approx([0.20, 0.15, 0.10, 0.05])
        assert sync_clock.now == pytest.approx(0.20)


def test_sync_tls_handshake_deadline(
    monkeypatch: pytest.MonkeyPatch, sync_clock: Clock
) -> None:
    wrapped: list[float | None] = []
    handshakes: list[float | None] = []

    class ObservedSocket(socket.socket):
        def do_handshake(self) -> None:
            remaining = self.gettimeout()
            handshakes.append(remaining)
            assert remaining is not None
            sync_clock.advance(remaining)
            # A late successful handshake must still be rejected at the deadline.

    def connect(
        backend: _sync_network._Backend, *args: object, **kwargs: object
    ) -> _sync_network._Stream:
        sync_clock.advance(0.05)
        return _sync_network._Stream(sock, backend)

    def wrap(
        context: ssl.SSLContext, raw: socket.socket, **kwargs: object
    ) -> socket.socket:
        wrapped.append(raw.gettimeout())
        sync_clock.advance(0.05)
        return raw

    with ObservedSocket() as sock, HTTP("https://127.0.0.1", timeout=0.20) as owner:
        monkeypatch.setattr(_sync_network._Backend, "connect_tcp", connect)
        monkeypatch.setattr(ssl.SSLContext, "wrap_socket", wrap)
        with pytest.raises(ClientError, check=lambda error: error.reason == "timeout"):
            owner.invoke("thing.run", {})
        assert wrapped == pytest.approx([0.15])
        assert handshakes == pytest.approx([0.10])
        assert sync_clock.now == pytest.approx(0.20)
        assert sock.fileno() == -1


@pytest.mark.parametrize("admitted", [False, True])
def test_sync_pool_admission_deadline(
    admitted: bool, monkeypatch: pytest.MonkeyPatch, sync_clock: Clock
) -> None:
    timeouts: list[float | None] = []
    releases: list[bool] = []

    class ObservedSlots(threading.BoundedSemaphore):
        def acquire(self, blocking: bool = True, timeout: float | None = None) -> bool:
            timeouts.append(timeout)
            assert timeout is not None
            sync_clock.advance(timeout)
            return admitted

        def release(self, n: int = 1) -> None:
            releases.append(True)

    with HTTP("http://127.0.0.1", timeout=0.20) as owner:
        assert owner._client is not None
        owner._client.close()
        transport = _Transport(max_connections=1)
        transport._slots = ObservedSlots(1)
        owner._client = httpx.Client(transport=transport, trust_env=False, timeout=0.20)
        original = owner._http_client

        def client(deadline: float | None = None) -> httpx.Client:
            sync_clock.advance(0.05)
            return original(deadline)

        def unexpected_connect(*args: object, **kwargs: object) -> None:
            pytest.fail("Expired pool admission started network I/O")

        monkeypatch.setattr(owner, "_http_client", client)
        monkeypatch.setattr(transport._backend, "connect_tcp", unexpected_connect)
        with pytest.raises(ClientError, check=lambda error: error.reason == "timeout"):
            owner.invoke("thing.run", {})
        assert timeouts == pytest.approx([0.15])
        assert sync_clock.now == pytest.approx(0.20)
        assert releases == ([True] if admitted else [])


def test_sync_partial_writes_keep_one_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = 0.0
    timeouts: list[float | None] = []
    partial: list[bool] = []

    class ObservedSocket(socket.socket):
        def send(self, data: Buffer, flags: int = 0) -> int:
            nonlocal now
            timeouts.append(self.gettimeout())
            size = memoryview(data).nbytes
            count = min(8, size) if partial else size
            partial.append(count < size)
            now += 0.05
            return count

    with ObservedSocket() as sock:
        with HTTP("http://127.0.0.1", timeout=0.20) as owner:
            # Only transport clocks advance; runner scheduling cannot consume the budget.
            clock = SimpleNamespace(monotonic=lambda: now)
            monkeypatch.setattr(_sync_http, "time", clock)
            monkeypatch.setattr(_sync_network, "time", clock)
            monkeypatch.setattr(
                _sync_network._Backend,
                "connect_tcp",
                lambda backend, *args, **kwargs: _sync_network._Stream(sock, backend),
            )
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "timeout"
            ):
                owner.invoke("thing.run", {"text": "a" * 32})
            assert timeouts == pytest.approx([0.20, 0.15, 0.10, 0.05])
            assert partial == [False, True, True, True]
            assert now == pytest.approx(0.20)


async def test_sync_concurrent_init_close_interrupts_io_and_rejects_copies() -> None:
    started = asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        started.set()
        await request.reader.read()

    async with Peer(handler) as peer:
        owner = HTTP(peer.origin)

        def initialize() -> list[int]:
            with ThreadPoolExecutor(max_workers=8) as executor:
                return list(executor.map(lambda _: id(owner._http_client()), range(8)))

        clients = await asyncio.to_thread(initialize)
        assert len(set(clients)) == 1
        copy = owner.with_bearer(secrets.token_urlsafe(32))
        request = asyncio.create_task(asyncio.to_thread(copy.invoke, "thing.run", {}))
        await asyncio.wait_for(started.wait(), 1)
        await asyncio.to_thread(owner.close)
        with pytest.raises(ClientError):
            await asyncio.wait_for(request, 1)
        owner.close()
        with pytest.raises(
            ClientError, check=lambda error: error.reason == "transport_closed"
        ):
            copy.invoke("thing.run", {})
        assert len(peer.received) == 1


@pytest.mark.parametrize("environment", ["emscripten", "wasi", "pyodide"])
def test_sync_environment_rejects_before_http_libraries(environment: str) -> None:
    script = """
import sys, types
from chickinfry import HTTP, ClientError
assert 'httpx' not in sys.modules and 'httpcore' not in sys.modules
if sys.argv[1] == 'pyodide':
    sys.modules['pyodide'] = types.ModuleType('pyodide')
else:
    sys.platform = sys.argv[1]
try:
    HTTP('http://127.0.0.1')
except ClientError as error:
    assert error.reason == 'unsupported_environment'
else:
    raise AssertionError
assert 'httpx' not in sys.modules and 'httpcore' not in sys.modules
"""
    assert (
        subprocess.run(
            [sys.executable, "-I", "-c", script, environment], capture_output=True
        ).returncode
        == 0
    )


def test_sync_each_failed_address_uses_remaining_budget(
    monkeypatch: pytest.MonkeyPatch, sync_clock: Clock
) -> None:
    timeouts: list[float | None] = []
    sockets: list[socket.socket] = []
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 0, "", ("127.0.0.1", 1))] * 8

    class ObservedSocket(socket.socket):
        def connect(self, address: object) -> None:
            sockets.append(self)
            timeouts.append(self.gettimeout())
            assert len(timeouts) <= 4, "Address retry restarted the deadline"
            sync_clock.advance(0.05)
            raise ConnectionRefusedError

    with HTTP("http://127.0.0.1", timeout=0.20) as owner:
        monkeypatch.setattr(
            _sync_network,
            "socket",
            SimpleNamespace(
                **(
                    vars(socket)
                    | {
                        "socket": ObservedSocket,
                        "getaddrinfo": lambda *args, **kwargs: addresses,
                    }
                )
            ),
        )
        with pytest.raises(ClientError, check=lambda error: error.reason == "timeout"):
            owner.invoke("thing.run", {})
        assert timeouts == pytest.approx([0.20, 0.15, 0.10, 0.05])
        assert sync_clock.now == pytest.approx(0.20)
        assert len(sockets) == 4 and all(sock.fileno() == -1 for sock in sockets)


async def test_sync_malformed_network_error_hides_raw_exception() -> None:
    token = secrets.token_urlsafe(32)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 " + token.encode() + b"\r\n\r\n")
        await writer.drain()

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "network_error"
            ) as caught:
                await asyncio.to_thread(
                    owner.with_bearer(token).invoke, "thing.run", {"private": token}
                )
            assert caught.value.__context__ is None and caught.value.__cause__ is None
            assert bool(token not in repr(caught.value) + str(caught.value))
            assert len(peer.received) == 1


async def test_sync_tls_verification_rejects_untrusted_certificate(
    tmp_path: Path,
) -> None:
    certificate, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    generated = subprocess.run(
        [
            "/usr/bin/openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=127.0.0.1",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        capture_output=True,
    )
    assert generated.returncode == 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    async with Peer(handler, ssl_context=context) as peer:
        with HTTP(peer.origin.replace("http://", "https://", 1)) as owner:
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "network_error"
            ):
                await asyncio.to_thread(owner.invoke, "thing.run", {})
            assert not peer.received


async def test_sync_reused_connection_gets_each_requests_new_deadline() -> None:
    accepts = 0

    async def raw(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nonlocal accepts
        accepts += 1
        for _ in range(2):
            head = await reader.readuntil(b"\r\n\r\n")
            assert head.startswith(b"POST /thing.run HTTP/1.1\r\n")
            length = next(
                int(line.partition(b":")[2])
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            assert await reader.readexactly(length) == b"{}"
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\n{}"
            )
            await writer.drain()

    async def unused(request: Received, writer: asyncio.StreamWriter) -> None:
        raise AssertionError

    async with Peer(unused, raw_handler=raw) as peer:
        with HTTP(peer.origin, timeout=0.20) as owner:
            assert await asyncio.to_thread(owner.invoke, "thing.run", {}) == {}
            await asyncio.sleep(0.25)
            assert await asyncio.to_thread(owner.invoke, "thing.run", {}) == {}
            assert accepts == 1
