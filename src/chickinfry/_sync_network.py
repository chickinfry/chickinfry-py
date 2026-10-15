import select
import socket
import ssl
import threading
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from typing import cast

import httpcore
import httpx

from ._conformance import _observer
from .errors import ClientError

_deadline: ContextVar[float] = ContextVar("chickinfry_sync_deadline")
SocketOption = (
    tuple[int, int, int]
    | tuple[int, int, bytes | bytearray]
    | tuple[int, int, None, int]
)


def _remaining(phase_timeout: float | None = None) -> float:
    remaining = _deadline.get() - time.monotonic()
    if remaining <= 0:
        raise TimeoutError
    return remaining if phase_timeout is None else min(remaining, phase_timeout)


class _Stream(httpcore.NetworkStream):
    def __init__(self, sock: socket.socket, backend: "_Backend") -> None:
        self._socket = sock
        self._backend = backend
        self._lock = threading.Lock()
        self._closed = False
        self._active = 0

    @contextmanager
    def _io(self) -> Iterator[socket.socket]:
        with self._lock:
            if self._closed:
                raise OSError
            self._active += 1
            sock = self._socket
        try:
            yield sock
        finally:
            with self._lock:
                self._active -= 1
                close = self._closed and self._active == 0
                sock = self._socket
            if close:
                sock.close()
                self._backend._discard(self)
                observation = _observer.get()
                if observation is not None:
                    observation.notify("socket-closed", self)

    def read(self, max_bytes: int, timeout: float | None = None) -> bytes:
        with self._io() as sock:
            sock.settimeout(_remaining(timeout))
            data = sock.recv(max_bytes)
            observation = _observer.get()
            if observation is not None:
                observation.notify("wire", (self, data))
            return data

    def write(self, buffer: bytes, timeout: float | None = None) -> None:
        with self._io() as sock:
            pending = memoryview(buffer)
            while pending:
                sock.settimeout(_remaining(timeout))
                count = sock.send(pending)
                if count == 0:
                    raise OSError
                pending = pending[count:]

    def start_tls(
        self,
        ssl_context: ssl.SSLContext,
        server_hostname: str | None = None,
        timeout: float | None = None,
    ) -> httpcore.NetworkStream:
        try:
            with self._io() as sock:
                sock.settimeout(_remaining(timeout))
                secured = ssl_context.wrap_socket(
                    sock,
                    server_hostname=server_hostname,
                    do_handshake_on_connect=False,
                )
                with self._lock:
                    self._socket = secured
                    if self._closed:
                        raise OSError
                secured.settimeout(_remaining(timeout))
                secured.do_handshake()
                _remaining(timeout)
            return self
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            sock = self._socket
            close = self._active == 0
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        # Closing the fd before in-flight recv/send calls exit may never wake the macOS waits.
        if close:
            sock.close()
            self._backend._discard(self)
            observation = _observer.get()
            if observation is not None:
                observation.notify("socket-closed", self)

    def get_extra_info(self, info: str) -> object:
        if info == "ssl_object":
            return self._socket if isinstance(self._socket, ssl.SSLSocket) else None
        if info == "socket":
            return self._socket
        if info == "is_readable":
            return bool(select.select([self._socket], [], [], 0)[0])
        if info == "client_addr":
            return self._socket.getsockname()
        if info == "server_addr":
            return self._socket.getpeername()
        return None


class _Backend(httpcore.NetworkBackend):
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._streams: set[_Stream] = set()
        self._closed = False

    def _discard(self, stream: _Stream) -> None:
        with self._lock:
            self._streams.discard(stream)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            streams = list(self._streams)
        for stream in streams:
            stream.close()

    def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SocketOption] | None = None,
    ) -> httpcore.NetworkStream:
        _remaining(timeout)
        # The OS resolver cannot be interrupted, but the budget is rechecked before new I/O.
        addresses = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        for family, kind, protocol, _, address in addresses:
            _remaining(timeout)
            sock = socket.socket(family, kind, protocol)
            try:
                if local_address is not None:
                    sock.bind((local_address, 0))
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                for option in socket_options or ():
                    if len(option) == 3:
                        sock.setsockopt(*option)
                    else:
                        sock.setsockopt(*option)
                sock.settimeout(_remaining(timeout))
                sock.connect(address)
                _remaining(timeout)
                stream = _Stream(sock, self)
                with self._lock:
                    if self._closed:
                        raise OSError
                    self._streams.add(stream)
                return stream
            except TimeoutError:
                sock.close()
                raise
            except OSError:
                sock.close()
            except BaseException:
                sock.close()
                raise
        raise OSError


class _ResponseStream(httpx.SyncByteStream):
    def __init__(
        self, response: httpcore.Response, slots: threading.BoundedSemaphore
    ) -> None:
        self._response = response
        self._slots = slots
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        for chunk in self._response.iter_stream():
            _remaining()
            yield chunk

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._response.close()
        finally:
            self._slots.release()
        observation = _observer.get()
        if observation is not None:
            observation.notify("reader-closed", self)


class _Transport(httpx.BaseTransport):
    def __init__(self, *, max_connections: int = 100) -> None:
        self._slots = threading.BoundedSemaphore(max_connections)
        self._backend = _Backend()
        # The admission lock owns the whole pool budget, so httpcore never re-waits internally.
        self._pool = httpcore.ConnectionPool(
            ssl_context=httpx.create_ssl_context(verify=True, trust_env=False),
            network_backend=self._backend,
            max_connections=None,
            max_keepalive_connections=20,
            retries=0,
            http1=True,
            http2=False,
        )
        self._closed = False
        self._lock = threading.Lock()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        if not self._slots.acquire(timeout=_remaining()):
            raise TimeoutError
        response: httpcore.Response | None = None
        transferred = False
        try:
            _remaining()
            with self._lock:
                if self._closed:
                    raise ClientError("transport_closed")
            core_request = httpcore.Request(
                method=request.method,
                url=httpcore.URL(
                    scheme=request.url.raw_scheme,
                    host=request.url.raw_host,
                    port=request.url.port,
                    target=request.url.raw_path,
                ),
                headers=request.headers.raw,
                content=cast(Iterable[bytes], request.stream),
                extensions=request.extensions,
            )
            response = self._pool.handle_request(core_request)
            _remaining()
            result = httpx.Response(
                response.status,
                headers=response.headers,
                stream=_ResponseStream(response, self._slots),
                extensions=response.extensions,
            )
            transferred = True
            return result
        finally:
            if not transferred:
                try:
                    if response is not None:
                        response.close()
                finally:
                    self._slots.release()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        self._backend.close()
        self._pool.close()
