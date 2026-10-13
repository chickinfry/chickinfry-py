import asyncio
import json
import ssl
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Self


@dataclass(repr=False)
class Received:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes = field(repr=False)
    reader: asyncio.StreamReader = field(repr=False)


Handler = Callable[[Received, asyncio.StreamWriter], Awaitable[None]]
RawHandler = Callable[[asyncio.StreamReader, asyncio.StreamWriter], Awaitable[None]]


async def respond(
    writer: asyncio.StreamWriter,
    body: bytes = b"{}",
    *,
    status: int = 200,
    headers: dict[str, str] | None = None,
    chunked: bool = False,
) -> None:
    fields = {"Content-Type": "application/json", "Connection": "close"}
    fields.update(headers or {})
    fields["Transfer-Encoding" if chunked else "Content-Length"] = (
        "chunked" if chunked else str(len(body))
    )
    writer.write(f"HTTP/1.1 {status} Result\r\n".encode())
    writer.write(
        "".join(f"{key}: {value}\r\n" for key, value in fields.items()).encode()
    )
    writer.write(b"\r\n")
    if chunked:
        for offset in range(0, len(body), 8192):
            chunk = body[offset : offset + 8192]
            writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
            await writer.drain()
        writer.write(b"0\r\n\r\n")
    else:
        writer.write(body)
    await writer.drain()


def json_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class Peer:
    def __init__(
        self,
        handler: Handler,
        *,
        ssl_context: ssl.SSLContext | None = None,
        raw_handler: RawHandler | None = None,
    ) -> None:
        self.handler = handler
        self._ssl_context = ssl_context
        self._raw_handler = raw_handler
        self.received: list[Received] = []
        self.origin = ""
        self._tasks: set[asyncio.Task[None]] = set()
        self._server: asyncio.Server | None = None
        self.errors: list[Exception] = []

    async def __aenter__(self) -> Self:
        self._server = await asyncio.start_server(
            self._start, "127.0.0.1", 0, ssl=self._ssl_context
        )
        port = self._server.sockets[0].getsockname()[1]
        self.origin = f"http://127.0.0.1:{port}"
        return self

    def _start(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        task = asyncio.create_task(self._serve(reader, writer))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _serve(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            if self._raw_handler is not None:
                await self._raw_handler(reader, writer)
                return
            head = (await reader.readuntil(b"\r\n\r\n")).decode("ascii")
            first, *lines = head.split("\r\n")
            method, path, _ = first.split(" ")
            headers = {}
            for line in lines:
                if line:
                    key, value = line.split(":", 1)
                    headers[key.lower()] = value.strip()
            body = await reader.readexactly(int(headers.get("content-length", "0")))
            received = Received(method, path, headers, body, reader)
            self.received.append(received)
            await self.handler(received, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        except Exception as failure:
            self.errors.append(failure)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def __aexit__(self, *args: object) -> None:
        assert self._server is not None
        self._server.close()
        await self._server.wait_closed()
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        assert not self.errors, "fixture handler failed"
