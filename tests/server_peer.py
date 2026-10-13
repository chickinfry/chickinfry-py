"""A test-only TCP proxy that withholds only real PostgreSQL responses and the cancellation EOF."""

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .server_fixture import PostgreSQL


@dataclass
class StalledPeer:
    marker: bytes
    received: asyncio.Event = field(default_factory=asyncio.Event)
    closed: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)
    paused: bool = False
    port: int = 0

    def dsn(self, postgres: PostgreSQL) -> str:
        url = urlsplit(postgres._dsn)
        return url._replace(
            netloc=f"{url.username}:{url.password}@127.0.0.1:{self.port}"
        ).geturl()


@asynccontextmanager
async def stalled_peer(
    postgres: PostgreSQL, marker: bytes
) -> AsyncIterator[StalledPeer]:
    peer = StalledPeer(marker)
    upstream = urlsplit(postgres._dsn)
    assert upstream.hostname is not None and upstream.port is not None
    tasks: list[asyncio.Task[None]] = []
    writers: list[asyncio.StreamWriter] = []

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        writers.append(writer)
        first = await reader.read(8192)
        is_cancel = first[4:8] == b"\x04\xd2\x16\x2e"
        remote_reader, remote_writer = await asyncio.open_connection(
            upstream.hostname, upstream.port
        )
        writers.append(remote_writer)
        remote_writer.write(first)
        await remote_writer.drain()

        async def incoming() -> None:
            tail = b""
            try:
                while data := await reader.read(8192):
                    tail = (tail + data)[-8192:]
                    matched = peer.marker in tail
                    if matched:
                        peer.paused = True
                    remote_writer.write(data)
                    await remote_writer.drain()
                    if matched:
                        peer.received.set()
            finally:
                if not is_cancel:
                    peer.closed.set()

        async def outgoing() -> None:
            while True:
                data = await remote_reader.read(8192)
                if peer.paused:
                    await peer.release.wait()
                if not data:
                    return
                writer.write(data)
                await writer.drain()

        directions = [asyncio.create_task(incoming()), asyncio.create_task(outgoing())]
        try:
            await asyncio.gather(*directions)
        finally:
            for direction in directions:
                direction.cancel()
            await asyncio.gather(*directions, return_exceptions=True)

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        tasks.append(asyncio.create_task(handle(reader, writer)))

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    peer.port = server.sockets[0].getsockname()[1]
    try:
        yield peer
    finally:
        server.close()
        peer.release.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for writer in writers:
            writer.close()
            try:
                async with asyncio.timeout(1):
                    await writer.wait_closed()
            except (TimeoutError, ConnectionError):
                pass
        await server.wait_closed()
