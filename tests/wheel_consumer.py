"""Run with an isolated interpreter after installing the built wheel."""

import asyncio
import json
from importlib.resources import files

import chickinfry
from chickinfry import AsyncHttpTransport, AsyncTransport, HttpTransport, Transport


async def main() -> None:
    assert chickinfry.__file__ is not None
    assert "site-packages" in chickinfry.__file__
    assert files("chickinfry").joinpath("py.typed").is_file()
    received: list[bytes] = []

    async def handle(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            assert head.startswith(b"POST /account.get_status HTTP/1.1\r\n")
            length = next(
                int(line.partition(b":")[2])
                for line in head.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            received.append(await reader.readexactly(length))
            body = b'{"status":"active"}'
            writer.write(
                b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n"
                + f"Content-Length: {len(body)}\r\n\r\n".encode()
                + body
            )
            await writer.drain()
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        origin = f"http://127.0.0.1:{port}"

        def sync_call() -> object:
            with HttpTransport(origin) as transport:
                client: Transport = transport
                return client.invoke("account.get_status", {})

        synchronous = await asyncio.to_thread(sync_call)
        async with AsyncHttpTransport(origin) as transport:
            client: AsyncTransport = transport
            asynchronous = await client.invoke("account.get_status", {})
        assert synchronous == asynchronous == {"status": "active"}
        assert received == [b"{}", b"{}"]
    print(
        json.dumps(
            {
                "installedImport": "pass",
                "pyTyped": "pass",
                "syncCall": "pass",
                "asyncCall": "pass",
            }
        )
    )


if __name__ == "__main__":
    asyncio.run(main())
