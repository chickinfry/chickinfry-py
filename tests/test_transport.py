import asyncio
import datetime
import gzip
import secrets
import ssl
import subprocess
import sys
import traceback
import zlib
from collections.abc import Mapping
from pathlib import Path
from urllib.parse import SplitResult

import pytest

from chickinfry import (
    AsyncHttpTransport,
    ClientError,
    HttpTransport,
    MemoryStore,
    OperationError,
    SessionCredentials,
)
from chickinfry.wire import read_list, read_record, read_string

from .peer import Peer, Received, json_bytes, respond


@pytest.mark.parametrize(
    "origin",
    [
        "http://localhost",
        "http://example.com",
        "http://127.1",
        "http://2130706433",
        "http://127.0.0.256",
        "http://0127.0.0.1",
        "http://[::2]",
        "http://[::ffff:127.0.0.1]",
        "http://[0:0:0:0:0:ffff:7f00:1]",
        "http://[::127.0.0.1]",
        "http://[::7f00:1]",
        "http://[64:ff9b::127.0.0.1]",
        "http://[64:ff9b::7f00:1]",
        "http://[2002:7f00:1::]",
        "http://[::192.0.2.1]",
        "http://[::c000:201]",
        "https://@example.com",
        "https://user@example.com",
        "https://example.com/api",
        "https://example.com//",
        "https://example.com?",
        "https://example.com#",
        "https://example.com:bad",
        "https://example.com:65536",
        "https://example.com:",
        "https://example.com:0",
        " https://example.com",
        "https://example.com\n",
        "https://exa\tmple.com",
        "https://example.com\\evil",
        "http://[::1%25lo0]",
        "ftp://127.0.0.1",
    ],
)
@pytest.mark.parametrize("transport", [HttpTransport, AsyncHttpTransport])
def test_origin_rejected(
    origin: str, transport: type[HttpTransport] | type[AsyncHttpTransport]
) -> None:
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        transport(origin)


@pytest.mark.parametrize(
    "origin",
    [
        "https://EXAMPLE.com:443/",
        "http://127.0.0.2/",
        "http://[0:0:0:0:0:0:0:1]:80/",
        "http://[::1]",
        "http://[::0.0.0.1]",
        "https://[::ffff:127.0.0.1]",
    ],
)
@pytest.mark.parametrize("transport", [HttpTransport, AsyncHttpTransport])
def test_origin_accepted(
    origin: str, transport: type[HttpTransport] | type[AsyncHttpTransport]
) -> None:
    transport(origin)


@pytest.mark.parametrize("authority", ["[::1]suffix", "prefix[::1]"])
@pytest.mark.parametrize("transport", [HttpTransport, AsyncHttpTransport])
def test_origin_rejects_bracket_suffix_and_prefix_with_legacy_parser(
    authority: str,
    transport: type[HttpTransport] | type[AsyncHttpTransport],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chickinfry import _origin

    # Early Python 3.11 urlsplit accepted these authorities before hostname extraction.
    parsed = SplitResult("http", authority, "", "", "")
    monkeypatch.setattr(_origin, "urlsplit", lambda origin: parsed)
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        transport("http://" + authority)


@pytest.mark.parametrize("timeout", [0.0, -1.0, float("inf"), float("nan"), True])
def test_timeout_validation(timeout: float) -> None:
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        AsyncHttpTransport("https://example.com", timeout=timeout)


async def test_copy_isolation_cookies_proxy_and_origin_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer, headers={"Set-Cookie": "session=private; Path=/"})

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")
    tokens = [secrets.token_urlsafe(32) for _ in range(4)]
    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as owner:
        credentials = SessionCredentials(
            access_token=tokens[2],
            refresh_token=tokens[3],
            expires_at="later",
            refresh_expires_at="later",
            user_id="u",
            session_id="s",
        )
        store = MemoryStore(peer.origin + "/", credentials)
        copies = [
            owner.with_bearer(tokens[0]),
            owner.with_bearer(tokens[1]),
            owner.with_session(store),
        ]
        await owner.invoke("thing.run", {})
        for copy in copies:
            assert not hasattr(copy, "aclose") and not hasattr(copy, "with_bearer")
            await copy.invoke("thing.run", {})
        await owner.invoke("thing.run", {})
        assert all(
            item.method == "POST" and item.path == "/thing.run"
            for item in peer.received
        )
        assert all(
            item.headers["content-type"] == "application/json" for item in peer.received
        )
        assert all("cookie" not in item.headers for item in peer.received)
        assert "authorization" not in peer.received[0].headers
        assert "authorization" not in peer.received[-1].headers
        for item, token in zip(peer.received[1:4], tokens[:3], strict=True):
            assert bool(item.headers["authorization"] == "Bearer " + token)
        with pytest.raises(
            ClientError, check=lambda error: error.code == "failed_precondition"
        ):
            owner.with_session(MemoryStore("https://example.com", credentials))
        for token in ["", tokens[0] + "\n", "bad"]:
            with pytest.raises(
                ClientError, check=lambda error: error.code == "invalid_argument"
            ):
                owner.with_bearer(token)
    with pytest.raises(
        ClientError, check=lambda error: error.code == "failed_precondition"
    ):
        await copies[0].invoke("thing.run", {})


async def test_input_rejected_before_send_and_values_preserved() -> None:
    async def echo(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer, request.body)

    async with Peer(echo) as peer, AsyncHttpTransport(peer.origin) as transport:
        for operation in ["thing.run\n", "Thing.run", "thing/run", "thing..run"]:
            with pytest.raises(
                ClientError, check=lambda error: error.code == "invalid_argument"
            ):
                await transport.invoke(operation, {})
        bad: list[bytes | Mapping[str, object]] = [
            b"null",
            b"[]",
            b"{",
            b'{"a":NaN}',
            {"time": datetime.date.today()},
            {"time": datetime.datetime.now()},
            {"a": float("nan")},
            {"a": "\ud800"},
        ]
        for payload in bad:
            with pytest.raises(
                ClientError, check=lambda error: error.code == "invalid_argument"
            ):
                await transport.invoke("thing.run", payload)
        assert len(peer.received) == 0
        timestamp = "2026-10-13T12:34:56.123456Z"
        result = read_record(
            await transport.invoke("thing.run", {"items": [timestamp, "한국어"]})
        )
        items = read_list(result.get("items"))
        assert [read_string(item) for item in items] == [timestamp, "한국어"]
        assert peer.received[0].body == json_bytes({"items": [timestamp, "한국어"]})


@pytest.mark.parametrize("value", [None, 1, True, [], "string"])
def test_record_reader_rejects_invalid(value: object) -> None:
    with pytest.raises(ClientError, check=lambda error: error.code == "internal"):
        read_record(value)


@pytest.mark.parametrize("value", [None, 1, True, {}, "string"])
def test_list_reader_rejects_invalid(value: object) -> None:
    with pytest.raises(ClientError, check=lambda error: error.code == "internal"):
        read_list(value)


@pytest.mark.parametrize("value", [None, 1, True, {}, []])
def test_string_reader_rejects_invalid(value: object) -> None:
    with pytest.raises(ClientError, check=lambda error: error.code == "internal"):
        read_string(value)


@pytest.mark.parametrize(
    ("status", "body", "code"),
    [
        (429, b'{"error":"rate_limited"}', "rate_limited"),
        (500, b'{"error":"operation_failed","detail":"hidden"}', "operation_failed"),
        (503, b"not json", "internal"),
        (401, b'{"error":"invalid_token\\n"}', "internal"),
        (400, b'{"error":1}', "internal"),
        (400, b"[]", "internal"),
        (302, b"ignored", "internal"),
        (307, b"ignored", "internal"),
        (308, b"ignored", "internal"),
    ],
)
async def test_errors_status_no_redirect_or_resend(
    status: int, body: bytes, code: str
) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(
            writer,
            body,
            status=status,
            headers={"Location": peer.origin + "/thing.run"},
        )

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as transport:
        with pytest.raises(ClientError) as caught:
            await transport.invoke("thing.run", {})
        assert caught.value.code == code
        assert isinstance(caught.value, OperationError) == (code != "internal")
        assert caught.value.status == status
        assert len(peer.received) == 1
        assert "hidden" not in repr(caught.value)


@pytest.mark.parametrize(
    "body", [b"not json", b"\xff", b'{"x":NaN}', b"", b'{"x":Infinity}']
)
async def test_invalid_success_json_is_local_error(body: bytes) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer, body)

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as transport:
        with pytest.raises(ClientError) as caught:
            await transport.invoke("thing.run", {})
        assert type(caught.value) is ClientError
        assert caught.value.code == "internal"
        assert caught.value.status == 200
        assert len(peer.received) == 1


async def test_disconnect_and_raw_exception_redaction() -> None:
    token = secrets.token_urlsafe(32)

    async def disconnect(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 " + token.encode() + b"\r\n\r\n")
        await writer.drain()

    async with Peer(disconnect) as peer, AsyncHttpTransport(peer.origin) as owner:
        with pytest.raises(ClientError) as caught:
            await owner.with_bearer(token).invoke("thing.run", {"private": token})
        failure = caught.value
        assert failure.code == "unavailable"
        assert failure.__context__ is None and failure.__cause__ is None
        assert bool(
            token
            not in str(failure)
            + repr(failure)
            + "".join(traceback.format_exception(failure))
        )
        assert len(peer.received) == 1


async def test_request_utf8_boundary() -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    limit = 4 * 1024 * 1024
    payload = {"text": "한" * ((limit - 11) // 3) + "a" * ((limit - 11) % 3)}
    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as transport:
        await transport.invoke("thing.run", payload)
        assert len(peer.received[0].body) == limit
        with pytest.raises(
            ClientError, check=lambda error: error.code == "resource_exhausted"
        ):
            await transport.invoke("thing.run", {"text": str(payload["text"]) + "a"})
        with pytest.raises(
            ClientError, check=lambda error: error.code == "resource_exhausted"
        ):
            await transport.invoke("thing.run", b" " * (limit + 1))
        assert len(peer.received) == 1


@pytest.mark.parametrize(
    ("encoding", "extra", "status"),
    [
        ("identity", 0, 200),
        ("identity", 1, 200),
        ("gzip", 0, 200),
        ("gzip", 1, 200),
        ("deflate", 1, 200),
        ("gzip", 1, 500),
    ],
)
async def test_streamed_response_boundary(
    encoding: str, extra: int, status: int
) -> None:
    limit = 1024 * 1024
    payload = b'{"text":"' + b"a" * (limit - 11 + extra) + b'"}'
    compressed = (
        gzip.compress(payload)
        if encoding == "gzip"
        else zlib.compress(payload)
        if encoding == "deflate"
        else payload
    )

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(
            writer,
            compressed,
            status=status,
            headers={"Content-Encoding": encoding},
            chunked=True,
        )

    async with Peer(handler) as peer, AsyncHttpTransport(peer.origin) as transport:
        if extra:
            with pytest.raises(
                ClientError, check=lambda error: error.code == "resource_exhausted"
            ) as caught:
                await transport.invoke("thing.run", {})
            assert caught.value.status == status
        else:
            assert (
                len(
                    read_string(
                        read_record(await transport.invoke("thing.run", {}))["text"]
                    )
                )
                == limit - 11
            )
        assert len(peer.received) == 1


@pytest.mark.parametrize("cancel", [False, True])
async def test_whole_body_deadline_cancel_disconnect_and_no_resend(
    cancel: bool,
) -> None:
    started = asyncio.Event()
    disconnected = asyncio.Event()

    async def slow(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        await writer.drain()
        started.set()

        async def chunks() -> None:
            while True:
                writer.write(b"1\r\na\r\n")
                await writer.drain()
                await asyncio.sleep(0.02)

        sender = asyncio.create_task(chunks())
        try:
            try:
                await request.reader.read()
            except ConnectionError:
                pass
            disconnected.set()
        finally:
            sender.cancel()
            await asyncio.gather(sender, return_exceptions=True)

    async with (
        Peer(slow) as peer,
        AsyncHttpTransport(peer.origin, timeout=0.15) as transport,
    ):
        begin = asyncio.get_running_loop().time()
        task = asyncio.create_task(transport.invoke("thing.run", {}))
        await asyncio.wait_for(started.wait(), 1)
        if cancel:
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        else:
            with pytest.raises(
                ClientError, check=lambda error: error.code == "deadline_exceeded"
            ) as caught:
                await task
            assert caught.value.status == 200
        await asyncio.wait_for(disconnected.wait(), 1)
        assert asyncio.get_running_loop().time() - begin < 1
        assert len(peer.received) == 1


@pytest.mark.parametrize("environment", ["emscripten", "wasi", "pyodide"])
def test_environment_rejected_before_httpx_import(environment: str) -> None:
    script = """
import sys, types
import chickinfry
assert 'httpx' not in sys.modules
if sys.argv[1] == 'pyodide':
    sys.modules['pyodide'] = types.ModuleType('pyodide')
else:
    sys.platform = sys.argv[1]
try:
    chickinfry.AsyncHttpTransport('http://127.0.0.1')
except chickinfry.ClientError as failure:
    assert failure.code == 'unimplemented'
else:
    raise AssertionError('environment accepted')
assert 'httpx' not in sys.modules
"""
    result = subprocess.run(
        [sys.executable, "-I", "-c", script, environment], capture_output=True
    )
    assert result.returncode == 0


def test_cross_event_loop_rejected() -> None:
    owner = AsyncHttpTransport("https://example.com")
    store = MemoryStore("https://example.com")

    async def first() -> None:
        async with owner:
            store.credentials()

    asyncio.run(first())

    async def second() -> None:
        with pytest.raises(
            ClientError, check=lambda error: error.code == "failed_precondition"
        ):
            await owner.invoke("thing.run", {})
        with pytest.raises(
            ClientError, check=lambda error: error.code == "failed_precondition"
        ):
            store.credentials()

    asyncio.run(second())


async def test_oversized_stream_is_closed_before_remaining_body() -> None:
    disconnected = asyncio.Event()

    async def oversized(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
        chunk = b"a" * (1024 * 1024 + 1)
        writer.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
        await writer.drain()
        await request.reader.read()
        disconnected.set()

    async with Peer(oversized) as peer, AsyncHttpTransport(peer.origin) as transport:
        with pytest.raises(
            ClientError, check=lambda error: error.code == "resource_exhausted"
        ):
            await transport.invoke("thing.run", {})
        await asyncio.wait_for(disconnected.wait(), 1)
        assert len(peer.received) == 1


async def test_received_mutation_then_connection_drop_has_no_replay() -> None:
    async def drop(request: Received, writer: asyncio.StreamWriter) -> None:
        return

    async with Peer(drop) as peer, AsyncHttpTransport(peer.origin) as transport:
        with pytest.raises(
            ClientError, check=lambda error: error.code == "unavailable"
        ):
            await transport.invoke("thing.run", {})
        assert len(peer.received) == 1


async def test_untrusted_tls_certificate_is_rejected(tmp_path: Path) -> None:
    certificate, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    created = subprocess.run(
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
    assert created.returncode == 0
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    async with Peer(handler, ssl_context=context) as peer:
        async with AsyncHttpTransport(
            peer.origin.replace("http://", "https://", 1)
        ) as transport:
            with pytest.raises(
                ClientError, check=lambda error: error.code == "unavailable"
            ):
                await transport.invoke("thing.run", {})
        assert len(peer.received) == 0
