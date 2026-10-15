import asyncio
import logging
import secrets
import socket
import ssl
import subprocess
import threading
import time
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from dataclasses import asdict
from pathlib import Path

import httpx
import pytest
from typing_extensions import Buffer

from chickinfry import (
    HTTP,
    AsyncHTTP,
    ClientError,
    OperationError,
    SessionCredentials,
    SessionStore,
    _sync_network,
)
from chickinfry._http_common import _response, _serialize
from chickinfry.session import _read_credentials

from .deadline import Clock
from .peer import Peer, Received, json_bytes, respond
from .test_session import credentials


@asynccontextmanager
async def _owner(
    mode: str, origin: str, timeout: float = 1.0
) -> AsyncIterator[HTTP | AsyncHTTP]:
    if mode == "async":
        async with AsyncHTTP(origin, timeout=timeout) as owner:
            yield owner
    else:
        with HTTP(origin, timeout=timeout) as sync:
            yield sync


async def _call(
    owner: HTTP | AsyncHTTP,
    operation: str = "thing.run",
    payload: bytes | Mapping[str, object] = b"{}",
    store: SessionStore | None = None,
) -> object:
    if isinstance(owner, AsyncHTTP):
        client = owner.with_session(store) if store is not None else owner
        return await client.invoke(operation, payload)
    sync = owner.with_session(store) if store is not None else owner
    return await asyncio.to_thread(sync.invoke, operation, payload)


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("variable", ["SSL_CERT_FILE", "SSL_CERT_DIR"])
async def test_environment_ca_is_not_trusted(
    mode: str, variable: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key, certificate, config = (
        tmp_path / "key.pem",
        tmp_path / "ca.pem",
        tmp_path / "openssl.cnf",
    )
    config.write_text(
        "[req]\nprompt=no\ndistinguished_name=dn\nx509_extensions=ext\n[dn]\nCN=127.0.0.1\n[ext]\nsubjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:TRUE\nkeyUsage=keyCertSign,digitalSignature,keyEncipherment\n"
    )
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
            "-config",
            str(config),
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        capture_output=True,
    )
    assert generated.returncode == 0
    hashed = subprocess.check_output(
        ["/usr/bin/openssl", "x509", "-hash", "-noout", "-in", str(certificate)],
        text=True,
    ).strip()
    (tmp_path / (hashed + ".0")).write_bytes(certificate.read_bytes())
    server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_context.load_cert_chain(certificate, key)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer)

    async with Peer(handler, ssl_context=server_context) as peer:
        origin = peer.origin.replace("http://", "https://", 1)
        async with httpx.AsyncClient(
            verify=ssl.create_default_context(cafile=str(certificate)), trust_env=False
        ) as control:
            assert (
                await control.post(origin + "/thing.run", content=b"{}")
            ).status_code == 200
        assert len(peer.received) == 1
        peer.received.clear()
        monkeypatch.delenv("SSL_CERT_FILE", raising=False)
        monkeypatch.delenv("SSL_CERT_DIR", raising=False)
        monkeypatch.setenv(
            variable, str(certificate if variable == "SSL_CERT_FILE" else tmp_path)
        )
        async with _owner(mode, origin) as owner:
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "network_error"
            ):
                await _call(owner)
        assert not peer.received


async def test_interrupt_during_start_keeps_live_refresh_owned(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old, rotated = credentials(), credentials()
    received = threading.Event()
    release = asyncio.Event()
    originals, refreshes = 0, 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal originals, refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            received.set()
            await release.wait()
            await respond(writer, json_bytes(asdict(rotated)))
        else:
            originals += 1
            valid = (
                request.headers.get("authorization") == "Bearer " + rotated.access_token
            )
            await respond(
                writer,
                b"{}" if valid else b'{"error":"invalid_token"}',
                status=200 if valid else 401,
            )

    original_start = threading.Thread.start

    def interrupted(thread: threading.Thread) -> None:
        original_start(thread)
        if thread.name.endswith("(_produce)"):
            assert received.wait(1)
            raise KeyboardInterrupt

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            client = owner.with_session(store)
            monkeypatch.setattr(threading.Thread, "start", interrupted)

            def first() -> bool:
                try:
                    client.invoke("thing.run", {})
                except KeyboardInterrupt:
                    return True
                return False

            assert await asyncio.to_thread(first)
            with store._locked():
                flight = next(iter(store._sync_flights.values()))
                assert not flight.producer_done and not flight.settled
                producer = flight.thread
            monkeypatch.setattr(threading.Thread, "start", original_start)
            later = asyncio.create_task(
                asyncio.to_thread(client.invoke, "thing.run", {})
            )
            while originals < 2:
                await asyncio.sleep(0)
            release.set()
            assert await asyncio.wait_for(later, 1) == {}
            assert refreshes == 1 and originals == 3
            assert producer is not None
            await asyncio.to_thread(producer.join, 1)
            assert not producer.is_alive() and not store._sync_flights


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_dependency_debug_logs_hide_sdk_tokens_only(
    mode: str, caplog: pytest.LogCaptureFixture
) -> None:
    secret = secrets.token_urlsafe(32)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        writer.write(b"HTTP/1.1 " + secret.encode() + b"\r\n\r\n")
        await writer.drain()

    caplog.set_level(logging.DEBUG)
    logger = logging.getLogger("httpcore.http11")
    logger.debug("outside SDK visible")
    async with Peer(handler) as peer:
        async with _owner(mode, peer.origin) as owner:
            with pytest.raises(ClientError) as caught:
                await _call(owner)
        assert bool(secret not in str(caught.value) + repr(caught.value))
        assert bool(secret not in caplog.text)
        assert all(
            secret not in record.getMessage()
            and secret not in repr(record.args)
            and secret not in repr(record.exc_info)
            for record in caplog.records
        )
        assert any(
            record.getMessage() == "outside SDK visible" for record in caplog.records
        )
        assert any(
            record.getMessage() == "Chickinfry request transport event"
            for record in caplog.records
        )
        logger.debug("after SDK visible")
        assert any(
            record.getMessage() == "after SDK visible" for record in caplog.records
        )
        with pytest.raises(httpx.HTTPError):
            async with httpx.AsyncClient(trust_env=False) as external:
                await external.post(peer.origin + "/thing.run", content=b"{}")
        assert any(secret in record.getMessage() for record in caplog.records)
        caplog.clear()


@pytest.mark.parametrize(
    "phase", ["serialize", "setup", "decode", "credentials", "publish"]
)
async def test_async_absolute_deadlines_discard_late_success(
    phase: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, rotated = credentials(), credentials()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if request.path == "/auth.refresh":
            await respond(writer, json_bytes(asdict(rotated)))
        elif phase in {"credentials", "publish"}:
            await respond(writer, b'{"error":"invalid_token"}', status=401)
        else:
            await respond(writer)

    async with Peer(handler) as peer:
        owner = AsyncHTTP(peer.origin, timeout=0.02)
        if phase != "setup":
            owner._http_client()
        store = SessionStore(peer.origin, old)
        snapshot = store.credentials()
        import chickinfry.http as implementation

        if phase == "serialize":
            original = _serialize

            def serialize(payload: bytes | Mapping[str, object]) -> bytes:
                result = original(payload)
                time.sleep(0.07)
                return result

            monkeypatch.setattr(implementation, "_serialize", serialize)
        elif phase == "setup":
            get_client = owner._http_client

            def setup() -> httpx.AsyncClient:
                client = get_client()
                time.sleep(0.04)
                return client

            monkeypatch.setattr(owner, "_http_client", setup)
        elif phase == "decode":
            decode = _response

            def decode_late(body: bytes, status: int) -> object:
                value = decode(body, status)
                time.sleep(0.04)
                return value

            monkeypatch.setattr(implementation, "_response", decode_late)
        elif phase == "credentials":
            read = _read_credentials

            def credentials_late(value: object) -> SessionCredentials:
                result = read(value)
                time.sleep(0.04)
                return result

            monkeypatch.setattr(implementation, "_read_credentials", credentials_late)
        else:
            attempt = owner._attempt

            async def publish_late(
                operation: str,
                body: bytes,
                token: str | None,
                *,
                credentials: bool = False,
                deadline: float | None = None,
            ) -> object:
                result = await attempt(
                    operation, body, token, credentials=credentials, deadline=deadline
                )
                if operation == "auth.refresh":
                    time.sleep(0.04)
                return result

            monkeypatch.setattr(owner, "_attempt", publish_late)
        try:
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "timeout"
            ):
                await _call(
                    owner, store=store if phase in {"credentials", "publish"} else None
                )
            assert store.credentials() is snapshot
            if phase in {"serialize", "setup"}:
                assert not peer.received
        finally:
            await owner.aclose()


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize(
    "body",
    [
        b"not JSON",
        b"{}",
        b'{"message":"unavailable"}',
        b'{"error":""}',
        b'{"error":"Conflict"}',
        b'{"error":"conflict1"}',
        b'{"error":"bad-request"}',
        b'{"error":42}',
        b'{"error":null}',
        b'{"error":{}}',
        b'{"error":[]}',
    ],
)
async def test_invalid_error_envelope_preserves_status(mode: str, body: bytes) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(writer, body, status=503)

    async with Peer(handler) as peer:
        async with _owner(mode, peer.origin) as owner:
            with pytest.raises(OperationError) as caught:
                await _call(owner)
        assert caught.value.code == "invalid_response" and caught.value.status == 503
        assert not caught.value._valid_error_envelope
        assert len(peer.received) == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize(
    "outcome",
    ["timeout", "disconnect", "400", "403", "429", "500", "malformed", "malformed401"],
)
async def test_unknown_refresh_blocks_generation_until_replace(
    mode: str, outcome: str
) -> None:
    old, recovered, rotated = credentials(), credentials(), credentials()
    originals, refreshes = 0, 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal originals, refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            if refreshes == 2:
                await respond(writer, json_bytes(asdict(rotated)))
            elif outcome == "timeout":
                await asyncio.sleep(3)
                await respond(writer, json_bytes(asdict(rotated)))
            elif outcome == "disconnect":
                return
            else:
                status = (
                    int(outcome)
                    if outcome.isdigit()
                    else 401
                    if outcome == "malformed401"
                    else 200
                )
                await respond(
                    writer,
                    b"not JSON"
                    if outcome.startswith("malformed")
                    else b'{"error":"operation_failed"}',
                    status=status,
                )
        else:
            originals += 1
            valid = (
                request.headers.get("authorization") == "Bearer " + rotated.access_token
            )
            await respond(
                writer,
                b"{}" if valid else b'{"error":"invalid_token"}',
                status=200 if valid else 401,
            )

    async with Peer(handler) as peer:
        async with _owner(mode, peer.origin, timeout=0.5) as owner:
            store = SessionStore(peer.origin, old)
            snapshot = store.credentials()
            with pytest.raises(ClientError) as first:
                await _call(owner, store=store)
            assert originals == 1 and refreshes == 1
            assert first.value._outcome_unknown
            with pytest.raises(OperationError) as later:
                await _call(owner, store=store)
            assert later.value.code == "invalid_token" and later.value.status == 401
            assert originals == 2 and refreshes == 1
            assert store.credentials() is snapshot
            store.replace(recovered)
            assert await _call(owner, store=store) == {}
            assert originals == 4 and refreshes == 2


async def test_uncertain_unstarted_producer_expires_without_second_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = credentials()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        assert request.path != "/auth.refresh"
        await respond(writer, b'{"error":"invalid_token"}', status=401)

    start = threading.Thread.start

    def unknown(thread: threading.Thread) -> None:
        if thread.name.endswith("(_produce)"):
            raise SystemExit
        start(thread)

    async with Peer(handler) as peer:
        with HTTP(peer.origin, timeout=0.04) as owner:
            store = SessionStore(peer.origin, old)
            client = owner.with_session(store)
            monkeypatch.setattr(threading.Thread, "start", unknown)

            def interrupted() -> bool:
                try:
                    client.invoke("thing.run", {})
                except SystemExit:
                    return True
                return False

            assert await asyncio.to_thread(interrupted)
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "timeout"
            ):
                await asyncio.to_thread(client.invoke, "thing.run", {})
            await asyncio.sleep(0.01)
            assert not store._sync_flights
            with pytest.raises(OperationError) as later:
                await asyncio.to_thread(client.invoke, "thing.run", {})
            assert later.value.code == "invalid_token"
            assert len(peer.received) == 3 and store.credentials() is not None


async def test_definite_creation_failure_can_retry_new_call(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old, rotated = credentials(), credentials()
    refreshes = 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            await respond(writer, json_bytes(asdict(rotated)))
        else:
            valid = (
                request.headers.get("authorization") == "Bearer " + rotated.access_token
            )
            await respond(
                writer,
                b"{}" if valid else b'{"error":"invalid_token"}',
                status=200 if valid else 401,
            )

    start = threading.Thread.start

    def fail(thread: threading.Thread) -> None:
        if thread.name.endswith("(_produce)"):
            raise RuntimeError
        start(thread)

    async with Peer(handler) as peer:
        with HTTP(peer.origin) as owner:
            store = SessionStore(peer.origin, old)
            client = owner.with_session(store)
            monkeypatch.setattr(threading.Thread, "start", fail)
            with pytest.raises(
                ClientError, check=lambda error: error.reason == "network_error"
            ):
                await asyncio.to_thread(client.invoke, "thing.run", {})
            assert not store._sync_flights and store._blocked_generation is None
            monkeypatch.setattr(threading.Thread, "start", start)
            assert await asyncio.to_thread(client.invoke, "thing.run", {}) == {}
            assert refreshes == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize(
    "failure", ["connect", "mid_send", "timeout", "disconnect", "final_error"]
)
async def test_private_outcome_unknown_observes_send_progress(
    mode: str, failure: str
) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        if failure == "timeout":
            await request.reader.read()
        elif failure == "disconnect":
            return
        else:
            await respond(writer, b'{"error":"operation_failed"}', status=500)

    async def reset(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        assert await reader.read(1024)
        writer.transport.abort()

    async with Peer(
        handler, raw_handler=reset if failure == "mid_send" else None
    ) as peer:
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            origin = (
                f"http://127.0.0.1:{reserved.getsockname()[1]}"
                if failure == "connect"
                else peer.origin
            )
            async with _owner(mode, origin, timeout=0.10) as owner:
                with pytest.raises(ClientError) as caught:
                    await _call(
                        owner,
                        payload={"text": "a" * (4 * 1024 * 1024 - 11)}
                        if failure == "mid_send"
                        else b"{}",
                    )
                assert caught.value._outcome_unknown == (
                    failure in {"mid_send", "timeout", "disconnect"}
                )


def test_package_does_not_export_private_conformance_hooks() -> None:
    import chickinfry
    from chickinfry import _conformance

    assert set(chickinfry.__all__) == {
        "HTTP",
        "SyncClientTransport",
        "AsyncHTTP",
        "ClientTransport",
        "ClientError",
        "OperationError",
        "SessionCredentials",
        "SessionStore",
    }
    private = {
        "_observer",
        "_Observation",
        "_outcome_unknown",
        "_HookError",
        "_ClearAttempt",
        "_clear_attempts",
    }
    assert private.isdisjoint(vars(chickinfry))
    assert private.isdisjoint(dir(chickinfry))
    assert not any(hasattr(chickinfry, name) for name in private)
    assert all(name not in Path("README.md").read_text() for name in private)
    # Importing a submodule installs its own name on the parent package.
    assert {
        name for name, value in vars(chickinfry).items() if value is _conformance
    } == {"_conformance"}


def test_sync_read_phase_cannot_outlive_remaining_whole_deadline(
    monkeypatch: pytest.MonkeyPatch, sync_clock: Clock
) -> None:
    timeouts: list[float | None] = []

    class ObservedSocket(socket.socket):
        def send(self, data: Buffer, flags: int = 0) -> int:
            sync_clock.advance(0.05)
            return memoryview(data).nbytes

        def recv(self, bufsize: int, flags: int = 0) -> bytes:
            remaining = self.gettimeout()
            timeouts.append(remaining)
            assert remaining is not None
            sync_clock.advance(remaining)
            raise TimeoutError

    with ObservedSocket() as sock, HTTP("http://127.0.0.1", timeout=10.0) as owner:
        monkeypatch.setattr(
            _sync_network._Backend,
            "connect_tcp",
            lambda backend, *args, **kwargs: _sync_network._Stream(sock, backend),
        )
        with pytest.raises(ClientError, check=lambda error: error.reason == "timeout"):
            owner._attempt("thing.run", b"{}", None, 0.20)
        assert timeouts == pytest.approx([0.10])
        assert sync_clock.now == pytest.approx(0.20)


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("failure", ["size", "decompression"])
async def test_incomplete_body_failure_is_outcome_unknown(
    mode: str, failure: str
) -> None:
    disconnected = asyncio.Event()

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        body = b"a" * (1024 * 1024 + 1) if failure == "size" else b"broken gzip"
        encoding = b"Content-Encoding: gzip\r\n" if failure == "decompression" else b""
        writer.write(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
            + encoding
            + b"\r\n"
            + f"{len(body):x}\r\n".encode()
            + body
            + b"\r\n"
        )
        await writer.drain()
        try:
            await request.reader.read()
        except ConnectionError:
            pass
        disconnected.set()

    async with Peer(handler) as peer:
        async with _owner(mode, peer.origin) as owner:
            reason = "response_too_large" if failure == "size" else "invalid_response"
            with pytest.raises(
                ClientError, check=lambda error: error.reason == reason
            ) as caught:
                await _call(owner)
            assert caught.value.status == 200 and caught.value._outcome_unknown
            await asyncio.wait_for(disconnected.wait(), 1)
            assert len(peer.received) == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("code", ["invalid_token", "other", "invalid_response"])
async def test_well_formed_refresh_401_clears_only_expected_without_retry(
    mode: str, code: str
) -> None:
    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        await respond(
            writer,
            json_bytes(
                {"error": code if request.path == "/auth.refresh" else "invalid_token"}
            ),
            status=401,
        )

    async with Peer(handler) as peer:
        async with _owner(mode, peer.origin) as owner:
            store = SessionStore(peer.origin, credentials())
            with pytest.raises(OperationError) as caught:
                await _call(owner, store=store)
            assert caught.value.code == code and caught.value._valid_error_envelope
            assert not caught.value._outcome_unknown
            assert store.credentials() is None
            assert len(peer.received) == 2


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("status", [200, 401])
async def test_refresh_hooks_preserve_unregistered_session_behavior(
    mode: str, status: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    from chickinfry._conformance import _ClearAttempt, _Observation, _observer

    rotated = credentials()
    outcomes: list[tuple[object, bool, int, int]] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        pytest.fail("An unregistered session hook performed work.")

    for registered in (False, True):

        async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
            if request.path == "/auth.refresh":
                await respond(
                    writer,
                    json_bytes(asdict(rotated))
                    if status == 200
                    else b'{"error":"invalid_token"}',
                    status=status,
                )
            else:
                signed = (
                    request.headers.get("authorization")
                    == "Bearer " + rotated.access_token
                )
                await respond(
                    writer,
                    b"{}" if signed else b'{"error":"invalid_token"}',
                    status=200 if signed else 401,
                )

        async with Peer(handler) as peer, _owner(mode, peer.origin) as owner:
            store = SessionStore(peer.origin, credentials())
            observation = _Observation(float("inf")) if registered else None
            token = _observer.set(observation) if observation is not None else None
            try:
                with monkeypatch.context() as guard:
                    if not registered:
                        guard.setattr(_ClearAttempt, "__init__", forbidden)
                        for method in ("arrive", "aarrive", "trace", "atrace"):
                            guard.setattr(_Observation, method, forbidden)
                    try:
                        value: object = await _call(owner, store=store)
                    except OperationError as error:
                        value = (error.code, error.status, error._outcome_unknown)
                current = store.credentials()
                outcomes.append(
                    (value, current == rotated, store._generation, len(peer.received))
                )
                assert store._active == {} and store._clear_attempts is None
                assert store._flights == {} and store._sync_flights == {}
            finally:
                if token is not None:
                    _observer.reset(token)
    assert outcomes[0] == outcomes[1]
