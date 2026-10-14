import asyncio
import ssl
from urllib.parse import urlencode, urlsplit

import pytest

from chickinfry.postgres import PostgresPort

from .server_fixture import Harness

MODES = ("prefer", "require", "verify-ca", "verify-full")


def connection(
    db: Harness, host: str, mode: str | None, binding: str | None = None
) -> PostgresPort:
    url = urlsplit(db.postgres._dsn)
    assert url.username is not None and url.password is not None
    options = {} if mode is None else {"sslmode": mode}
    if binding is not None:
        options["channel_binding"] = binding
    port = PostgresPort(
        url._replace(
            netloc=f"{url.username}:{url.password}@{host}:{url.port}",
            query=urlencode(options),
        ).geturl()
    )
    db.ports.append(port)
    return port


@pytest.mark.parametrize("mode", MODES)
async def test_tls_requires_trusted_certificate_and_hostname(
    db: Harness, mode: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    untrusted = connection(db, "localhost", mode)
    with pytest.raises(ssl.SSLCertVerificationError):
        await untrusted.query("select 1", ())
    default_context = ssl.create_default_context
    monkeypatch.setattr(
        ssl,
        "create_default_context",
        lambda: default_context(cafile=str(db.postgres.certificate)),
    )
    trusted = connection(db, "localhost", mode)
    assert (await trusted.query("select 1 as value", ()))[0]["value"] == 1
    mismatch = connection(db, "127.0.0.1", mode)
    with pytest.raises(ssl.SSLCertVerificationError):
        await mismatch.query("select 1", ())


@pytest.mark.parametrize("mode", [None, "disable", "no-verify"])
async def test_explicit_tls_policy_modes(db: Harness, mode: str | None) -> None:
    port = connection(db, "127.0.0.1", mode)
    result = await port.query(
        "select ssl from pg_stat_ssl where pid=pg_backend_pid()", ()
    )
    assert result[0]["ssl"] is (mode == "no-verify")


@pytest.mark.parametrize(
    "query",
    [
        "sslmode=unknown",
        "sslmode=allow",
        "sslmode=",
        "sslmode=REQUIRE",
        "sslmode=disable&sslmode=require",
        "sslmode=no-verify&unknown=value",
        "channel_binding=unknown",
        "channel_binding=",
        "channel_binding=prefer&channel_binding=disable",
    ],
)
def test_unsupported_tls_options_rejected(query: str) -> None:
    with pytest.raises(ValueError):
        PostgresPort("postgresql://test:test@127.0.0.1:5432/test?" + query)


@pytest.mark.parametrize("mode", ["disable", "require"])
@pytest.mark.parametrize("binding", [None, "prefer", "disable"])
async def test_optional_channel_binding_preserves_tls_policy(
    db: Harness, mode: str, binding: str | None, monkeypatch: pytest.MonkeyPatch
) -> None:
    default_context = ssl.create_default_context
    monkeypatch.setattr(
        ssl,
        "create_default_context",
        lambda: default_context(cafile=str(db.postgres.certificate)),
    )
    port = connection(db, "localhost", mode, binding)
    assert (
        await port.query("select ssl from pg_stat_ssl where pid=pg_backend_pid()", ())
    )[0]["ssl"] is (mode == "require")


@pytest.mark.parametrize("mode", [None, "disable", "require", "no-verify"])
def test_required_channel_binding_rejected_before_connect(mode: str | None) -> None:
    query = "channel_binding=require" + ("" if mode is None else "&sslmode=" + mode)
    with pytest.raises(
        ValueError, match="Remove channel_binding from the database URL"
    ):
        PostgresPort("postgresql://test:test@127.0.0.1:5432/test?" + query)


@pytest.mark.parametrize("mode", (*MODES, "no-verify"))
async def test_tls_never_falls_back_to_plaintext(mode: str) -> None:
    ended = asyncio.Event()
    connections = 0
    plaintext = bytearray()
    tasks: list[asyncio.Task[None]] = []

    async def reject(
        reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        nonlocal connections
        connections += 1
        try:
            assert await reader.readexactly(8) == b"\0\0\0\x08\x04\xd2\x16\x2f"
            writer.write(b"N")
            await writer.drain()
            plaintext.extend(await reader.read())
        finally:
            writer.close()
            await writer.wait_closed()
            ended.set()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        tasks.append(asyncio.create_task(reject(reader, writer)))

    server = await asyncio.start_server(accept, "127.0.0.1", 0)
    port = PostgresPort(
        f"postgresql://test:test@127.0.0.1:{server.sockets[0].getsockname()[1]}/test?sslmode={mode}"
    )
    try:
        async with server:
            with pytest.raises(ConnectionError):
                await port.query("select 1", ())
            await asyncio.wait_for(ended.wait(), 1)
            assert connections == 1 and not plaintext
    finally:
        await port.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
