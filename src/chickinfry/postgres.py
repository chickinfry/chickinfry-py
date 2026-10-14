"""Generated applications create and close a PostgresPort per request.

The asyncpg dependency of chickinfry[server] is imported only on the first
query. The text codecs for date and timestamp reject infinity instead of
mapping it to calendar boundary values.
"""

import asyncio
import ssl
from collections.abc import Awaitable, Callable, Mapping, Sequence
from contextvars import ContextVar
from datetime import date, datetime
from importlib import import_module
from typing import Protocol, TypeVar, cast
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

from .orm import DatabasePort, format_timestamp, parse_date, parse_timestamp

T = TypeVar("T")
_CLEANUP_SECONDS = 5.0
_ACTIVE: ContextVar[frozenset[int]] = ContextVar(
    "chickinfry_transactions", default=frozenset()
)


class CommitOutcomeUnknown(Exception):
    """A work unit is never retried automatically when the COMMIT response is ambiguous."""

    outcome_unknown = True

    def __init__(self) -> None:
        super().__init__("Transaction commit outcome is unknown.")


class _Connection(Protocol):
    _transport: asyncio.Transport

    async def fetch(
        self, query: str, *args: object
    ) -> Sequence[Mapping[str, object]]: ...
    async def execute(self, query: str) -> str: ...
    async def close(self, *, timeout: float) -> None: ...
    def terminate(self) -> None: ...
    async def set_type_codec(
        self,
        typename: str,
        *,
        schema: str,
        encoder: Callable[[object], str],
        decoder: Callable[[str], object],
        format: str,
    ) -> None: ...


class _Asyncpg(Protocol):
    async def connect(
        self,
        dsn: str,
        *,
        timeout: float,
        server_settings: Mapping[str, str],
        ssl: ssl.SSLContext | bool,
    ) -> _Connection: ...


def _date_text(value: object) -> str:
    if type(value) is not date:
        raise ValueError("A date parameter is required.")
    return value.isoformat()


def _timestamp_text(value: object) -> str:
    if not isinstance(value, datetime):
        raise ValueError("A datetime parameter is required.")
    return format_timestamp(value)


def _validate_url(dsn: str) -> None:
    try:
        url = urlsplit(dsn)
        if (
            url.scheme not in ("postgres", "postgresql")
            or not url.hostname
            or not url.username
            or not url.password
            or not url.path[1:]
            or url.fragment
            or (url.port is not None and not 1 <= url.port <= 65535)
        ):
            raise ValueError
        if any(
            any(ord(c) < 32 or ord(c) == 127 for c in unquote(part))
            for part in (url.hostname, url.username, url.password, url.path)
        ):
            raise ValueError
        options = parse_qsl(url.query, keep_blank_values=True)
        if len({key for key, _ in options}) != len(options):
            raise ValueError
        for key, value in options:
            if key == "channel_binding":
                if value not in ("require", "prefer", "disable"):
                    raise ValueError
            elif key != "sslmode" or value not in (
                "disable",
                "prefer",
                "require",
                "verify-ca",
                "verify-full",
                "no-verify",
            ):
                raise ValueError
    except ValueError:
        raise ValueError("A complete, supported PostgreSQL URL is required.") from None


class PostgresPort:
    """Lazily creates one connection and gives transaction callbacks a scoped DatabasePort."""

    def __init__(self, dsn: str) -> None:
        _validate_url(dsn)
        url = urlsplit(dsn)
        options = dict(parse_qsl(url.query, keep_blank_values=True))
        if options.get("channel_binding") == "require":
            raise ValueError(
                "channel_binding=require is not supported by this runtime. "
                "Remove channel_binding from the database URL; the connection "
                "still verifies TLS with sslmode=verify-full."
            )
        # The pinned asyncpg offers no PLUS mechanism, so prefer may use plain SCRAM.
        options.pop("channel_binding", None)
        self._dsn = url._replace(query=urlencode(options)).geturl()
        self._connection: _Connection | None = None
        self._lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._closed = False

    def _check(self) -> None:
        if self._closed:
            raise RuntimeError("The database connection is closed.")
        if id(self) in _ACTIVE.get():
            raise RuntimeError(
                "Root database reentry inside a transaction is not supported."
            )

    async def _connect(self) -> _Connection:
        if self._closed:
            raise RuntimeError("The database connection is closed.")
        if self._connection is None:
            driver = cast(_Asyncpg, import_module("asyncpg"))
            mode = dict(parse_qsl(urlsplit(self._dsn).query)).get("sslmode")
            tls: ssl.SSLContext | bool = False
            if mode is not None and mode != "disable":
                # prefer/require/verify-* all require verified TLS, matching the TS runtime.
                tls = ssl.create_default_context()
                if mode == "no-verify":
                    tls.check_hostname = False
                    tls.verify_mode = ssl.CERT_NONE
            connection = await driver.connect(
                self._dsn,
                timeout=10,
                server_settings={"DateStyle": "ISO", "TimeZone": "UTC"},
                ssl=tls,
            )
            self._connection = connection
            try:
                if self._closed:
                    raise RuntimeError("The database connection is closed.")
                await connection.set_type_codec(
                    "date",
                    schema="pg_catalog",
                    format="text",
                    encoder=_date_text,
                    decoder=parse_date,
                )
                await connection.set_type_codec(
                    "timestamptz",
                    schema="pg_catalog",
                    format="text",
                    encoder=_timestamp_text,
                    decoder=parse_timestamp,
                )
            except BaseException:
                self.terminate()
                raise
        return self._connection

    async def _execute(self, sql: str) -> None:
        await (await self._connect()).execute(sql)

    async def query(
        self, sql: str, parameters: Sequence[object]
    ) -> Sequence[Mapping[str, object]]:
        self._check()
        async with self._lock:
            self._check()
            try:
                return await (await self._connect()).fetch(sql, *parameters)
            except asyncio.CancelledError:
                self.terminate()
                raise

    async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
        self._check()
        async with self._lock:
            self._check()
            tx = _TransactionPort(self)
            begun = committing = False
            marker = _ACTIVE.set(_ACTIVE.get() | {id(self)})
            try:
                await self._execute("begin")
                begun = True
                value = await work(tx)
                tx.active = False
                committing = True
                await self._execute("commit")
                return value
            except BaseException as error:
                tx.active = False
                if committing:
                    try:
                        await self.close()
                    except BaseException:
                        pass
                    raise CommitOutcomeUnknown() from None
                if isinstance(error, asyncio.CancelledError):
                    # No driver query or rollback waits for the cancellation acknowledgement.
                    self.terminate()
                    raise
                if begun:
                    try:
                        async with asyncio.timeout(_CLEANUP_SECONDS):
                            await self._execute("rollback")
                    except BaseException:
                        self.terminate()
                else:
                    self.terminate()
                raise
            finally:
                tx.active = False
                _ACTIVE.reset(marker)

    async def close(self) -> None:
        self._closed = True
        try:
            # The driver close timeout does not cover waiting for a pending cancel.
            async with asyncio.timeout(_CLEANUP_SECONDS):
                async with self._close_lock:
                    if self._connection is not None:
                        await self._connection.close(timeout=_CLEANUP_SECONDS)
        finally:
            self.terminate()

    def terminate(self) -> None:
        """Reclaims the real connection and cancel work after a timeout or cancellation."""
        self._closed = True
        connection, self._connection = self._connection, None
        if connection is not None:
            transport = connection._transport
            try:
                connection.terminate()
            finally:
                # asyncpg 0.31 skips the transport abort while its closing flag is set.
                transport.abort()


class _TransactionPort:
    def __init__(self, root: PostgresPort) -> None:
        self.root = root
        self.active = True
        self._lock = asyncio.Lock()

    async def query(
        self, sql: str, parameters: Sequence[object]
    ) -> Sequence[Mapping[str, object]]:
        async with self._lock:
            if not self.active:
                raise RuntimeError("The transaction is no longer active.")
            return await (await self.root._connect()).fetch(sql, *parameters)

    async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
        raise RuntimeError("Nested transactions are not supported.")
