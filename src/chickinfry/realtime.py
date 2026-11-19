"""Ordered realtime subscriptions for generated async clients."""

import asyncio
import json
import logging
import re
from collections import deque
from collections.abc import AsyncIterator, Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import partial
from typing import cast
from uuid import uuid4

from websockets.asyncio.client import ClientConnection, connect
from websockets.exceptions import WebSocketException

from .errors import ClientError, OperationError
from .http import AsyncTransport, _Authenticated

_UUID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
_ENDPOINT = re.compile(r"wss://" + _UUID.pattern + r"\.chickinfry\.app/realtime")
_CODE = re.compile(r"[a-z_]{1,64}")
_FRAME_ERRORS = {
    "unauthorized_channel": "permission_denied",
    "already_subscribed": "internal",
    "too_many_channels": "resource_exhausted",
    "replay_failed": "unavailable",
    "realtime_unavailable": "unavailable",
}
_MAX_BYTES = 66_560
_BUDGET = 30
_LOG = logging.Logger("chickinfry.websocket", logging.CRITICAL + 1)


def _endpoint(value: object) -> str:
    if not isinstance(value, str) or not _ENDPOINT.fullmatch(value):
        raise ClientError("internal")
    return value


def _uuid(value: object) -> bool:
    return isinstance(value, str) and _UUID.fullmatch(value) is not None


def _cursor(value: object) -> str:
    if isinstance(value, str) and (not value or _uuid(value)):
        return value
    raise ClientError("internal")


class _Connect(connect):
    # The ticket must never follow a redirect, including one on the same host.
    def process_redirect(self, exc: Exception) -> Exception:
        return exc


@dataclass(frozen=True)
class RealtimeEvent:
    channel: str
    payload: object

    @property
    def type(self) -> str:
        return "event"


@dataclass(frozen=True)
class RealtimeGap:
    channel: str

    @property
    def type(self) -> str:
        return "gap"


@dataclass(frozen=True)
class SubscribeOptions:
    on_gap: Callable[[RealtimeGap], Awaitable[None]] | None = None


@dataclass(frozen=True)
class _Probe:
    endpoint: Callable[[object], str]
    point: Callable[[str], None]
    inspect: Callable[[Callable[[], dict[str, int]]], None]
    dispatch: Callable[[str, Callable[[], Awaitable[None]]], Awaitable[None]]


_probe: ContextVar[_Probe | None] = ContextVar("realtime_probe", default=None)


class RealtimeClient:
    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport

    async def subscribe(
        self, channel: str, options: SubscribeOptions | None = None
    ) -> "RealtimeSubscription":
        try:
            valid = 0 < len(channel.encode("utf-8")) <= 128
        except (AttributeError, UnicodeError):
            valid = False
        if not valid or any(ord(char) < 32 or ord(char) == 127 for char in channel):
            raise ClientError("invalid_argument")
        sub = RealtimeSubscription(
            self._transport, channel, options or SubscribeOptions(), _probe.get()
        )
        return await sub._start()


@dataclass(eq=False)
class _Connection:
    socket: ClientConnection
    prepared: bool = False
    confirmation: str | None = None
    checkpoint: str | None = None


@dataclass(eq=False)
class _Recovery:
    cursor: str
    complete: bool = False
    connection: _Connection | None = None


class _Events:
    def __init__(self, subscription: "RealtimeSubscription") -> None:
        self._subscription = subscription
        self._consumed = False

    def __aiter__(self) -> AsyncIterator[RealtimeEvent]:
        if self._consumed:
            raise ClientError("failed_precondition")
        self._consumed = True
        return self._subscription._events()


class RealtimeSubscription:
    def __init__(
        self,
        transport: AsyncTransport,
        channel: str,
        options: SubscribeOptions,
        probe: _Probe | None,
    ) -> None:
        self.events = _Events(self)
        self._transport = transport
        self._channel = channel
        self._on_gap = options.on_gap
        self._probe = probe
        self._id = str(uuid4())
        self._last = ""
        self._queue: deque[tuple[str, object]] = deque()
        self._changed = asyncio.Event()
        self._ready: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._connection: _Connection | None = None
        self._recovery: _Recovery | None = None
        self._deadline: asyncio.TimerHandle | None = None
        self._worker: asyncio.Task[None] | None = None
        self._renewal: asyncio.Task[None] | None = None
        self._callback: asyncio.Task[None] | None = None
        self._active = True
        self._first_ready = False
        self._demand = False
        self._failure: ClientError | None = None
        self._loss_budgets = 0
        self._connections_started = 0

    async def _start(self) -> "RealtimeSubscription":
        if self._probe:
            self._probe.inspect(self._metrics)
        self._arm_budget()
        self._worker = asyncio.create_task(self._run())
        if (
            isinstance(self._transport, _Authenticated)
            and self._transport._store is not None
        ):
            self._renewal = asyncio.create_task(self._renew(self._transport))
        try:
            await self._ready
            return self
        except asyncio.CancelledError:
            await self.unsubscribe()
            raise

    def _metrics(self) -> dict[str, int]:
        return {
            "pendingReads": int(self._active and self._demand),
            "activeRenewalWatchers": int(self._active and self._renewal is not None),
            "reprepareBudgetMs": _BUDGET * 1000 if self._loss_budgets else 0,
            "budgetResets": max(0, self._loss_budgets - 1),
            "connectionsStarted": self._connections_started,
        }

    def _arm_budget(self) -> None:
        if self._deadline is None:
            self._loss_budgets += int(self._first_ready)
            self._deadline = asyncio.get_running_loop().call_later(
                _BUDGET, self._stop, ClientError("deadline_exceeded")
            )

    def _stop(self, error: ClientError | None = None) -> None:
        if not self._active:
            return
        self._active = False
        self._failure = error
        self._queue.clear()
        self._connection = None
        self._recovery = None
        if self._deadline is not None:
            self._deadline.cancel()
        if not self._ready.done():
            self._ready.set_exception(error or ClientError("canceled"))
        for task in (self._worker, self._renewal):
            if task is not None and task is not asyncio.current_task():
                task.cancel()
        self._changed.set()

    async def unsubscribe(self) -> None:
        current = self._connection
        if current is not None:
            await self._send(current, "unsubscribe")
        self._stop()
        for task in (self._worker, self._renewal):
            if task is not None and task is not asyncio.current_task():
                await asyncio.gather(task, return_exceptions=True)

    async def _events(self) -> AsyncIterator[RealtimeEvent]:
        try:
            while True:
                self._demand = True
                try:
                    while self._active:
                        if self._recovery is not None:
                            self._recover()
                        elif (
                            self._connection is not None
                            and self._connection.prepared
                            and self._queue
                        ):
                            self._last, payload = self._queue.popleft()
                            await self._ack(self._connection)
                            break
                        self._changed.clear()
                        await self._changed.wait()
                    else:
                        if self._failure is not None:
                            raise self._failure
                        return
                finally:
                    self._demand = False
                if self._active:
                    yield RealtimeEvent(self._channel, payload)
        finally:
            await self.unsubscribe()

    async def _send(self, current: _Connection, kind: str, **fields: object) -> bool:
        try:
            await current.socket.send(
                json.dumps({"type": kind, "channel": self._channel, **fields})
            )
            return self._active and self._connection is current
        except WebSocketException:
            await current.socket.close()
            return False

    async def _ack(self, current: _Connection) -> None:
        if (
            current.prepared
            and current.checkpoint is not None
            and self._recovery is None
            and not self._queue
        ):
            if await self._send(current, "ack", cursor=current.checkpoint):
                current.checkpoint = None

    def _gap(self, cursor: str) -> None:
        if self._on_gap is None:
            self._stop(ClientError("data_loss"))
            return
        self._recovery = _Recovery(cursor)
        self._queue.clear()
        if self._connection is not None:
            self._connection.prepared = False
        self._arm_budget()
        if self._probe:
            self._probe.point("gap")
        self._recover()

    def _recover(self) -> None:
        recovery, callback = self._recovery, self._on_gap
        if (
            not self._active
            or recovery is None
            or callback is None
            or recovery.complete
            or self._callback is not None
            or (self._first_ready and not self._demand)
        ):
            return

        async def reload() -> None:
            try:
                if not self._active or recovery is not self._recovery:
                    return
                await callback(RealtimeGap(self._channel))
                if self._active and recovery is self._recovery:
                    recovery.complete = True
                    self._last = recovery.cursor
                    self._queue.clear()
                    current, self._connection = self._connection, None
                    if current is not None:
                        await current.socket.close()
            except Exception as cause:
                if self._active and recovery is self._recovery:
                    failure = ClientError("unknown")
                    failure.__cause__ = cause
                    self._stop(failure)
            finally:
                self._callback = None
                self._changed.set()

        self._callback = asyncio.create_task(reload())

    async def _receive(self, current: _Connection, message: str | bytes) -> None:
        if not self._active or self._connection is not current:
            if self._probe:
                self._probe.point("discarded")
            return
        try:
            if (
                not isinstance(message, str)
                or len(message.encode("utf-8")) > _MAX_BYTES
            ):
                raise ClientError("internal")
            value = json.loads(message)
            if not isinstance(value, dict):
                raise ClientError("internal")
            frame = cast(dict[str, object], value)
            kind = frame.get("type")
            if frame.get("channel") != self._channel and not (
                kind == "error" and "channel" not in frame
            ):
                raise ClientError("internal")
            if kind == "ready":
                cursor = _cursor(frame.get("cursor"))
                nonce = frame.get("confirmation")
                ack = frame.get("acknowledge", False)
                if not isinstance(ack, bool) or (
                    "confirmation" in frame and not _uuid(nonce)
                ):
                    raise ClientError("internal")
                current.checkpoint = cursor if ack else None
                if nonce is None:
                    if current.confirmation is None:
                        current.confirmation = str(uuid4())
                        await self._send(
                            current, "confirm", confirmation=current.confirmation
                        )
                    return
                if nonce != current.confirmation:
                    return
                recovery = self._recovery
                if recovery is not None:
                    if not recovery.complete or recovery.connection is not current:
                        return
                    self._recovery = None
                    if self._probe:
                        self._probe.point("recovered")
                current.prepared = self._first_ready = True
                if self._deadline is not None:
                    self._deadline.cancel()
                    self._deadline = None
                if not self._ready.done():
                    self._ready.set_result(None)
                await self._ack(current)
                self._changed.set()
            elif kind == "gap":
                self._gap(_cursor(frame.get("cursor")))
            elif kind == "event":
                cursor = _cursor(frame.get("cursor"))
                previous = _cursor(frame.get("previous"))
                if not cursor or "payload" not in frame:
                    raise ClientError("internal")
                if cursor == self._last or any(
                    item[0] == cursor for item in self._queue
                ):
                    return
                expected = (
                    self._queue[-1][0]
                    if self._queue
                    else (
                        self._recovery.cursor
                        if self._recovery is not None
                        else self._last
                    )
                )
                full = len(self._queue) >= (512 if self._probe else 256)
                if full or previous != expected:
                    if full and self._probe:
                        self._probe.point("overflow")
                    self._gap(cursor)
                else:
                    self._queue.append((cursor, frame["payload"]))
                    self._changed.set()
            elif kind == "error":
                code = frame.get("error")
                if not isinstance(code, str) or not _CODE.fullmatch(code):
                    raise ClientError("internal")
                self._stop(ClientError(_FRAME_ERRORS.get(code, "unknown")))
            else:
                raise ClientError("internal")
        except (UnicodeError, ValueError, RecursionError):
            self._stop(ClientError("internal"))
        except ClientError as error:
            self._stop(error)

    async def _run(self) -> None:
        backoff = 0.5
        while self._active:
            try:
                value = await self._transport.invoke("realtime.ticket", {})
                if not isinstance(value, dict):
                    raise ClientError("internal")
                ticket = value.get("ticket")
                if not _uuid(ticket):
                    raise ClientError("internal")
                endpoint = (self._probe.endpoint if self._probe else _endpoint)(
                    value.get("endpoint")
                )
            except OperationError as error:
                if not (
                    (error.status == 409 and not self._first_ready)
                    or error.status == 429
                    or (error.status is not None and error.status >= 500)
                ):
                    self._stop(error)
                    return
            except ClientError as error:
                if error.code not in ("unavailable", "deadline_exceeded"):
                    self._stop(error)
                    return
            except Exception:
                self._stop(ClientError("internal"))
                return
            else:
                try:
                    async with _Connect(
                        f"{endpoint}?ticket={ticket}",
                        proxy=None,
                        open_timeout=10,
                        close_timeout=1,
                        max_size=_MAX_BYTES,
                        compression=None,
                        logger=_LOG,
                    ) as socket:
                        current = _Connection(socket)
                        self._connection = current
                        self._connections_started += 1
                        recovery = self._recovery
                        if recovery is not None and recovery.complete:
                            recovery.connection = current
                        if await self._send(
                            current,
                            "subscribe",
                            cursor=(
                                recovery.cursor if recovery is not None else self._last
                            ),
                            subscription=self._id,
                        ):
                            backoff = 0.5
                            async for message in socket:
                                if isinstance(message, str) and self._probe:
                                    await self._probe.dispatch(
                                        message,
                                        partial(self._receive, current, message),
                                    )
                                else:
                                    await self._receive(current, message)
                                if not self._active:
                                    return
                except (OSError, TimeoutError, WebSocketException):
                    pass
                finally:
                    self._connection = None
                    self._queue.clear()
                    if self._active:
                        self._arm_budget()
                        self._changed.set()
            if self._active:
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 5)

    async def _renew(self, transport: _Authenticated) -> None:
        store = transport._store
        assert store is not None
        try:
            while self._active:
                credentials = store.credentials()
                if credentials is None:
                    raise ClientError("unauthenticated")
                due = datetime.fromisoformat(credentials.expires_at)
                await asyncio.sleep(
                    max(0, (due - datetime.now(timezone.utc)).total_seconds() - 60)
                )
                if not self._active:
                    return
                with store._locked():
                    current, generation = store._register()
                try:
                    if current == credentials:
                        await transport._owner._refresh(store, credentials, generation)
                        if store.credentials() == credentials:
                            raise ClientError("internal")
                finally:
                    store._release(generation)
        except ClientError as error:
            self._stop(error)
        except Exception:
            self._stop(ClientError("internal"))
