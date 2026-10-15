import json
import re
from collections.abc import Awaitable, Callable, Iterable
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from .errors import _MESSAGES, ClientError, OperationError

if TYPE_CHECKING:
    from ._request_state import _RequestState
    from .session import SessionCredentials


class _HookError(Exception):
    pass


@dataclass(repr=False)
class _ClearAttempt:
    call_id: str
    expected: "SessionCredentials"
    removed: bool


@dataclass(repr=False)
class _Observation:
    deadline: float
    status: int | None = None
    details: list[str] = field(default_factory=list)
    body_checked: bool = False
    call_id: str = ""
    barrier: Callable[[str, dict[str, object]], None] | None = None
    async_barrier: Callable[[str, dict[str, object]], Awaitable[None]] | None = None
    flight: object | None = None
    flight_ref: Callable[[object], str] | None = None
    hook_failed: bool = False
    transport: Callable[[str, object], None] | None = None
    refusal: str | None = None
    sealed: bool = False

    def release(self) -> None:
        self.sealed = True
        self.details.clear()
        self.barrier = None
        self.async_barrier = None
        self.flight = None
        self.flight_ref = None

    def notify(self, point: str, value: object = None) -> None:
        if self.transport is not None:
            try:
                self.transport(point, value)
            except Exception:
                self.hook_failed = True
                raise _HookError() from None

    def arrive(self, point: str, facts: dict[str, object]) -> None:
        if self.barrier is not None:
            try:
                self.barrier(point, facts)
            except Exception:
                self.hook_failed = True
                raise _HookError() from None

    async def aarrive(self, point: str, facts: dict[str, object]) -> None:
        if self.async_barrier is not None:
            try:
                await self.async_barrier(point, facts)
            except Exception:
                self.hook_failed = True
                raise _HookError() from None

    def trace(
        self,
        state: "_RequestState",
        event: str,
        info: dict[str, object],
        *,
        refresh: bool = True,
    ) -> None:
        state.trace(event, info)
        self.notify("trace", (event, info))
        if (
            refresh
            and self.flight is not None
            and self.flight_ref is not None
            and event.endswith(".receive_response_headers.started")
        ):
            self.arrive("refresh-joined", {"refreshRef": self.flight_ref(self.flight)})

    async def atrace(
        self,
        state: "_RequestState",
        event: str,
        info: dict[str, object],
        *,
        refresh: bool = True,
    ) -> None:
        state.trace(event, info)
        self.notify("trace", (event, info))
        if (
            refresh
            and self.flight is not None
            and self.flight_ref is not None
            and event.endswith(".receive_response_headers.started")
        ):
            await self.aarrive(
                "refresh-joined", {"refreshRef": self.flight_ref(self.flight)}
            )

    def _detail(self, value: str) -> None:
        if self.sealed:
            return
        self.details.append(value)
        self.details.extend(re.findall(r"[\w]+(?:[./:+-][\w]+)*", value))

    def record_headers(self, status: int, values: Iterable[str]) -> None:
        self.status = status
        self.body_checked = False
        self.refusal = None
        for value in values:
            self._detail(value)

    def record_body(self, data: bytes) -> None:
        if self.sealed:
            return
        text = data.decode("utf-8", "replace")
        self.details.append(text)
        try:
            value: object = json.loads(data)
        except (ValueError, UnicodeError, RecursionError):
            self._detail(text)
            self.body_checked = True
            return
        pending = [value]
        while pending:
            value = pending.pop()
            if isinstance(value, str):
                self._detail(value)
            elif isinstance(value, (int, float)):
                self._detail(str(value))
            elif isinstance(value, dict):
                pending.extend(value.values())
            elif isinstance(value, list):
                pending.extend(value)
        self.body_checked = True

    def raw_details(self, error: Exception) -> bool | None:
        seen: set[int] = set()
        pending: list[tuple[BaseException, int]] = [(error, 0)]
        fixed = True
        while pending:
            current, depth = pending.pop()
            if id(current) in seen:
                continue
            if depth >= 32 or len(seen) >= 32:
                return None
            seen.add(id(current))
            visible = list(getattr(current, "__notes__", ()))
            if visible:
                fixed = False
            if isinstance(current, BaseExceptionGroup):
                fixed = False
                visible.append(current.message)
            # Only an unchanged diagnostic argument is known to be safe.
            elif not (
                isinstance(current, ClientError)
                and type(current) in (ClientError, OperationError)
                and len(current.args) == 1
                and type(current.args[0]) is str
                and current.args == (_MESSAGES[current.reason],)
            ):
                fixed = False
                visible.extend(
                    (
                        str(current),
                        repr(current).removeprefix(type(current).__name__ + "("),
                    )
                )
            # Even short response values must fail closed in every visible error.
            if any(
                detail.strip() and any(detail in text for text in visible)
                for detail in self.details
            ):
                return True
            if isinstance(current, BaseExceptionGroup):
                pending.extend((child, depth + 1) for child in current.exceptions)
            cause = current.__cause__ or (
                None if current.__suppress_context__ else current.__context__
            )
            if cause is not None:
                pending.append((cause, depth + 1))
        if self.status is not None and not self.body_checked:
            if (
                fixed
                and not getattr(error, "__notes__", ())
                and isinstance(error, ClientError)
                and self.refusal == getattr(error, "code", error.reason)
            ):
                return False
            return None
        return False if isinstance(error, ClientError) else None


_observer: ContextVar[_Observation | None] = ContextVar(
    "chickinfry_conformance_observer", default=None
)
