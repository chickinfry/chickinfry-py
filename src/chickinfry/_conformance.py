import json
import re
from collections.abc import Iterable
from contextvars import ContextVar
from dataclasses import dataclass, field

from .errors import _MESSAGES, ClientError


@dataclass(repr=False)
class _Observation:
    deadline: float
    status: int | None = None
    details: list[str] = field(default_factory=list)
    body_checked: bool = False

    def _detail(self, value: str) -> None:
        self.details.append(value)
        self.details.extend(re.findall(r"[\w]+(?:[./:+-][\w]+)*", value))

    def record_headers(self, status: int, values: Iterable[str]) -> None:
        self.status = status
        self.body_checked = False
        for value in values:
            self._detail(value)

    def record_body(self, data: bytes) -> None:
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
        while pending:
            current, depth = pending.pop()
            if id(current) in seen:
                continue
            if depth >= 32 or len(seen) >= 32:
                return None
            seen.add(id(current))
            visible = list(getattr(current, "__notes__", ()))
            if isinstance(current, BaseExceptionGroup):
                visible.append(current.message)
            # Only an unchanged diagnostic argument is known to be safe.
            elif not (
                isinstance(current, ClientError)
                and current.args == (_MESSAGES[current.reason],)
            ):
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
            return None
        return False if isinstance(error, ClientError) else None


_observer: ContextVar[_Observation | None] = ContextVar(
    "chickinfry_conformance_observer", default=None
)
