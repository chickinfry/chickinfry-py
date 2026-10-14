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
        visible: tuple[str, ...] = (
            str(error),
            repr(error).removeprefix(type(error).__name__ + "("),
        )
        # Only an unchanged diagnostic argument is known to be safe.
        if isinstance(error, ClientError) and error.args == (_MESSAGES[error.reason],):
            visible = ()
        # Even short response values must fail closed when they appear in an error.
        if any(
            detail.strip() and any(detail in text for text in visible)
            for detail in self.details
        ):
            return True
        if self.status is not None and not self.body_checked:
            return None
        return False if isinstance(error, ClientError) else None


_observer: ContextVar[_Observation | None] = ContextVar(
    "chickinfry_conformance_observer", default=None
)
