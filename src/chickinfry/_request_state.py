import threading
from contextvars import ContextVar


class _RequestState:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._sending = False
        self._finished = False

    def trace(self, event: str, info: dict[str, object]) -> None:
        if event.endswith(".send_request_headers.started"):
            with self._lock:
                self._sending = True

    async def atrace(self, event: str, info: dict[str, object]) -> None:
        self.trace(event, info)

    def finish(self) -> None:
        with self._lock:
            self._finished = True

    @property
    def outcome_unknown(self) -> bool:
        # Failures after header writes begin may have sent partial output; only completion is certain.
        with self._lock:
            return self._sending and not self._finished


_state: ContextVar[_RequestState | None] = ContextVar(
    "chickinfry_request_state", default=None
)
