import logging
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from types import TracebackType

_active: ContextVar[bool] = ContextVar("chickinfry_request_logs", default=False)
_lock = threading.Lock()
_installed: Callable[..., logging.LogRecord] | None = None


def _install() -> None:
    global _installed
    with _lock:
        previous = logging.getLogRecordFactory()
        if previous is _installed:
            return

        def factory(
            name: str,
            level: int,
            pathname: str,
            lineno: int,
            msg: object,
            args: tuple[object, ...] | Mapping[str, object] | None,
            exc_info: tuple[type[BaseException], BaseException, TracebackType | None]
            | tuple[None, None, None]
            | None,
            func: str | None = None,
            sinfo: str | None = None,
            **kwargs: object,
        ) -> logging.LogRecord:
            if _active.get() and name.split(".", 1)[0] in {"httpx", "httpcore", "h11"}:
                # Sanitize contextual logs before outer factories or handlers see the raw exception.
                msg, args, exc_info, sinfo = (
                    "Chickinfry request transport event",
                    (),
                    None,
                    None,
                )
            return previous(
                name,
                level,
                pathname,
                lineno,
                msg,
                args,
                exc_info,
                func,
                sinfo,
                **kwargs,
            )

        logging.setLogRecordFactory(factory)
        _installed = factory


@contextmanager
def _request_logs() -> Iterator[None]:
    _install()
    token = _active.set(True)
    try:
        yield
    finally:
        _active.reset(token)
