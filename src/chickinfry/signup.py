from collections.abc import Mapping
from threading import Lock
from typing import TYPE_CHECKING

from .errors import ClientError
from .session import _read_credentials
from .wire import read_record, read_string

if TYPE_CHECKING:
    from ._sync_http import Transport
    from .http import AsyncTransport


class SignupBinding:
    """Bind required-verification requests to this client's pending signup."""

    def __init__(self) -> None:
        self._attempt: str | None = None
        self._lock = Lock()

    def _prepare(
        self, operation: str, payload: Mapping[str, object]
    ) -> dict[str, object]:
        result = dict(payload)
        if operation in {"auth.verify_email", "auth.send_verification_email"}:
            if "email" in result and "attempt" in result:
                raise ClientError("invalid_argument")
            with self._lock:
                if (
                    "email" not in result
                    and "attempt" not in result
                    and self._attempt is not None
                ):
                    result["attempt"] = self._attempt
            if "email" not in result and "attempt" not in result:
                raise ClientError("invalid_argument")
        return result

    def _accept(
        self, operation: str, payload: Mapping[str, object], response: object
    ) -> None:
        if operation == "auth.signup":
            record = read_record(response)
            attempt = read_string(record.get("attempt"))
            if record.get("accepted") is not True or not attempt:
                raise ClientError("internal")
            with self._lock:
                self._attempt = attempt
        elif operation == "auth.verify_email":
            _read_credentials(response)
            with self._lock:
                if payload.get("attempt") == self._attempt:
                    self._attempt = None

    def invoke(
        self, transport: "Transport", operation: str, payload: Mapping[str, object]
    ) -> object:
        """Invoke a synchronous SDK operation without changing its public result."""
        prepared = self._prepare(operation, payload)
        response = transport.invoke(operation, prepared)
        self._accept(operation, prepared, response)
        return response

    async def invoke_async(
        self, transport: "AsyncTransport", operation: str, payload: Mapping[str, object]
    ) -> object:
        """Invoke an asynchronous SDK operation using the same signup binding."""
        prepared = self._prepare(operation, payload)
        response = await transport.invoke(operation, prepared)
        self._accept(operation, prepared, response)
        return response
