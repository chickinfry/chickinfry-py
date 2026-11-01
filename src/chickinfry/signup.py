from collections.abc import Callable, Mapping
from threading import Lock
from typing import TYPE_CHECKING, TypeVar

from .errors import ClientError
from .session import _read_credentials
from .wire import read_record, read_string

if TYPE_CHECKING:
    from ._sync_http import Transport
    from .http import AsyncTransport

# Match server trimming without importing the server authentication core.
_EMAIL_WHITESPACE = (
    "\t\n\v\f\r \u00a0\u1680"
    "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
    "\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_Output = TypeVar("_Output")


def _normalize_email(value: object) -> str:
    return read_string(value).strip(_EMAIL_WHITESPACE).lower()


class SignupBinding:
    """Bind required-verification requests to this client's pending signup."""

    def __init__(self) -> None:
        self._attempt: str | None = None
        self._email: str | None = None
        self._active_signups: dict[object, str] = {}
        self._lock = Lock()

    def _prepare(
        self, operation: str, payload: Mapping[str, object]
    ) -> tuple[dict[str, object], str | None, object | None]:
        result = dict(payload)
        target_operation = operation in {
            "auth.verify_email",
            "auth.send_verification_email",
        }
        if target_operation:
            if "email" in result and "attempt" in result:
                raise ClientError("invalid_argument")
        email: str | None = None
        signup: object | None = None
        with self._lock:
            if operation in {"auth.signup", "auth.signin"}:
                email = _normalize_email(result.get("email"))
                if operation == "auth.signup":
                    signup = object()
                    self._active_signups[signup] = email
            if target_operation:
                if (
                    "email" not in result
                    and "attempt" not in result
                    and self._attempt is not None
                ):
                    result["attempt"] = self._attempt
                if "email" not in result and "attempt" not in result:
                    raise ClientError("invalid_argument")
                if "email" in result:
                    email = _normalize_email(result["email"])
                elif result["attempt"] == self._attempt:
                    email = self._email
        return result, email, signup

    def _clear(self, email: str | None) -> None:
        with self._lock:
            if email is None or email == self._email:
                self._attempt = self._email = None
            self._active_signups = {
                request: pending_email
                for request, pending_email in self._active_signups.items()
                if email is not None and pending_email != email
            }

    def _accept(
        self, operation: str, response: object, email: str | None, signup: object | None
    ) -> None:
        if operation == "auth.signup":
            record = read_record(response)
            attempt = read_string(record.get("attempt"))
            if record.get("accepted") is not True or not attempt:
                raise ClientError("internal")
            with self._lock:
                if signup not in self._active_signups:
                    return
                self._attempt = attempt
                self._email = email
        elif operation in {"auth.verify_email", "auth.signin"}:
            _read_credentials(response)
            if email is not None:
                self._clear(email)
        elif operation == "auth.logout":
            read_string(read_record(response).get("status"))
            self._clear(None)

    def invoke(
        self,
        transport: "Transport",
        operation: str,
        payload: Mapping[str, object],
        decode: Callable[[object], _Output],
    ) -> _Output:
        """Invoke a synchronous SDK operation without changing its public result."""
        prepared, email, signup = self._prepare(operation, payload)
        try:
            response = transport.invoke(operation, prepared)
            output = decode(response)
            self._accept(operation, response, email, signup)
            return output
        finally:
            with self._lock:
                self._active_signups.pop(signup, None)

    async def invoke_async(
        self,
        transport: "AsyncTransport",
        operation: str,
        payload: Mapping[str, object],
        decode: Callable[[object], _Output],
    ) -> _Output:
        """Invoke an asynchronous SDK operation using the same signup binding."""
        prepared, email, signup = self._prepare(operation, payload)
        try:
            response = await transport.invoke(operation, prepared)
            output = decode(response)
            self._accept(operation, response, email, signup)
            return output
        finally:
            with self._lock:
                self._active_signups.pop(signup, None)
