import re

from ._error_details import FieldError as FieldError
from ._error_details import _fields, _message

_MESSAGES = {
    "device_storage_unavailable": "Could not use device storage for the session. Check that the storage location is writable, or set persist to another directory or turn it off.",
    "device_storage_corrupt": "Stored session data could not be read. Sign out to clear it, then sign in again.",
    "device_storage_full": "Device storage for sign-in is full. Finish or cancel pending sign-ups, then try again.",
    "device_storage_version_unsupported": "Stored session data was written by a newer SDK. Update the SDK, or sign out and sign in again.",
    "invalid_origin": "The server address is invalid; use an HTTPS origin or an explicit IP loopback HTTP origin without a path, query, or fragment.",
    "invalid_operation": "The operation name is invalid; use the operation name defined by your generated client.",
    "invalid_input": "The request data is invalid; provide JSON-compatible values or valid UTF-8 JSON bytes.",
    "invalid_token": "The authentication token is invalid; sign in again and use the newly issued credentials.",
    "invalid_session": "The session cannot be used by this client; use valid credentials in a separate session store for the selected transport and event loop.",
    "origin_mismatch": "The session belongs to a different server origin; use a session store created for the same origin as this client.",
    "invalid_timeout": "The timeout is invalid; set it to a positive finite number of seconds.",
    "invalid_response": "The server response is invalid; check that the server and generated client use the same API contract.",
    "request_too_large": "The request exceeds the 4 MiB limit; reduce the request size before making another call.",
    "response_too_large": "The response exceeds the 1 MiB limit; request less data or reduce the server's response size.",
    "timeout": "The request exceeded its time limit; check the server's state before making another call.",
    "network_error": "The request could not complete because of a network failure; check your connection and the server's state before making another call.",
    "unsupported_environment": "This client does not support Python Workers yet (support is planned); make calls from a regular Python process for now.",
    "wrong_event_loop": "The async client belongs to a different event loop; create and use the client on the same event loop.",
    "transport_closed": "The client is closed; create a new client before making another call.",
    "operation_failed": "The operation failed; check the error code and HTTP status, then resolve the reported problem before making another call.",
}
_REASONS = frozenset(_MESSAGES) - {"operation_failed"}


class ClientError(Exception):
    """A local failure with a safe reason and optional received HTTP status."""

    def __init__(self, reason: str, status: int | None = None) -> None:
        self.reason = reason if reason in _REASONS else "network_error"
        self.status = status
        self._outcome_unknown = False
        super().__init__(_MESSAGES[self.reason])


class OperationError(ClientError):
    """A server operation failure retaining its wire code and HTTP status."""

    def __init__(
        self,
        code: str,
        status: int,
        message: str | None = None,
        fields: tuple[FieldError, ...] = (),
    ) -> None:
        self.code = code if re.fullmatch(r"[a-z_]+", code) else "operation_failed"
        self.reason = "operation_failed"
        self.status = status
        self.response_message = _message(message)
        self.fields = _fields(fields) if self.code == "invalid_input" else ()
        self._outcome_unknown = False
        self._valid_error_envelope = True
        Exception.__init__(self, _MESSAGES[self.reason])
