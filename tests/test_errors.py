import re
import secrets
import string
from pathlib import Path

import pytest

from chickinfry import ClientError, OperationError
from chickinfry.errors import _MESSAGES


@pytest.mark.parametrize(
    "reason",
    [
        "invalid_origin",
        "invalid_operation",
        "invalid_input",
        "invalid_token",
        "invalid_session",
        "origin_mismatch",
        "invalid_timeout",
        "invalid_response",
        "request_too_large",
        "response_too_large",
        "timeout",
        "network_error",
        "unsupported_environment",
        "wrong_event_loop",
        "transport_closed",
    ],
)
def test_each_client_reason_has_an_actionable_sentence(reason: str) -> None:
    error = ClientError(reason, 503)
    assert error.reason == reason and error.status == 503
    message = str(error)
    assert message == _MESSAGES[reason]
    assert message.endswith(".") and message.count(".") == 1 and "; " in message
    assert reason not in message


@pytest.mark.parametrize(
    "code",
    [
        "conflict",
        "invalid_token",
        "invalid_response",
        "redirect_not_allowed",
        "operation_failed",
        "UPPER",
        "two-words",
        "123",
        "",
    ],
)
def test_operation_message_preserves_machine_code_and_status(code: str) -> None:
    error = OperationError(code, 409)
    expected = code if re.fullmatch(r"[a-z_]+", code) else "operation_failed"
    assert error.code == expected and error.reason == "operation_failed"
    assert error.status == 409
    message = str(error)
    assert message == _MESSAGES[error.reason]
    assert message.endswith(".") and message.count(".") == 1 and "; " in message
    assert "HTTP status" in message and "error code" in message


def test_error_messages_do_not_include_untrusted_values() -> None:
    token = "".join(secrets.choice(string.ascii_lowercase) for _ in range(64))
    values = [token, f"https://{token}.invalid", f'{{"password":"{token}"}}']
    for value in values:
        local = ClientError(value, 503)
        operation = OperationError(value, 409)
        assert local.reason == "network_error" and local.status == 503
        assert operation.code == (token if value == token else "operation_failed")
        assert operation.status == 409 and operation.reason == "operation_failed"
        visible = str(local) + repr(local) + str(operation) + repr(operation)
        assert all(secret not in visible for secret in values)
    for reason in _MESSAGES:
        error = (
            OperationError(token, 409)
            if reason == "operation_failed"
            else ClientError(reason)
        )
        assert all(secret not in str(error) + repr(error) for secret in values)


def test_worker_message_explains_next_available_environment() -> None:
    message = str(ClientError("unsupported_environment"))
    assert message == (
        "This client does not support Python Workers yet (support is planned); "
        "make calls from a regular Python process for now."
    )


def test_readme_uses_approved_preview_status() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    assert readme.splitlines()[2] == (
        "Status: not yet supported (preview). APIs may change before support is announced."
    )
