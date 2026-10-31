import json
import re
import secrets
import string
from pathlib import Path

import pytest

from chickinfry import ClientError, OperationError
from chickinfry._http_common import _response
from chickinfry.errors import _CODES, _MESSAGES, _storage_error
from chickinfry.server import FieldError
from chickinfry.session import _Failure


@pytest.mark.parametrize("code", sorted(_CODES))
def test_each_client_code_has_an_actionable_sentence(code: str) -> None:
    error = ClientError(code, 503)
    assert error.code == code and error.status == 503
    message = str(error)
    assert message == _MESSAGES[code]
    assert message.endswith(".") and message.count(".") == 1 and "; " in message


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
    assert error.code == expected
    assert error.status == 409
    message = str(error)
    assert message == _MESSAGES["operation_failed"]
    assert message.endswith(".") and message.count(".") == 1 and "; " in message
    assert "HTTP status" in message and "error code" in message


def test_error_messages_do_not_include_untrusted_values() -> None:
    token = "".join(secrets.choice(string.ascii_lowercase) for _ in range(64))
    values = [token, f"https://{token}.invalid", f'{{"password":"{token}"}}']
    for value in values:
        local = ClientError(value, 503)
        operation = OperationError(value, 409)
        assert local.code == "unknown" and local.status == 503
        assert operation.code == (token if value == token else "operation_failed")
        assert operation.status == 409
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
    message = str(ClientError("unimplemented"))
    assert message == (
        "This client does not support Python Workers yet (support is planned); "
        "make calls from a regular Python process for now."
    )


def test_readme_uses_approved_preview_status() -> None:
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    assert readme.splitlines()[2] == (
        "Status: not yet supported (preview). APIs may change before support is announced."
    )


@pytest.mark.parametrize(
    "body,message,fields",
    [
        ({"error": "conflict"}, None, ()),
        ({"error": "conflict", "message": None, "fields": None}, None, ()),
        ({"error": "conflict", "message": "", "fields": []}, "", ()),
        (
            {
                "error": "invalid_input",
                "message": "Safe",
                "fields": [{"path": "quantity", "code": "too_large"}],
            },
            "Safe",
            (FieldError("quantity", "too_large"),),
        ),
        (
            {
                "error": "invalid_input",
                "message": "bad\n",
                "fields": [{"path": "quantity", "code": "too_large"}],
            },
            None,
            (FieldError("quantity", "too_large"),),
        ),
        (
            {
                "error": "invalid_input",
                "message": "Safe",
                "fields": [
                    {"path": "quantity", "code": "ok"},
                    {"path": "bad[01]", "code": "bad"},
                ],
            },
            "Safe",
            (),
        ),
        (
            {
                "error": "invalid_input",
                "message": "Safe",
                "fields": [{"path": "items[4294967295].quantity", "code": "required"}],
            },
            "Safe",
            (FieldError("items[4294967295].quantity", "required"),),
        ),
        (
            {
                "error": "invalid_input",
                "fields": [{"path": "items[4294967296].quantity", "code": "required"}],
            },
            None,
            (),
        ),
        (
            {
                "error": "conflict",
                "fields": [{"path": "quantity", "code": "too_large"}],
            },
            None,
            (),
        ),
        ({"error": "x" * 65, "message": "Safe"}, "Safe", ()),
    ],
)
def test_received_error_details(
    body: dict[str, object], message: str | None, fields: tuple[FieldError, ...]
) -> None:
    with pytest.raises(OperationError) as caught:
        _response(json.dumps(body).encode(), 422)
    error = caught.value
    assert error.code == body["error"] and error.status == 422
    assert error.response_message == message and error.fields == fields
    assert str(error) == _MESSAGES["operation_failed"]
    assert "Safe" not in str(error) + repr(error)


def test_session_failure_snapshot_preserves_details_and_uncertainty() -> None:
    with pytest.raises(OperationError) as caught:
        _response(
            b'{"error":"invalid_input","message":"Safe","fields":[{"path":"quantity","code":"required"}]}',
            422,
        )
    original = caught.value
    original._outcome_unknown = True
    reconstructed = _Failure.from_error(original).error()
    assert isinstance(reconstructed, OperationError)
    assert reconstructed.code == "invalid_input" and reconstructed.status == 422
    assert reconstructed.response_message == "Safe"
    assert reconstructed.fields == (FieldError("quantity", "required"),)
    assert reconstructed._outcome_unknown and reconstructed._valid_error_envelope
    assert "Safe" not in str(reconstructed) + repr(reconstructed)


def test_local_failure_uses_common_code_without_reason_alias() -> None:
    error = ClientError("invalid_argument")
    assert error.code == "invalid_argument"
    assert error.status is None
    assert not hasattr(error, "reason")
    assert ClientError("unrecognized").code == "unknown"
    assert ClientError("invalid_origin").code == "unknown"
    for failure in (
        ClientError("failed_precondition"),
        _storage_error("failed_precondition"),
    ):
        restored = _Failure.from_error(failure).error()
        assert type(restored) is ClientError
        assert restored.code == "failed_precondition"
        assert restored._storage_failure == failure._storage_failure
        assert str(restored) == str(failure)


@pytest.mark.parametrize(
    "code,reason",
    [
        ("invalid_argument", "invalid_origin"),
        ("invalid_argument", "invalid_operation"),
        ("invalid_argument", "invalid_input"),
        ("invalid_argument", "invalid_token"),
        ("invalid_argument", "invalid_timeout"),
        ("failed_precondition", "invalid_session"),
        ("failed_precondition", "origin_mismatch"),
        ("failed_precondition", "wrong_event_loop"),
        ("failed_precondition", "transport_closed"),
        ("resource_exhausted", "request_too_large"),
        ("resource_exhausted", "response_too_large"),
        ("deadline_exceeded", "timeout"),
        ("unavailable", "network_error"),
        ("unimplemented", "unsupported_environment"),
        ("internal", "invalid_response"),
    ],
)
def test_each_client_reason_has_an_actionable_sentence(code: str, reason: str) -> None:
    from chickinfry.errors import _local_error

    error = _local_error(code, reason, 503)
    assert error.code == code and error.status == 503
    message = str(error)
    assert message == _MESSAGES[reason]
    assert message.endswith(".") and message.count(".") == 1 and "; " in message
    assert reason not in message
