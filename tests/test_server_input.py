import json
from collections.abc import Mapping

import pytest

from chickinfry.server import MAX_REQUEST_BYTES, Application, Operation, OperationError

from .test_server_dispatch import BytesRequest, Probe


async def test_initial_budget_overflow_without_inserting_defaults(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chickinfry import _input

    body = b'{"wire_value":"ok","ignored":1e5}'
    monkeypatch.setattr(_input, "MAX_REQUEST_BYTES", len(body))
    probe = Probe()

    def decode(value: Mapping[str, object]) -> str:
        budget = _input.InputBudget(value)
        return _input.read_string(
            _input.read_field(value, "wire_value", budget, '"default"')
        )

    app = Application(
        {"probe.echo": Operation(decode, probe.invoke, lambda x: {})}, probe.open
    )
    response = await app.fetch(BytesRequest([body]))
    assert response.status == 413
    assert json.loads(response.body) == {"error": "request_too_large"}
    assert probe.calls == probe.opened == 0


@pytest.mark.parametrize(
    "ignored", [{"ignored": "\ud800"}, {"\ud800": "ignored"}, {"ignored": "\udfff"}]
)
async def test_ignored_surrogate_strings_keep_existing_acceptance(
    ignored: dict[str, str],
) -> None:
    from chickinfry import _input

    probe = Probe()

    def decode(value: Mapping[str, object]) -> str:
        budget = _input.InputBudget(value)
        return _input.read_string(_input.read_field(value, "wire_value", budget))

    app = Application(
        {"probe.echo": Operation(decode, probe.invoke, lambda x: {})}, probe.open
    )
    response = await app.fetch(
        BytesRequest([json.dumps({"wire_value": "ok", **ignored}).encode()])
    )
    assert response.status == 200
    assert probe.calls == probe.opened == 1


def test_overflow_is_checked_before_default_materialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chickinfry import _input

    budget = _input.InputBudget({})
    literal = '"' + "x" * MAX_REQUEST_BYTES + '"'
    calls: list[str] = []

    def decode(value: str) -> object:
        calls.append(value)
        return value

    monkeypatch.setattr(json, "loads", decode)
    with pytest.raises(OperationError) as error:
        _input.read_field({}, "large", budget, literal)
    assert (error.value.code, error.value.status) == ("request_too_large", 413)
    assert calls == []


def test_missing_present_and_fresh_nested_defaults() -> None:
    from chickinfry._input import (
        InputBudget,
        read_field,
        read_list,
        read_nullable,
        read_record,
        read_string,
    )

    literal = '[{"name":"original","children":[]}]'
    first: dict[str, object] = {}
    budget = InputBudget(first)
    value = read_field(first, "items", budget, literal)
    items = read_list(value, read_record)
    assert read_string(items[0]["name"]) == "original"
    assert first == {}
    assert read_field({"name": ""}, "name", budget, '"default"') == ""
    assert read_field({"name": None}, "name", budget, '"default"') is None
    assert read_nullable(None, read_string) is None
    assert read_nullable("", read_string) == ""
    with pytest.raises(ValueError):
        read_field({}, "required", budget)
    with pytest.raises(ValueError):
        read_string(None)
    items[0]["name"] = "changed"
    items[0]["children"] = ["changed"]
    assert read_field({}, "items", InputBudget({}), literal) == [
        {"name": "original", "children": []}
    ]
    malformed_values: tuple[object, ...] = ({}, (), "", [None], [{}, None])
    for malformed in malformed_values:
        with pytest.raises(ValueError):
            read_list(malformed, read_record)


@pytest.mark.parametrize("offset,status", [(-1, 200), (0, 200), (1, 413)])
async def test_default_budget_and_413_dispatch(offset: int, status: int) -> None:
    from chickinfry._input import InputBudget, read_field, read_string
    from chickinfry.server import MAX_REQUEST_BYTES

    probe = Probe()
    literal = json.dumps("\ud55c🎉", ensure_ascii=False)
    fixed = len('{"wire_value":"","a":"\ud55c🎉","b":""}'.encode())
    payload = {"wire_value": "x" * (MAX_REQUEST_BYTES - fixed + offset)}

    def decode(value: Mapping[str, object]) -> str:
        budget = InputBudget(value)
        assert read_field(value, "a", budget, literal) == "\ud55c🎉"
        assert read_field(value, "b", budget, '""') == ""
        return read_string(value["wire_value"])

    app = Application(
        {"probe.echo": Operation(decode, probe.invoke, lambda x: {})}, probe.open
    )
    response = await app.fetch(BytesRequest([json.dumps(payload).encode()]))
    assert response.status == status
    assert probe.calls == probe.opened == (1 if status == 200 else 0)
    if status == 413:
        assert json.loads(response.body) == {"error": "request_too_large"}


def test_nested_default_budget_counts_each_insertion_once() -> None:
    from chickinfry._input import InputBudget, read_field, read_list, read_record
    from chickinfry.server import MAX_REQUEST_BYTES

    root: dict[str, object] = {}
    budget = InputBudget(root)
    items = read_list(read_field(root, "items", budget, '[{"child":"x"}]'), read_record)
    before = budget.size
    assert read_field(items[0], "child", budget, '"x"') == "x"
    assert budget.size == before == len(b'{"items":[{"child":"x"}]}')
    budget.size = MAX_REQUEST_BYTES
    with pytest.raises(OperationError) as error:
        read_field(items[0], "other", budget, '"x"')
    assert (error.value.code, error.value.status) == ("request_too_large", 413)


@pytest.mark.parametrize(
    "code,status",
    [("permission_denied", 403), ("request_too_large", 400), ("other", 413)],
)
async def test_decoder_does_not_promote_unrelated_server_errors(
    code: str, status: int
) -> None:
    probe = Probe()

    def decode(value: Mapping[str, object]) -> str:
        raise OperationError(code, status)

    app = Application(
        {"probe.echo": Operation(decode, probe.invoke, lambda x: {})}, probe.open
    )
    response = await app.fetch(BytesRequest([b"{}"]))
    assert response.status == 400
    assert json.loads(response.body) == {"error": "invalid_input"}
    assert probe.calls == probe.opened == 0
