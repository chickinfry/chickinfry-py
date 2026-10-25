import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from chickinfry._input import InputBudget, read_field, read_string
from chickinfry.server import MAX_REQUEST_BYTES, Application, Operation

from .test_server_dispatch import BytesRequest, Probe


def test_compact_budget_matches_javascript_oracle() -> None:
    vectors = json.loads(
        (Path(__file__).parent / "testdata/input-budget-vectors.json").read_text()
    )
    for case in vectors["cases"]:
        assert InputBudget(json.loads(case["raw"])).size == case["bytes"], case["name"]


@pytest.mark.parametrize("literal", ["1e-7", "1e20"])
async def test_numeric_unknown_keys_preserve_shared_budget_decision(
    literal: str,
) -> None:
    probe = Probe()
    default = '"default"'
    prefix = b'{"wire_value":"'
    suffix = b'","ignored":' + literal.encode() + b"}"
    expected = 200 if literal == "1e-7" else 413
    if expected == 200:
        suffix = b'","ignored":1e-7,"default":"present"}'
        padding = MAX_REQUEST_BYTES - len(prefix) - len(suffix)
    else:
        # JavaScript expands 1e20 to 21 integer digits before inserting the default.
        compact_overhead = len(prefix) + len(b'","ignored":100000000000000000000}')
        insertion = len(b',"default":"default"')
        padding = MAX_REQUEST_BYTES + 1 - compact_overhead - insertion
    body = prefix + b"x" * padding + suffix
    assert len(body) <= MAX_REQUEST_BYTES

    def decode(value: Mapping[str, object]) -> str:
        budget = InputBudget(value)
        read_string(read_field(value, "default", budget, default))
        return read_string(value["wire_value"])

    app = Application(
        {"probe.echo": Operation(decode, probe.invoke, lambda _: {})}, probe.open
    )
    response = await app.fetch(BytesRequest([body]))
    assert response.status == expected
    assert probe.calls == probe.opened == (1 if expected == 200 else 0)
    if expected == 413:
        assert json.loads(response.body) == {"error": "request_too_large"}
