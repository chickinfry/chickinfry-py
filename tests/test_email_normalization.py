import hashlib
import itertools
import json
import random
import re
from pathlib import Path

import pytest

from chickinfry import auth
from chickinfry.auth import normalize_email
from chickinfry.server import ServerError

# Source: chickinfry/chickinfry auth/testdata/emails.json at
# 1365d4ca9e962b87374741417fefb50ae665b915.
_CORPUS_BYTES = (Path(__file__).parent / "testdata" / "emails.json").read_bytes()
assert hashlib.sha256(_CORPUS_BYTES).hexdigest() == (
    "26e5f184b31eca32b1cbac279fb59d9042610ec15ef92f13bbf5f595ff809595"
), "Email corpus SHA-256 mismatch"
_EMAIL_CASES: dict[str, dict[str, str]] = {
    case["name"]: case for case in json.loads(_CORPUS_BYTES)
}


@pytest.mark.parametrize("name", _EMAIL_CASES)
def test_email_normalization_corpus(name: str) -> None:
    case = _EMAIL_CASES[name]
    try:
        normalized = normalize_email(case["input"])
    except ServerError as error:
        if case.get("error") != error.code or error.status != 400:
            pytest.fail(name, pytrace=False)
    else:
        if "normalized" not in case or normalized != case["normalized"]:
            pytest.fail(name, pytrace=False)


def test_email_format_matches_previous_regex() -> None:
    whitespace = (
        "\t\n\v\f\r \u00a0\u1680"
        "\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a"
        "\u2028\u2029\u202f\u205f\u3000\ufeff"
    )
    previous = re.compile(rf"[^{whitespace}@]+@[^{whitespace}@]+\.[^{whitespace}@]+")

    def compare(value: str, name: str) -> None:
        if auth._valid_email_format(value) != (previous.fullmatch(value) is not None):
            pytest.fail(name, pytrace=False)

    for length in range(7):
        for index, characters in enumerate(
            itertools.product("a@. \u0085", repeat=length)
        ):
            compare("".join(characters), f"exhaustive_{length}_{index}")

    randomizer = random.Random(238)
    alphabet = "a@.\0\u0085\u180e\u200b\u0301\ud800\udfff\U0001f600" + whitespace
    for index in range(10_000):
        parts = [
            "".join(randomizer.choices(alphabet, k=randomizer.randrange(25)))
            for _ in range(3)
        ]
        compare("".join(parts), f"unstructured_{index}")
        compare(parts[0] + "@" + parts[1] + "." + parts[2], f"structured_{index}")


def test_email_length_rejects_before_format_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def check_format(value: str) -> bool:
        nonlocal calls
        calls += 1
        return False

    monkeypatch.setattr(auth, "_valid_email_format", check_format)
    # Moving the format check before the length guard must fail without running a regex.
    value = "a@" + "." * 100_000 + " a"
    with pytest.raises(ServerError) as caught:
        normalize_email(value)
    assert caught.value.code == "invalid_input"
    assert caught.value.status == 400
    assert calls == 0
