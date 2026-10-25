"""Each mutation removes one distinct input safety guarantee."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "module,original,mutation",
    [
        ("_input.py", "if key in record:", "if record.get(key):"),
        (
            "_input.py",
            "return cast(object, json.loads(literal))",
            "return _defaults.setdefault(literal, json.loads(literal))",
        ),
        ("_input.py", "if self.size > MAX_REQUEST_BYTES:", "if False:"),
        (
            "_input.py",
            "        self._check()\n        self._counts[id(record)] = (record, count + 1)\n        return cast(object, json.loads(literal))",
            "        decoded = json.loads(literal)\n        self._check()\n        self._counts[id(record)] = (record, count + 1)\n        return cast(object, decoded)",
        ),
        (
            "_input.py",
            '"utf-8", errors="backslashreplace"',
            '"utf-8", errors="strict"',
        ),
        (
            "server.py",
            'if error.code == "request_too_large" and error.status == 413:',
            "if False:",
        ),
        (
            "_input.py",
            "return [decode(item) for item in value]",
            "return [decode(item) for item in value if isinstance(item, dict)]",
        ),
    ],
    ids=[
        "presence",
        "fresh-default",
        "budget",
        "clone-before-budget",
        "ignored-surrogates",
        "413-envelope",
        "list-atomicity",
    ],
)
def test_server_input_mutation_is_detected(
    module: str, original: str, mutation: str, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    for name in ("src", "tests"):
        shutil.copytree(
            ROOT / name, source / name, ignore=shutil.ignore_patterns("__pycache__")
        )
    shutil.copyfile(ROOT / "pyproject.toml", source / "pyproject.toml")
    path = source / "src/chickinfry" / module
    text = path.read_text()
    expected_count = 3 if 'errors="strict"' in mutation else 1
    assert text.count(original) == expected_count, "The input mutation point changed"
    if "_defaults" in mutation:
        text = text.replace(
            'T = TypeVar("T")', 'T = TypeVar("T")\n_defaults: dict[str, object] = {}'
        )
    path.write_text(text.replace(original, mutation))
    environment = {
        key: os.environ[key]
        for key in ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL")
        if key in os.environ
    }
    environment["PYTHONPATH"] = str(source / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_server_input.py",
            "-q",
            "--tb=short",
        ],
        cwd=source,
        env=environment,
        capture_output=True,
        timeout=60,
    )
    output = result.stdout.decode("utf-8", "replace")
    (tmp_path / "mutation-output.txt").write_text(output)
    assert result.returncode == 1 and "FAILED" in output, (
        "The mutation escaped its assertion"
    )
    assert "ERROR collecting" not in output, (
        "The mutation did not reach the input tests"
    )
