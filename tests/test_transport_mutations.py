"""Run one observation defect at a time in a private source copy."""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    "role,environment,status",
    [
        ("h11", "sync", 302),
        ("h11", "async", 302),
        ("queue", "async", 302),
        ("sdk", "sync", 200),
        ("sdk", "async", 200),
        ("finish", "sync", 200),
        ("finish", "async", 200),
        ("httpx", "sync", 302),
        ("httpx", "async", 302),
        ("peak", "sync", 302),
        ("peak", "async", 302),
        ("identity", "sync", 200),
    ],
)
def test_missing_storage_is_a_numeric_census_failure(
    role: str, environment: str, status: int, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    for name in ("src", "tests", "conformance"):
        shutil.copytree(
            ROOT / name,
            source / name,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    shutil.copyfile(ROOT / "pyproject.toml", source / "pyproject.toml")
    path = source / "conformance/driver/transport.py"
    text = path.read_text()
    if role == "identity":
        original = "                storage.pop(id(value), None)"
        mutation = "                pass"
    elif role == "peak":
        original = "self.peak = max(self.peak, self.retained)"
        mutation = "self.peak = self.retained"
    else:
        original = "self.retained = sum(count for _, count in storage.values())"
        mutation = (
            "self.retained = sum(count for role, count in storage.values() "
            f"if role != {role!r})"
        )
    assert text.count(original) == 1, "The accounting mutation point changed"
    path.write_text(text.replace(original, mutation))
    environment_values = {**os.environ, "PYTHONPATH": str(source / "src")}
    node = f"tests/test_transport_census.py::test_live_redirect_byte_census[False-{status}-8191-{environment}]"
    if role == "httpx":
        node = f"tests/test_transport_census.py::test_httpx_completed_store_census[{environment}]"
    elif role == "identity":
        node = "tests/test_transport_census.py::test_reused_body_copy_identity_updates_the_current_census[plain]"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            node,
            "-q",
            "--tb=short",
            "--basetemp=" + str(tmp_path / "pytest"),
            "-p",
            "no:cacheprovider",
        ],
        cwd=source,
        env=environment_values,
        capture_output=True,
        timeout=90,
    )
    output = result.stdout.decode("utf-8", "replace")
    (tmp_path / "mutation-output.txt").write_text(output)
    assert result.returncode == 1, "The mutation did not reach its expected assertion"
    if role == "peak":
        mismatch = re.search(
            r"peak byte mismatch: reported=(\d+), census=(\d+)", output
        )
        assert mismatch is not None, "No exact peak mismatch was reported"
        assert int(mismatch[2]) > int(mismatch[1])
    else:
        mismatch = re.search(
            r"retained byte mismatch: reported=(\d+), census=(\d+), delta=(-?\d+)",
            output,
        )
        assert mismatch is not None, "No exact retained-byte mismatch was reported"
        assert int(mismatch[2]) - int(mismatch[1]) == int(mismatch[3])
        if role == "identity":
            assert int(mismatch[3]) == -57195, "The stale first-chunk count changed"
        else:
            assert int(mismatch[3]) in {4093, 8191}, (
                "The omitted positive storage changed"
            )


@pytest.mark.parametrize("environment", ["python-sync", "python-async"])
def test_cancel_then_raw_read_mutation_is_detected(
    environment: str, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    for name in ("src", "tests", "conformance"):
        shutil.copytree(
            ROOT / name,
            source / name,
            ignore=shutil.ignore_patterns("__pycache__"),
        )
    shutil.copyfile(ROOT / "pyproject.toml", source / "pyproject.toml")
    path = (
        source
        / "src/chickinfry"
        / ("_sync_http.py" if environment == "python-sync" else "http.py")
    )
    original = 'observation.notify("redirect", response)'
    read = (
        "next(response.iter_raw())"
        if environment == "python-sync"
        else "await anext(response.aiter_raw())"
    )
    text = path.read_text()
    assert text.count(original) == 1, "The M7 mutation point changed"
    path.write_text(text.replace(original, original + "\n" + " " * 32 + read))
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_conformance_driver.py::test_redirect_snapshot_and_actual_connection_close"
            f"[{environment}]",
            "-q",
            "--tb=short",
            "--basetemp=" + str(tmp_path / "pytest"),
            "-p",
            "no:cacheprovider",
        ],
        cwd=source,
        env={**os.environ, "PYTHONPATH": str(source / "src")},
        capture_output=True,
        timeout=90,
    )
    output = result.stdout.decode("utf-8", "replace")
    (tmp_path / "mutation-output.txt").write_text(output)
    returncode = result.returncode
    assert returncode == 1, "M7 escaped the no-read-after-cancel assertion"
    assert "'read'" in output and "Extra items" in output, output
