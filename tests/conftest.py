import json
import socket
import sys
import time
from collections.abc import Callable
from pathlib import Path

import pytest

from .server_fixture import db as db
from .server_fixture import postgres as postgres

_deadline_tight_nodeids = pytest.StashKey[frozenset[str]]()


@pytest.hookimpl(tryfirst=True)
def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    config.stash[_deadline_tight_nodeids] = frozenset(
        item.nodeid
        for item in items
        if item.get_closest_marker("deadline_tight") is not None
    )


@pytest.fixture
def deadline_tight_nodeids(pytestconfig: pytest.Config) -> frozenset[str]:
    return pytestconfig.stash[_deadline_tight_nodeids]


def pytest_configure(config: pytest.Config) -> None:
    basetemp = config.getoption("basetemp")
    if isinstance(basetemp, (str, Path)):
        Path(basetemp).parent.mkdir(parents=True, exist_ok=True)


@pytest.fixture(scope="session")
def deadline_tolerance() -> float:
    observations: list[float] = []
    for _ in range(16):
        reader, writer = socket.socketpair()
        try:
            reader.settimeout(0.01)
            begin = time.monotonic()
            with pytest.raises(TimeoutError):
                reader.recv(1)
            observations.append(max(0.0, time.monotonic() - begin - 0.01))
        finally:
            reader.close()
            writer.close()
    tolerance = 0.05
    assert max(observations) < tolerance
    record = {
        "python": sys.version.split()[0],
        "samples": len(observations),
        "maxOverrunSeconds": max(observations),
        "toleranceSeconds": tolerance,
    }
    Path(".evidence").mkdir(exist_ok=True)
    Path(
        f".evidence/deadline-{sys.version_info.major}.{sys.version_info.minor}.json"
    ).write_text(json.dumps(record))
    return tolerance


@pytest.fixture
def record_deadline(deadline_tolerance: float) -> Callable[[str, float, float], None]:
    def record(name: str, elapsed: float, budget: float) -> None:
        bound = budget + deadline_tolerance
        with Path(
            f".evidence/sync-deadlines-{sys.version_info.major}.{sys.version_info.minor}.jsonl"
        ).open("a") as output:
            output.write(
                json.dumps(
                    {
                        "case": name,
                        "elapsedSeconds": elapsed,
                        "budgetSeconds": budget,
                        "overshootSeconds": max(0.0, elapsed - budget),
                        "boundSeconds": bound,
                    }
                )
                + "\n"
            )
        assert elapsed <= bound

    return record


@pytest.fixture
def record_phase_deadline() -> Callable[[str, float, float], None]:
    Path(".evidence").mkdir(exist_ok=True)

    def record(name: str, elapsed: float, budget: float) -> None:
        bound = budget + 1.0
        with Path(
            f".evidence/phase-deadlines-{sys.version_info.major}.{sys.version_info.minor}.jsonl"
        ).open("a") as output:
            output.write(
                json.dumps(
                    {
                        "case": name,
                        "elapsedSeconds": elapsed,
                        "budgetSeconds": budget,
                        "overshootSeconds": max(0.0, elapsed - budget),
                        "boundSeconds": bound,
                    }
                )
                + "\n"
            )
        assert elapsed < bound

    return record
