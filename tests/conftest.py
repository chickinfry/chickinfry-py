import json
import socket
import sys
import time
from pathlib import Path

import pytest

from .deadline import Clock
from .server_fixture import db as db
from .server_fixture import postgres as postgres


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
def sync_clock(monkeypatch: pytest.MonkeyPatch) -> Clock:
    from chickinfry import _sync_http, _sync_network, session

    clock = Clock()
    # Replace only SDK clocks; the event loop and runner keep their real clocks.
    for module in (_sync_http, _sync_network, session):
        monkeypatch.setattr(module, "time", clock)
    return clock
