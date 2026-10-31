"""Require the rejoin regressions to reject each broken ownership comparison."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

MUTATIONS = [
    (
        "explicit-start-attempts",
        'state["attempts"] = self._merge_attempts(state, state, state)',
        'state["attempts"] = {}',
        "explicit_authentication_clears_observed_peer_marks",
    ),
    (
        "resolved-peer-marker",
        'latest[kind + "_unknown"]\n                and (',
        "True\n                and (",
        "keeps_a_peer_session_after_its_marker_resolves",
    ),
    (
        "applied-candidate-vs-new-result",
        "if install:",
        "if install and not applied:",
        "uncertain_commit_then_refresh_with_new_session_during_read_outage",
    ),
    (
        "auth-generation-floor",
        "return max(generation, floor) + 1",
        "return generation + 1",
        "auth_boundaries_do_not_reuse_a_speculative_generation",
    ),
    (
        "logout-generation-floor",
        "auth_generation=max(auth_generation, self._auth_high_water) + 1",
        "auth_generation=auth_generation + 1",
        "auth_boundaries_do_not_reuse_a_speculative_generation",
    ),
    (
        "explicit-auth-start",
        "if latest is not None and any(",
        "if False and any(",
        "explicit_authentication_clears_observed_peer_marks",
    ),
    (
        "speculative-auth-fence",
        'cast(int, state["auth_generation"]), self._auth_high_water',
        'cast(int, state["auth_generation"]), self._auth_generation',
        "does_not_reuse_a_discarded_memory_auth_generation",
    ),
    (
        "normal-marker-owner",
        'or state[kind + "_request"] != owned_request',
        "or False",
        "normal_completion_also_requires_the_original_request_marker",
    ),
    (
        "storage-history",
        'cast(int, latest["generation"]) < cast(int, base["generation"])',
        "False",
        "rejoin_rejects_a_replaced_storage_history",
    ),
    (
        "auth-boundary",
        'latest["auth_generation"] != base["auth_generation"] and not applied',
        "False",
        "uncertain_candidate_same_generation_different_auth",
    ),
    (
        "candidate-content",
        "self._auth_state(latest) == self._auth_state(self._candidate)",
        "True",
        "uncertain_candidate_same_generation_different_auth",
    ),
    (
        "expected-session",
        'install = latest["session"] == base["session"] and all(',
        "install = all(",
        "same_revision_adopts_complete_peer_credentials",
    ),
    (
        "request-owner",
        'and base[kind + "_request"] == request\n                    and latest[kind + "_request"] == request',
        'and base[kind + "_request"] == request',
        "rejoin_releases_only_matching_request_marker",
    ),
    (
        "peer-deletion",
        'if current is None or current["attempt"] != original["attempt"]:',
        "if False:",
        "peer_consumed_attempt_is_not_restored_by_local_metadata",
    ),
    (
        "own-deletion",
        "merged.pop(screen)",
        "pass",
        "recovery7_changed_auth_does_not_resurrect_consumed_attempts",
    ),
    (
        "peer-addition",
        "merged = deepcopy(remote)",
        "merged = deepcopy(local)",
        "recovery6_unchanged_auth_preserves_peer_additions_and_removals",
    ),
    (
        "same-screen-order",
        'cast(int, own["sequence"]) <= cast(int, current["sequence"])',
        "False",
        "same_screen_uses_request_order",
    ),
    (
        "attempt-limit",
        'if len(cast(dict[str, object], merged["attempts"])) > _MAX_ATTEMPTS:',
        "if False:",
        "merge_bounds_leave_persisted_state_untouched",
    ),
    (
        "raw-cas",
        "if record.raw != expected:",
        "if False:",
        "rejoin_cas_conflicts_recompute_all_gates_with_a_limit",
    ),
    (
        "retry-limit",
        "for _ in range(3):",
        "for _ in range(4):",
        "rejoin_cas_conflicts_recompute_all_gates_with_a_limit",
    ),
    (
        "restart-vs-live",
        'self._baseline is None\n            and state["auth_unknown"]',
        'state["auth_unknown"]',
        "live_peer_auth_marker_is_not_restart_debris",
    ),
    (
        "unknown-baseline",
        "base, memory = self._baseline, self._pending",
        "base, memory = self._baseline or latest, self._pending",
        "clears_unknown_base_memory",
    ),
    (
        "expiry-boundary",
        'if now - _time(cast(str, value["started_at"])) < 86_400_000_000',
        'if now - _time(cast(str, value["started_at"])) < 86_401_000_000',
        "prunes_attempts_at_the_24_hour_boundary",
    ),
]


@pytest.mark.parametrize(
    "name,original,mutation,selection", MUTATIONS, ids=[row[0] for row in MUTATIONS]
)
def test_rejoin_comparison_mutation_is_detected(
    name: str, original: str, mutation: str, selection: str, tmp_path: Path
) -> None:
    source = tmp_path / "source"
    shutil.copytree(
        ROOT / "src", source / "src", ignore=shutil.ignore_patterns("__pycache__")
    )
    (source / "tests").mkdir()
    for filename in (
        "__init__.py",
        "test_store_rejoin.py",
        "test_device_store.py",
        "test_session.py",
        "peer.py",
    ):
        shutil.copyfile(ROOT / "tests" / filename, source / "tests" / filename)
    shutil.copyfile(ROOT / "pyproject.toml", source / "pyproject.toml")
    path = source / "src/chickinfry/_device.py"
    text = path.read_text()
    assert text.count(original) == 1, "The mutation must change exactly one comparison"
    path.write_text(text.replace(original, mutation))
    allowed = {
        key: os.environ[key]
        for key in ("HOME", "PATH", "TMPDIR", "LANG", "LC_ALL")
        if key in os.environ
    }
    allowed["PYTHONPATH"] = str(source / "src")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_store_rejoin.py",
            "-k",
            selection,
            "-q",
            "--assert=plain",
            "--tb=line",
            "--basetemp=" + str(tmp_path / "pytest"),
            "-p",
            "no:cacheprovider",
        ],
        cwd=source,
        env=allowed,
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    (tmp_path / (name + ".txt")).write_text(result.stdout + result.stderr)
    assert result.returncode == 1, (
        "The broken comparison must fail an executed regression"
    )
    assert " failed" in result.stdout and "ERROR" not in result.stdout
