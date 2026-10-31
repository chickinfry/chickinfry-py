"""STORE-REJOIN adapter cases; generated signup wiring is a separate follow-up."""

import asyncio
import inspect
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, cast

import pytest

from chickinfry import AsyncHttpTransport, ClientError, HttpTransport
from chickinfry._device import _DeviceStore, _Record

from .peer import Peer, Received, json_bytes, respond
from .test_device_store import store_at
from .test_session import credentials


def entry(name: str, sequence: int = 1) -> dict[str, object]:
    return {
        "attempt": name,
        "email": name + "@example.invalid",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "sequence": sequence,
    }


@pytest.fixture(params=[False, True], ids=["memory", "file"])
def pair(
    request: pytest.FixtureRequest, tmp_path: Path
) -> tuple[_DeviceStore, _DeviceStore]:
    first = store_at(tmp_path / "state", persist=request.param)
    second = store_at(tmp_path / "state", persist=request.param)
    if not request.param:
        second._memory_record = first._memory_record
    first.replace(credentials())
    second.credentials()
    return first, second


@contextmanager
def failing_write(store: _DeviceStore, *, applied: bool = False) -> Iterator[None]:
    write = store._write

    def fail(record: _Record, state: dict[str, object]) -> None:
        if applied:
            write(record, state)
        raise PermissionError

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(store, "_write", fail)
        yield


def save(store: _DeviceStore, name: str, *, remove: tuple[str, ...] = ()) -> bool:
    return store._save_attempt(
        name, entry(name), expected_generation=store._generation, remove_screens=remove
    )


def save_reply(
    store: _DeviceStore, name: str, generation: int, auth_generation: int
) -> bool:
    options: dict[str, Any] = {"expected_generation": generation}
    # Run the same behavioral regression on the older private adapter signature.
    if "expected_auth_generation" in inspect.signature(store._save_attempt).parameters:
        options["expected_auth_generation"] = auth_generation
    return store._save_attempt(name, entry(name), **options)


def stage(
    store: _DeviceStore, name: str = "m", *, remove: tuple[str, ...] = ()
) -> None:
    with failing_write(store), pytest.raises(ClientError):
        save(store, name, remove=remove)


def snapshot(store: _DeviceStore) -> dict[str, object]:
    with store._transaction() as record:
        return store._read(record)


def names(store: _DeviceStore) -> set[str]:
    return set(cast(dict[str, object], snapshot(store)["attempts"]))


def test_review_storage_recovery_retains_new_successful_signup(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    stage(first)
    assert first._attempt("m") is not None
    assert not first._volatile
    assert names(peer) == {"m"}


def test_review_signup_retains_observed_base_during_read_outage(
    pair: tuple[_DeviceStore, _DeviceStore], monkeypatch: pytest.MonkeyPatch
) -> None:
    first, peer = pair
    read = first._read

    def fail(record: _Record) -> dict[str, object]:
        raise PermissionError

    monkeypatch.setattr(first, "_read", fail)
    with pytest.raises(ClientError):
        save(first, "m")
    assert first._attempt("m") is not None
    assert names(peer) == set()
    monkeypatch.setattr(first, "_read", read)
    assert first._attempt("m") is not None
    assert names(peer) == {"m"} and not first._volatile


@pytest.mark.parametrize("delete", [False, True])
def test_recovery6_unchanged_auth_preserves_peer_additions_and_removals(
    pair: tuple[_DeviceStore, _DeviceStore], delete: bool
) -> None:
    first, peer = pair
    assert save(first, "a")
    stage(first)
    peer.credentials()
    assert save(peer, "p", remove=("a",) if delete else ())
    first.credentials()
    assert not first._volatile
    assert names(peer) == ({"m", "p"} if delete else {"a", "m", "p"})


@pytest.mark.parametrize("peer_deleted", [False, True])
def test_recovery7_changed_auth_does_not_resurrect_consumed_attempts(
    pair: tuple[_DeviceStore, _DeviceStore], peer_deleted: bool
) -> None:
    first, peer = pair
    assert save(first, "a")
    stage(first, remove=() if peer_deleted else ("a",))
    peer.credentials()
    assert save(peer, "p", remove=("a",) if peer_deleted else ())
    current = peer.credentials()
    assert current is not None
    rotated = replace(
        credentials(), user_id=current.user_id, session_id=current.session_id
    )
    peer.replace(rotated)
    assert bool(first.credentials() == rotated)
    assert not first._volatile
    assert names(peer) == {"m", "p"}


def test_peer_consumed_attempt_is_not_restored_by_local_metadata(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    assert save(first, "a")
    with failing_write(first):
        with pytest.raises(ClientError):
            first._save_attempt(
                "a", entry("a", 2), expected_generation=first._generation
            )
        local = first._attempt("a")
        assert local is not None and local["sequence"] == 2
    peer.credentials()
    assert peer._remove_attempts(
        ("a",),
        expected_generation=peer._generation,
        expected_auth_generation=peer._auth_generation,
    )
    first.credentials()
    assert names(peer) == set() and not first._volatile


@pytest.mark.parametrize("boundary", ["logout", "switch"])
def test_review2_logout_before_first_recovered_read_clears_unknown_base_memory(
    pair: tuple[_DeviceStore, _DeviceStore], boundary: str
) -> None:
    first, peer = pair
    fresh = store_at(
        first._directory or Path("unused"),
        origin=first._origin,
        persist=first._memory_record is None,
    )
    fresh._memory_record = first._memory_record
    read = fresh._read
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(
            fresh, "_read", lambda record: (_ for _ in ()).throw(PermissionError())
        )
        with pytest.raises(ClientError):
            save(fresh, "m")
    current = peer.credentials()
    assert current is not None
    if boundary == "logout":
        peer.clear(current)
    else:
        peer.replace(
            replace(credentials(), user_id="peer-user", session_id="peer-session")
        )
    assert fresh.credentials() is None
    assert fresh._attempt("m") is None
    assert not fresh._volatile
    assert names(peer) == set()
    assert fresh._read == read


def test_review2_logout_fences_late_signup(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, _ = pair
    captured = first._snapshot()
    current = first.credentials()
    assert current is not None
    first.clear(current)
    assert not save_reply(
        first,
        "late",
        cast(int, captured["generation"]),
        cast(int, captured["auth_generation"]),
    )
    assert names(first) == set()


def test_review3_generation_collision_does_not_restore_attempt_after_logout(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    captured = first._snapshot()
    stage(first)
    current = peer.credentials()
    assert current is not None
    peer.clear(current)
    assert snapshot(peer)["generation"] == first._generation
    assert not save_reply(
        first,
        "late",
        first._generation,
        cast(int, captured["auth_generation"]),
    )
    assert names(peer) == set()
    assert first.credentials() is None


def test_review4_recovered_account_change_fences_peer_reply(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    captured = peer._snapshot()
    stage(first)
    first.credentials()
    new = replace(credentials(), user_id="new-user", session_id="new-session")
    assert first._accept_login(
        new, user_id=new.user_id, expected_generation=first._generation
    )
    peer.credentials()
    assert not save_reply(
        peer,
        "late",
        peer._generation,
        cast(int, captured["auth_generation"]),
    )
    assert bool(snapshot(peer)["session"] == asdict(new))
    assert names(peer) == {"m"}


@pytest.mark.parametrize("marker", ["refresh", "auth"])
@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_review5_live_peer_marker_blocks_protected_calls(
    tmp_path: Path, marker: str, mode: str
) -> None:
    sends: list[str] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        sends.append(request.path)
        await respond(writer, json_bytes({}))

    async with Peer(handler) as server:
        first = store_at(tmp_path / "state", origin=server.origin)
        peer = store_at(tmp_path / "state", origin=server.origin)
        first.replace(credentials())
        stage(first)
        old = peer.credentials()
        assert old is not None
        if marker == "refresh":
            peer._begin_refresh(old, peer._generation)
        else:
            assert peer._transition(
                old,
                user_id=old.user_id,
                expected_generation=peer._generation,
                auth_unknown=True,
            )
        before = snapshot(peer)
        first.credentials()
        assert snapshot(peer)[marker + "_unknown"] is True
        assert bool(snapshot(peer)["session"] == before["session"])

        async def invoke() -> None:
            async with AsyncHttpTransport(server.origin) as transport:
                await transport.with_session(first).invoke("probe.echo", {})

        def sync() -> None:
            with HttpTransport(server.origin) as transport:
                transport.with_session(first).invoke("probe.echo", {})

        with pytest.raises(ClientError):
            if mode == "async":
                await invoke()
            else:
                await asyncio.to_thread(sync)
        assert sends == []
        assert names(peer) == {"m"}


def test_live_peer_auth_marker_is_not_restart_debris(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    old = peer.credentials()
    assert old is not None
    assert peer._transition(
        old,
        user_id=old.user_id,
        expected_generation=peer._generation,
        auth_unknown=True,
    )
    before = snapshot(peer)
    assert first.credentials() is None
    assert bool(snapshot(peer) == before)


@pytest.mark.parametrize("marker", ["refresh", "auth"])
def test_legacy_boolean_marker_preserves_latest_true(
    pair: tuple[_DeviceStore, _DeviceStore], marker: str
) -> None:
    first, peer = pair
    stage(first)
    with peer._transaction() as record:
        state = peer._read(record)
        state[marker + "_unknown"] = True
        state.pop(marker + "_request", None)
        state["generation"] = cast(int, state["generation"]) + 1
        peer._write(record, state)
    first.credentials()
    assert snapshot(peer)[marker + "_unknown"] is True
    assert not first._volatile
    with pytest.raises(ClientError):
        first._register()


@pytest.mark.parametrize("marker", ["refresh", "auth"])
@pytest.mark.parametrize("own", [False, True])
def test_rejoin_releases_only_matching_request_marker(
    pair: tuple[_DeviceStore, _DeviceStore], marker: str, own: bool
) -> None:
    first, peer = pair
    old = first.credentials()
    assert old is not None
    if marker == "refresh":
        first._begin_refresh(old, first._generation)
    else:
        assert first._transition(
            old,
            user_id=old.user_id,
            expected_generation=first._generation,
            auth_unknown=True,
        )
    marked = snapshot(peer)
    assert isinstance(marked.get(marker + "_request"), str)
    new = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    with failing_write(first):
        assert first._accept_login(
            new, user_id=new.user_id, expected_generation=first._generation
        )
    if not own:
        with peer._transaction() as record:
            changed = peer._read(record)
            changed[marker + "_request"] = "peer-request"
            changed["generation"] = cast(int, changed["generation"]) + 1
            peer._write(record, changed)
    first.credentials()
    after = snapshot(peer)
    assert after[marker + "_unknown"] is (not own)
    assert bool(after["session"] == asdict(new)) is own
    if own:
        assert not first._volatile
        issued, generation = first._register()
        assert bool(issued == new)
        first._release(generation)
    else:
        with pytest.raises(ClientError):
            first._register()


@pytest.mark.parametrize("marker", ["refresh", "auth"])
@pytest.mark.parametrize("replacement", ["peer", "released"])
def test_normal_completion_also_requires_the_original_request_marker(
    pair: tuple[_DeviceStore, _DeviceStore], marker: str, replacement: str
) -> None:
    first, peer = pair
    old = first.credentials()
    assert old is not None
    generation = first._generation
    auth_generation = first._auth_generation
    if marker == "refresh":
        first._begin_refresh(old, generation)
    else:
        assert first._transition(
            old, user_id=old.user_id, expected_generation=generation, auth_unknown=True
        )
    peer.replace(old)
    current = peer.credentials()
    assert current is not None
    if replacement == "peer":
        if marker == "refresh":
            peer._begin_refresh(current, peer._generation)
        else:
            assert peer._transition(
                current,
                user_id=current.user_id,
                expected_generation=peer._generation,
                auth_unknown=True,
            )
    before = snapshot(peer)
    new = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    with pytest.raises(ClientError):
        if marker == "refresh":
            first._apply_refresh(old, generation, new, None)
        else:
            latest = first._snapshot()
            first._accept_login(
                new,
                user_id=new.user_id,
                expected_generation=cast(int, latest["generation"]),
                expected_auth_generation=auth_generation,
            )
    assert bool(snapshot(peer) == before)
    assert not first._volatile


def test_own_refresh_with_peer_attempt_cleanup(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    assert save(first, "a")
    old = first.credentials()
    assert old is not None
    generation = first._generation
    first._begin_refresh(old, generation)
    new = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    with failing_write(first):
        first._apply_refresh(old, generation, new, None)
    peer.credentials()
    assert save(peer, "p", remove=("a",))
    assert bool(first.credentials() == new)
    assert not first._volatile
    state = snapshot(peer)
    assert state["refresh_unknown"] is False
    assert names(peer) == {"p"}


def test_own_refresh_with_peer_pending(pair: tuple[_DeviceStore, _DeviceStore]) -> None:
    first, peer = pair
    old = first.credentials()
    assert old is not None
    generation = first._generation
    first._begin_refresh(old, generation)
    new = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    with failing_write(first):
        first._apply_refresh(old, generation, new, None)
    with peer._transaction() as record:
        state = peer._read(record)
        state.update(
            auth_unknown=True,
            auth_request="peer-request",
            generation=cast(int, state["generation"]) + 1,
        )
        peer._write(record, state)
    first.credentials()
    state = snapshot(peer)
    assert bool(state["session"] == asdict(new))
    assert state["refresh_unknown"] is False
    assert state["auth_unknown"] is True
    assert state["auth_request"] == "peer-request"
    with pytest.raises(ClientError):
        first._register()
    with peer._transaction() as record:
        state = peer._read(record)
        state.update(
            auth_unknown=False,
            auth_request=None,
            generation=cast(int, state["generation"]) + 1,
        )
        peer._write(record, state)
    assert bool(first.credentials() == new)


@pytest.mark.parametrize("peer_write", [False, True])
def test_uncertain_commit_already_applied(
    pair: tuple[_DeviceStore, _DeviceStore], peer_write: bool
) -> None:
    first, peer = pair
    new = replace(credentials(), user_id="new-user", session_id="new-session")
    with failing_write(first, applied=True):
        assert first._accept_login(
            new, user_id=new.user_id, expected_generation=first._generation
        )
    if peer_write:
        peer.credentials()
        assert save(peer, "p")
    assert bool(first.credentials() == new)
    assert not first._volatile
    assert names(peer) == ({"p"} if peer_write else set())


def test_uncertain_candidate_same_generation_different_auth_is_not_own(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    new = replace(credentials(), user_id="new-user", session_id="new-session")
    with failing_write(first):
        assert first._accept_login(
            new, user_id=new.user_id, expected_generation=first._generation
        )
    other = replace(credentials(), user_id="peer-user", session_id="peer-session")
    peer.replace(other)
    assert snapshot(peer)["auth_generation"] == first._auth_generation
    assert first.credentials() is None
    assert bool(first.credentials() == other)
    assert bool(snapshot(peer)["session"] == asdict(other))


def test_rejoin_same_revision_adopts_complete_peer_credentials(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    memory = credentials()
    with failing_write(first):
        assert first._accept_login(
            memory, user_id=memory.user_id, expected_generation=first._generation
        )
    latest = credentials()
    peer.replace(latest)
    assert snapshot(peer)["generation"] == first._generation
    assert bool(first.credentials() == latest)
    assert not first._volatile


@pytest.mark.parametrize("persist", [False, True], ids=["memory", "file"])
def test_rejoin_rejects_a_replaced_storage_history(
    tmp_path: Path, persist: bool
) -> None:
    first = store_at(tmp_path / "state", persist=persist)
    assert first.credentials() is None
    assert save(first, "a")
    stage(first)
    assert first._volatile
    with first._transaction() as record:
        reset = first._read(record)
        reset.update(generation=0, attempts={})
        first._write(record, reset)
    assert first.credentials() is None
    assert names(first) == set() and not first._volatile


def test_logout_failure_remains_blocked(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    old = first.credentials()
    assert old is not None
    with failing_write(first), pytest.raises(ClientError):
        first.clear(old)
    assert save(peer, "p")
    with pytest.raises(ClientError):
        first._register()
    assert first._storage_blocked


@pytest.mark.parametrize("bound", ["attempts", "bytes"])
def test_merge_bounds_leave_persisted_state_untouched(
    pair: tuple[_DeviceStore, _DeviceStore], bound: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    first, peer = pair
    stage(first)
    peer.credentials()
    if bound == "attempts":
        for name in ("p", "q", "r"):
            assert save(peer, name)
    else:
        assert save(peer, "p")
        import json

        from chickinfry import _device

        raw = snapshot(peer)
        limit = (
            len(json.dumps(raw, ensure_ascii=True, separators=(",", ":")).encode()) + 10
        )
        monkeypatch.setattr(_device, "_MAX_BYTES", limit)
    before = snapshot(peer)
    old = first._credentials
    assert bool(first.credentials() == old)
    assert first._volatile
    assert bool(snapshot(peer) == before)


@pytest.mark.parametrize("reverse", [False, True])
def test_review5_three_objects_four_replies_recovery_write_failure(
    pair: tuple[_DeviceStore, _DeviceStore],
    reverse: bool,
) -> None:
    first, peer = pair
    third = store_at(
        first._directory or Path("unused"),
        origin=first._origin,
        persist=first._memory_record is None,
    )
    third._memory_record = first._memory_record
    third.credentials()
    stage(first, "a")
    stage(peer, "b")
    assert save(third, "c")
    with failing_write(first):
        first.credentials()
    assert names(third) == {"c"}
    assert first._volatile
    for pending in (peer, first) if reverse else (first, peer):
        pending.credentials()
    assert names(third) == {"a", "b", "c"}
    captured_auth = third._auth_generation
    current = peer.credentials()
    assert current is not None
    peer.clear(current)
    assert not save_reply(third, "late", third._generation, captured_auth)
    assert names(peer) == set()


@pytest.mark.parametrize(
    "local_sequence,peer_sequence,winner", [(2, 3, "p"), (3, 2, "m"), (2, 2, "p")]
)
def test_same_screen_uses_request_order_and_keeps_persisted_ties(
    pair: tuple[_DeviceStore, _DeviceStore],
    local_sequence: int,
    peer_sequence: int,
    winner: str,
) -> None:
    first, peer = pair
    assert save(first, "a")
    with failing_write(first), pytest.raises(ClientError):
        first._save_attempt(
            "a", entry("m", local_sequence), expected_generation=first._generation
        )
    peer.credentials()
    assert peer._save_attempt(
        "a", entry("p", peer_sequence), expected_generation=peer._generation
    )
    first.credentials()
    attempts = cast(dict[str, dict[str, object]], snapshot(peer)["attempts"])
    assert attempts["a"]["attempt"] == winner


@pytest.mark.parametrize("expired", [False, True])
def test_rejoin_prunes_attempts_at_the_24_hour_boundary(
    pair: tuple[_DeviceStore, _DeviceStore],
    expired: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chickinfry import _device

    first, peer = pair
    fixed = datetime.now(timezone.utc)

    class Clock(datetime):
        @classmethod
        def now(cls, tz: Any = None) -> "Clock":
            return cls.fromisoformat(fixed.isoformat())

    value = entry("a")
    value["started_at"] = (
        fixed - timedelta(hours=24) + timedelta(microseconds=-1 if expired else 1)
    ).isoformat()
    assert first._save_attempt("a", value, expected_generation=first._generation)
    stage(first)
    monkeypatch.setattr(_device, "datetime", Clock)
    first.credentials()
    assert names(peer) == ({"m"} if expired else {"a", "m"})


@pytest.mark.parametrize("change", ["attempt", "logout", "always"])
def test_rejoin_cas_conflicts_recompute_all_gates_with_a_limit(
    pair: tuple[_DeviceStore, _DeviceStore],
    change: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first, peer = pair
    stage(first)
    assert first._volatile
    swap = first._swap
    calls = 0

    def conflict(
        record: _Record, expected: bytes | None, state: dict[str, object]
    ) -> bool:
        nonlocal calls
        calls += 1
        if calls == 1 or change == "always":
            latest = first._read(record)
            if change == "logout":
                latest.update(
                    session=None,
                    attempts={},
                    auth_generation=cast(int, latest["auth_generation"]) + 1,
                )
            else:
                cast(dict[str, object], latest["attempts"])["p"] = entry("p")
            latest["generation"] = cast(int, latest["generation"]) + 1
            peer._write(record, latest)
        return swap(record, expected, state)

    monkeypatch.setattr(first, "_swap", conflict)
    result = first.credentials()
    if change == "always":
        assert calls == 3 and first._volatile
        assert names(peer) == {"p"}
    elif change == "logout":
        assert calls == 1 and result is None
        assert not first._volatile and names(peer) == set()
    else:
        assert calls == 2 and not first._volatile
        assert names(peer) == {"m", "p"}


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("persist", [False, True], ids=["memory", "file"])
@pytest.mark.parametrize(
    "outcome", ["pending", "complete", "post-commit", "account-unknown"]
)
async def test_review5_public_cleanup_recovery_preserves_peer_outcome(
    tmp_path: Path, mode: str, persist: bool, outcome: str
) -> None:
    old = credentials()
    new = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    started, release = asyncio.Event(), asyncio.Event()
    sends: list[str] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        sends.append(request.path)
        if request.path == "/auth.signin":
            writer.close()
        elif request.path == "/auth.refresh":
            started.set()
            await release.wait()
            await respond(writer, json_bytes(asdict(new)))
        elif request.headers.get("authorization") == "Bearer " + new.access_token:
            await respond(writer, json_bytes({"ok": True}))
        else:
            await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as server:
        first = store_at(tmp_path / "state", origin=server.origin, persist=persist)
        peer = store_at(tmp_path / "state", origin=server.origin, persist=persist)
        if not persist:
            peer._memory_record = first._memory_record
        first.replace(old)
        assert save(first, "a")
        with (
            failing_write(first, applied=outcome == "post-commit"),
            pytest.raises(ClientError),
        ):
            first._remove_attempts(
                ("a",),
                expected_generation=first._generation,
                expected_auth_generation=first._auth_generation,
            )
        peer.credentials()

        async def invoke(
            store: _DeviceStore | None, operation: str = "probe.echo"
        ) -> object:
            if mode == "async":
                async with AsyncHttpTransport(server.origin) as transport:
                    target = (
                        transport if store is None else transport.with_session(store)
                    )
                    return await target.invoke(operation, {})

            def sync() -> object:
                with HttpTransport(server.origin) as transport:
                    target = (
                        transport if store is None else transport.with_session(store)
                    )
                    return target.invoke(operation, {})

            return await asyncio.to_thread(sync)

        if outcome == "account-unknown":
            current = peer.credentials()
            assert current is not None
            assert peer._transition(
                current,
                user_id=current.user_id,
                expected_generation=peer._generation,
                auth_unknown=True,
            )
            with pytest.raises(ClientError):
                await invoke(None, "auth.signin")
            first.credentials()
            assert snapshot(peer)["auth_unknown"] is True
            with pytest.raises(ClientError):
                await invoke(first)
            assert sends == ["/auth.signin"]
        else:
            task = asyncio.create_task(invoke(peer))
            await asyncio.wait_for(started.wait(), timeout=3)
            if outcome == "pending":
                first.credentials()
                assert snapshot(peer)["refresh_unknown"] is True
                with pytest.raises(ClientError):
                    await invoke(first)
            release.set()
            assert await asyncio.wait_for(task, timeout=3) == {"ok": True}
            assert bool(first.credentials() == new)
            assert bool(snapshot(peer)["session"] == asdict(new))
            assert sends == ["/probe.echo", "/auth.refresh", "/probe.echo"]
            assert not first._volatile
        assert names(peer) == set()


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("persist", [False, True], ids=["memory", "file"])
@pytest.mark.parametrize("marker", ["refresh", "auth"])
@pytest.mark.parametrize("cleanup_fails", [False, True])
async def test_store_rejoin_explicit_authentication_clears_observed_peer_marks(
    tmp_path: Path, mode: str, persist: bool, marker: str, cleanup_fails: bool
) -> None:
    """Preserve all screens at start; STORE-CAS-RETRY addendum 4 clears email on install."""
    old = credentials()
    new = replace(credentials(), user_id="new-user", session_id="new-session")
    sends: list[str] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        sends.append(request.path)
        await respond(writer, json_bytes(asdict(new)))

    async with Peer(handler) as server:
        first = store_at(tmp_path / "state", origin=server.origin, persist=persist)
        peer = store_at(tmp_path / "state", origin=server.origin, persist=persist)
        if not persist:
            peer._memory_record = first._memory_record
        first.replace(old)
        for screen in ("same-one", "same-two", "other"):
            value = entry(screen)
            if screen != "other":
                value["email"] = "target@example.invalid"
            assert first._save_attempt(
                screen, value, expected_generation=first._generation
            )
        stage(first, "m", remove=("same-one",))
        previous = peer.credentials()
        assert previous is not None
        peer_generation, peer_auth = peer._generation, peer._auth_generation
        if marker == "refresh":
            peer._begin_refresh(previous, peer_generation)
        else:
            assert peer._transition(
                previous,
                user_id=previous.user_id,
                expected_generation=peer_generation,
                auth_unknown=True,
            )
        with failing_write(first):
            first.credentials()
        assert first._volatile
        local_generation, local_auth = first._generation, first._auth_generation
        before = snapshot(peer)

        def start() -> bool:
            return first._transition(
                None,
                expected_generation=local_generation,
                expected_auth_generation=local_auth,
                screens=("same-one", "same-two"),
                auth_unknown=True,
            )

        if cleanup_fails:
            with (
                failing_write(first),
                pytest.raises(ClientError, check=lambda error: error._storage_failure),
            ):
                start()
            assert bool(snapshot(peer) == before)
            assert sends == []
            return
        assert start()
        after = snapshot(peer)
        assert after["session"] is None
        assert after["auth_unknown"] is False and after["refresh_unknown"] is False
        assert cast(int, after["generation"]) > local_generation
        assert cast(int, after["auth_generation"]) > local_auth
        assert names(peer) == {"same-one", "same-two", "other"} and not first._volatile
        assert bool(after["attempts"] == before["attempts"])
        if marker == "refresh":
            with pytest.raises(ClientError):
                peer._apply_refresh(previous, peer_generation, credentials(), None)
        else:
            assert not peer._accept_login(
                credentials(),
                user_id=old.user_id,
                expected_generation=peer._generation,
                expected_auth_generation=peer_auth,
            )
        assert bool(snapshot(peer) == after)

        async def signin() -> None:
            if mode == "async":
                async with AsyncHttpTransport(server.origin) as transport:
                    await transport.invoke(
                        "auth.signin", {"email": "target@example.invalid"}
                    )
            else:

                def sync() -> None:
                    with HttpTransport(server.origin) as transport:
                        transport.invoke(
                            "auth.signin", {"email": "target@example.invalid"}
                        )

                await asyncio.to_thread(sync)

        await signin()
        assert first._accept_login(
            new,
            user_id=new.user_id,
            expected_generation=first._generation,
            expected_auth_generation=first._auth_generation,
            screens=("same-one", "same-two"),
        )
        assert bool(first.credentials() == new)
        assert names(peer) == {"other"}
        assert sends == ["/auth.signin"]


def test_explicit_authentication_does_not_reuse_a_discarded_memory_auth_generation(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    old = first.credentials()
    assert old is not None
    assert first._transition(
        old,
        user_id=old.user_id,
        expected_generation=first._generation,
        auth_unknown=True,
    )
    new = replace(credentials(), user_id="memory-user", session_id="memory-session")
    with failing_write(first):
        assert first._accept_login(
            new, user_id=new.user_id, expected_generation=first._generation
        )
    retired_auth = first._auth_generation
    peer.replace(old)
    previous = peer.credentials()
    assert previous is not None
    peer._begin_refresh(previous, peer._generation)
    first.credentials()
    assert not first._volatile
    assert first._transition(
        None,
        expected_generation=first._generation,
        expected_auth_generation=first._auth_generation,
        auth_unknown=True,
    )
    assert first._auth_generation > retired_auth
    assert not save_reply(first, "late", first._generation, retired_auth)
    assert names(peer) == set()


def test_explicit_authentication_keeps_a_peer_session_after_its_marker_resolves(
    pair: tuple[_DeviceStore, _DeviceStore],
) -> None:
    first, peer = pair
    stage(first)
    old = peer.credentials()
    assert old is not None
    generation = peer._generation
    peer._begin_refresh(old, generation)
    with failing_write(first):
        first.credentials()
    captured_generation, captured_auth = first._generation, first._auth_generation
    new = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    peer._apply_refresh(old, generation, new, None)
    assert not first._transition(
        old,
        user_id=old.user_id,
        expected_generation=captured_generation,
        expected_auth_generation=captured_auth,
        auth_unknown=True,
    )
    state = snapshot(peer)
    assert bool(state["session"] == asdict(new))
    assert state["auth_generation"] == captured_auth
    assert names(peer) == {"m"}


@pytest.mark.parametrize("boundary", ["logout", "signin", "replace"])
def test_auth_boundaries_do_not_reuse_a_speculative_generation(
    pair: tuple[_DeviceStore, _DeviceStore], boundary: str
) -> None:
    first, peer = pair
    old = first.credentials()
    assert old is not None
    new = replace(credentials(), user_id="memory-user", session_id="memory-session")
    with failing_write(first):
        assert first._accept_login(
            new, user_id=new.user_id, expected_generation=first._generation
        )
    retired_auth = first._auth_generation
    memory = first._credentials
    assert memory is not None
    if boundary == "logout":
        first.clear(memory)
    else:
        peer.replace(
            replace(credentials(), user_id=old.user_id, session_id=old.session_id)
        )
        first.credentials()
        assert not first._volatile
        latest = replace(
            credentials(), user_id="latest-user", session_id="latest-session"
        )
        if boundary == "replace":
            first.replace(latest)
        else:
            assert first._accept_login(
                latest, user_id=latest.user_id, expected_generation=first._generation
            )
    assert first._auth_generation > retired_auth
    assert not save_reply(first, "late", first._generation, retired_auth)
    assert names(peer) == set()


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("persist", [False, True], ids=["memory", "file"])
async def test_uncertain_commit_then_refresh_with_new_session_during_read_outage(
    tmp_path: Path, mode: str, persist: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = credentials()
    new = replace(credentials(), user_id=old.user_id, session_id="new-session")
    started, release = asyncio.Event(), asyncio.Event()
    sends: list[str] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        sends.append(request.path)
        if request.path == "/auth.refresh":
            started.set()
            await release.wait()
            await respond(writer, json_bytes(asdict(new)))
        elif request.path == "/auth.signup":
            await respond(writer, json_bytes({"accepted": True, "attempt": "m"}))
        elif request.headers.get("authorization") == "Bearer " + new.access_token:
            await respond(writer, json_bytes({"ok": True}))
        else:
            await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as server:
        store = store_at(tmp_path / "state", origin=server.origin, persist=persist)
        store.replace(old)
        original_auth = store._auth_generation

        async def invoke(bound: bool, operation: str = "probe.echo") -> object:
            if mode == "async":
                async with AsyncHttpTransport(server.origin) as transport:
                    target = transport.with_session(store) if bound else transport
                    return await target.invoke(operation, {})

            def sync() -> object:
                with HttpTransport(server.origin) as transport:
                    target = transport.with_session(store) if bound else transport
                    return target.invoke(operation, {})

            return await asyncio.to_thread(sync)

        task = asyncio.create_task(invoke(True))
        await asyncio.wait_for(started.wait(), timeout=3)
        assert await invoke(False, "auth.signup") == {"accepted": True, "attempt": "m"}
        with failing_write(store, applied=True), pytest.raises(ClientError):
            save(store, "m")
        committed = snapshot(store)
        assert committed["auth_generation"] == original_auth
        read = store._read

        def unreadable(record: _Record) -> dict[str, object]:
            raise PermissionError

        monkeypatch.setattr(store, "_read", unreadable)
        release.set()
        with pytest.raises(ClientError):
            await asyncio.wait_for(task, timeout=3)
        assert bool(store.credentials() == new)
        target_auth = store._auth_generation
        assert target_auth > original_auth
        monkeypatch.setattr(store, "_read", read)
        assert bool(store.credentials() == new)
        state = snapshot(store)
        assert state["auth_generation"] == target_auth
        assert bool(state["session"] == asdict(new))
        assert state["refresh_unknown"] is False
        assert names(store) == {"m"} and not store._volatile
        assert await invoke(True) == {"ok": True}
        assert sends.count("/auth.refresh") == 1 and sends.count("/auth.signup") == 1
