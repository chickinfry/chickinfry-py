import asyncio
import json
import secrets
import sys
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import TypeVar
from uuid import UUID

import pytest

from chickinfry._auth_database import Database as PrivateDatabase
from chickinfry._auth_database import create_database
from chickinfry.auth import Auth, CleanupContext, hash_token, random_token
from chickinfry.orm import DatabasePort, format_timestamp
from chickinfry.postgres import PostgresPort
from chickinfry.server import OperationError

from .server_fixture import Harness

T = TypeVar("T")


@dataclass
class PassCounts:
    runs: int = 0
    queries: int = 0
    auth_attempts: int = 0
    invite_attempts: int = 0
    auth_deleted: int = 0
    invite_deleted: int = 0
    auth_zero_rows: int = 0
    invite_zero_rows: int = 0
    closed: bool = False
    candidates: list[str] = field(default_factory=list)
    session_queries: int = 0


class CountingPort:
    def __init__(
        self, delegate: DatabasePort, root: PostgresPort, counts: PassCounts
    ) -> None:
        self.delegate, self.root, self.counts = delegate, root, counts

    async def query(
        self, sql: str, parameters: Sequence[object]
    ) -> Sequence[Mapping[str, object]]:
        self.counts.queries += 1
        deleting = sql.startswith("delete from ")
        invite = sql.startswith('delete from "public"."app_auth_invites"')
        if deleting:
            if invite:
                self.counts.invite_attempts += 1
            else:
                self.counts.auth_attempts += 1
        rows = await self.delegate.query(sql, parameters)
        if sql.startswith("select ") and 'from "public"."app_auth_sessions"' in sql:
            self.counts.session_queries += 1
            self.counts.candidates.extend(str(row["id"]) for row in rows)
        if deleting:
            if invite:
                self.counts.invite_deleted += len(rows)
                self.counts.invite_zero_rows += int(not rows)
            else:
                self.counts.auth_deleted += len(rows)
                self.counts.auth_zero_rows += int(not rows)
        return rows

    async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
        async def run(port: DatabasePort) -> T:
            return await work(CountingPort(port, self.root, self.counts))

        return await self.delegate.transaction(run)

    async def close(self) -> None:
        await self.root.close()
        self.counts.closed = True

    def terminate(self) -> None:
        self.root.terminate()
        self.counts.closed = True


async def test_cleanup_attempt_bounds_include_zero_row_deletes(db: Harness) -> None:
    password = "a long cleanup test password"
    owner = await Auth(db.port(), create_database, now=db.now).signup(
        "bounds@example.test", password
    )
    private = PrivateDatabase(db.port())
    old = format_timestamp(db.now() - timedelta(days=40))
    for i in range(33):
        session = await private.sessions.insert(
            {
                "id": str(UUID(int=i + 1)),
                "user_id": owner.user_id,
                "token_hash": hash_token(random_token()),
                "user_session_version": 1,
                "expires_at": old,
                "created_at": old,
            }
        )
        await private.refresh_tokens.insert(
            {
                "id": str(UUID(int=i + 101)),
                "session_id": session.id,
                "token_hash": "veto" if i == 0 else hash_token(random_token()),
                "expires_at": old,
                "created_at": old,
            }
        )
        await private.rate_limits.insert(
            {
                "action": "old",
                "key_hash": f"{i:02d}",
                "attempt_count": 1,
                "expires_at": old,
            }
        )
        await private.invites.insert(
            {
                "id": str(UUID(int=i + 1001)),
                "email": "old@example.test",
                "issued_by": owner.user_id,
                "code_hash": "veto" if i == 0 else hash_token(random_token()),
                "expires_at": old,
            }
        )
    retained = await private.invites.insert(
        {
            "email": "retained@example.test",
            "issued_by": owner.user_id,
            "code_hash": hash_token(random_token()),
            "expires_at": format_timestamp(
                db.now() - timedelta(days=30) + timedelta(microseconds=1)
            ),
        }
    )
    setup = db.port()
    await setup._execute("""
        create function suppress_cleanup_delete() returns trigger language plpgsql as $$
        begin
            if to_jsonb(OLD)->>'token_hash' = 'veto' or to_jsonb(OLD)->>'code_hash' = 'veto'
               or to_jsonb(OLD)->>'key_hash' = '00'
               or to_jsonb(OLD)->>'id' = '00000000-0000-0000-0000-000000000002' then
                return null;
            end if;
            return OLD;
        end $$;
    """)
    for table in (
        "app_auth_refresh_tokens",
        "app_auth_sessions",
        "app_auth_rate_limits",
        "app_auth_invites",
    ):
        await setup._execute(
            f'create trigger suppress_cleanup_delete before delete on "{table}" '
            "for each row execute function suppress_cleanup_delete()"
        )
    counts = PassCounts()
    tasks: list[asyncio.Task[None]] = []
    cleanup_root = db.port()

    def make_port() -> CountingPort:
        counts.runs += 1
        return CountingPort(cleanup_root, cleanup_root, counts)

    def schedule(work: Coroutine[None, None, None]) -> None:
        tasks.append(asyncio.create_task(work))

    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        cleanup=CleanupContext(make_port, schedule),
    )
    tokens = await core.signin("bounds@example.test", password)
    await asyncio.gather(*tasks)
    assert counts.runs == 1 and counts.queries > 0 and counts.closed
    assert 0 < counts.auth_attempts <= 96 and 0 < counts.invite_attempts <= 32
    assert counts.auth_zero_rows > 0 and counts.invite_zero_rows > 0
    assert counts.auth_deleted + counts.auth_zero_rows == counts.auth_attempts
    assert counts.invite_deleted + counts.invite_zero_rows == counts.invite_attempts
    assert await core.session(tokens.access_token)
    assert await private.invites.find_by_id({"id": retained.id}) is not None
    Path(".evidence").mkdir(exist_ok=True)
    Path(
        f".evidence/cleanup-bounds-{sys.version_info.major}.{sys.version_info.minor}.json"
    ).write_text(
        json.dumps(
            {
                "cleanupRan": counts.runs,
                "queries": counts.queries,
                "authDeleteAttempts": counts.auth_attempts,
                "inviteDeleteAttempts": counts.invite_attempts,
                "authDeleted": counts.auth_deleted,
                "inviteDeleted": counts.invite_deleted,
                "authZeroRowDeletes": counts.auth_zero_rows,
                "inviteZeroRowDeletes": counts.invite_zero_rows,
                "portClosed": counts.closed,
                "successPreserved": True,
            }
        )
    )


async def test_cleanup_progress_past_preserved_credentials_and_legacy_families(
    db: Harness,
) -> None:
    """M12/CLEANUP-SEL: detect credential-capped starvation or lost replay links."""
    core = Auth(db.port(), create_database, now=db.now)
    initial = await core.signup("progress@example.test", "a long cleanup test password")
    started = db.now()
    private = PrivateDatabase(db.port())
    db.instant += timedelta(days=29)
    current = await core.refresh(initial.refresh_token)
    for _ in range(100):
        await private.refresh_tokens.insert(
            {
                "session_id": initial.session_id,
                "token_hash": hash_token(random_token()),
                "created_at": format_timestamp(started),
                "consumed_at": format_timestamp(db.now()),
                "expires_at": initial.refresh_expires_at,
            }
        )
    dead: list[str] = []
    for i in range(70):
        row = await private.sessions.insert(
            {
                "user_id": initial.user_id,
                "token_hash": hash_token(random_token()),
                "user_session_version": 1,
                "created_at": format_timestamp(started),
                "expires_at": format_timestamp(started + timedelta(seconds=900)),
                "first_login_at": None if i % 2 else format_timestamp(started),
                "last_renewed_at": None if i % 2 else format_timestamp(started),
            }
        )
        dead.append(row.id)
        await private.refresh_tokens.insert(
            {
                "session_id": row.id,
                "token_hash": hash_token(random_token()),
                "created_at": format_timestamp(started),
                "expires_at": format_timestamp(
                    started + timedelta(days=7 if i % 2 else 30)
                ),
            }
        )
    tasks: list[asyncio.Task[None]] = []
    counts: list[PassCounts] = []

    def create_port() -> CountingPort:
        tally = PassCounts()
        counts.append(tally)
        port = db.port()
        return CountingPort(port, port, tally)

    def schedule(work: Coroutine[None, None, None]) -> None:
        tasks.append(asyncio.create_task(work))

    core.cleanup_context = CleanupContext(create_port, schedule)
    db.instant = started + timedelta(days=31)
    newest = await core.refresh(current.refresh_token)
    await asyncio.gather(*tasks)
    for _ in range(3):
        core._schedule_cleanup()
        await asyncio.gather(*tasks)
    for tally in counts:
        assert (
            tally.closed and tally.auth_attempts <= 96 and tally.invite_attempts <= 32
        )
        assert initial.session_id not in tally.candidates
    assert sum(tally.auth_deleted for tally in counts) >= 140
    survivors = await private.sessions.find_many()
    assert len(survivors) == 1 and survivors[0].id == initial.session_id
    assert not any(row.id in dead for row in survivors)
    assert len(await private.refresh_tokens.find_many()) == 103
    with pytest.raises(OperationError) as reused:
        await core.refresh(initial.refresh_token)
    assert reused.value.code == "session_revoked"
    with pytest.raises(OperationError):
        await core.session(newest.access_token)
    with pytest.raises(OperationError):
        await core.refresh(newest.refresh_token)


async def test_cleanup_growth_rejects_expired_refresh_and_eventually_selects_family(
    db: Harness,
) -> None:
    """CLEANUP-GROW (a): catch stored-expiry revival or never selecting delayed cleanup."""
    core = Auth(db.port(), create_database, now=db.now, idle_timeout_seconds=3600)
    password = "a long cleanup test password"
    initial = await core.signup("growth@example.test", password)
    probe = await core.signin("growth@example.test", password)
    started = db.now()
    private = PrivateDatabase(db.port())
    grown = Auth(db.port(), create_database, now=db.now, idle_timeout_seconds=7200)
    db.instant = started + timedelta(seconds=3600, microseconds=1)
    with pytest.raises(OperationError) as expired:
        await grown.refresh(probe.refresh_token)
    assert expired.value.status == 401 and expired.value.code == "session_revoked"
    # The rejection revokes its probe; keep the untouched family for candidate checks.
    root = db.port()
    for instant in (db.now(), started + timedelta(seconds=7200, microseconds=-1)):
        db.instant = instant
        tally = PassCounts()
        await grown._cleanup(CountingPort(root, root, tally), False)
        assert initial.session_id not in tally.candidates
        assert await private.sessions.find_by_id({"id": initial.session_id}) is not None
    db.instant = started + timedelta(seconds=7200)
    tally = PassCounts()
    await grown._cleanup(CountingPort(root, root, tally), False)
    assert initial.session_id in tally.candidates and tally.auth_deleted == 2
    assert await private.sessions.find_by_id({"id": initial.session_id}) is None
    assert not await private.refresh_tokens.find_many()


async def test_cleanup_start_is_generated_once_per_pass(
    db: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    core = Auth(db.port(), create_database, now=db.now)
    generate = core._cleanup_start
    starts: list[str] = []

    def record_start() -> str:
        value = generate()
        starts.append(value)
        return value

    monkeypatch.setattr(core, "_cleanup_start", record_start)
    root = db.port()
    for count in (1, 2):
        tally = PassCounts()
        await core._cleanup(CountingPort(root, root, tally), False)
        assert len(starts) == count
        assert tally.session_queries == 2
        assert UUID(starts[-1]).version == 4
        assert str(UUID(starts[-1])) == starts[-1]
    assert starts[0] != starts[1]


async def test_cleanup_start_boundary_selects_each_candidate_once(
    db: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """K3: the wrap-around segment must not reselect the start row."""
    core = Auth(db.port(), create_database, now=db.now)
    private = PrivateDatabase(db.port())
    owner = await private.users.insert({"email": "start-boundary@example.test"})
    expected: list[str] = []
    for i in range(5):
        row = await private.sessions.insert(
            {
                "id": str(UUID(int=i + 1)),
                "user_id": owner.id,
                "token_hash": hash_token(random_token()),
                "user_session_version": 1,
                "created_at": format_timestamp(db.now() - timedelta(days=8)),
                "expires_at": format_timestamp(db.now() - timedelta(days=8)),
            }
        )
        expected.append(row.id)
    monkeypatch.setattr(core, "_cleanup_start", lambda: expected[2])
    tally = PassCounts()
    root = db.port()
    await core._cleanup(CountingPort(root, root, tally), False)
    assert len(tally.candidates) == len(set(tally.candidates)) == len(expected)
    assert sorted(tally.candidates) == sorted(expected)


async def test_cleanup_start_draws_entropy_from_secrets(
    db: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    """K5b: the cleanup start must come from the OS CSPRNG, not a seeded PRNG."""
    calls: list[int] = []

    def fake_token_bytes(count: int) -> bytes:
        calls.append(count)
        return bytes(range(count))

    monkeypatch.setattr(secrets, "token_bytes", fake_token_bytes)
    core = Auth(db.port(), create_database, now=db.now)
    assert core._cleanup_start() == str(UUID(bytes=bytes(range(16)), version=4))
    calls.clear()
    root = db.port()
    for passes in (1, 2):
        tally = PassCounts()
        await core._cleanup(CountingPort(root, root, tally), False)
        # asyncpg's SCRAM handshake also draws from secrets on new connections.
        assert [size for size in calls if size == 16] == [16] * passes


@pytest.mark.parametrize("legacy", [False, True], ids=["modern", "legacy"])
async def test_cleanup_shrink_progress_past_full_candidate_batch(
    db: Harness, legacy: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """F-05 shrink: reach dead families past a full live batch, including wrap-around."""
    private = PrivateDatabase(db.port())
    owner = await private.users.insert({"email": "shrink@example.test"})
    started = db.now()
    issued = started - timedelta(minutes=30) if legacy else started
    access_expiry = (
        started - timedelta(hours=2) if legacy else issued + timedelta(seconds=900)
    )
    stored_expiry = format_timestamp(started + timedelta(days=6))
    blockers: list[str] = []
    credentials: list[tuple[str, str]] = []
    for i in range(32):
        access, refresh = random_token(), random_token()
        credentials.append((access, refresh))
        row = await private.sessions.insert(
            {
                "id": f"00000000-0000-4000-8000-{i:012x}",
                "user_id": owner.id,
                "token_hash": hash_token(access),
                "user_session_version": 1,
                "created_at": format_timestamp(
                    started - timedelta(days=1) if legacy else started
                ),
                "expires_at": format_timestamp(access_expiry),
                "first_login_at": None if legacy else format_timestamp(started),
                "last_renewed_at": None if legacy else format_timestamp(issued),
            }
        )
        await private.refresh_tokens.insert(
            {
                "session_id": row.id,
                "token_hash": hash_token(refresh),
                "created_at": format_timestamp(issued),
                "expires_at": stored_expiry,
            }
        )
        blockers.append(row.id)
    dead: list[str] = []
    dead_issued = (
        started - timedelta(minutes=90) if legacy else started + timedelta(seconds=1)
    )
    for i in range(2):
        row = await private.sessions.insert(
            {
                "id": f"ffffffff-ffff-4fff-bfff-{i:012x}",
                "user_id": owner.id,
                "token_hash": hash_token(random_token()),
                "user_session_version": 1,
                "created_at": format_timestamp(dead_issued),
                "expires_at": format_timestamp(dead_issued + timedelta(seconds=900)),
                "first_login_at": format_timestamp(dead_issued),
                "last_renewed_at": format_timestamp(dead_issued),
            }
        )
        dead.append(row.id)
        await private.refresh_tokens.insert(
            {
                "session_id": row.id,
                "token_hash": hash_token(random_token()),
                "created_at": format_timestamp(dead_issued),
                "expires_at": format_timestamp(dead_issued + timedelta(seconds=3600)),
            }
        )
    if not legacy:
        db.instant = started + timedelta(seconds=7200)
    shrunk = Auth(db.port(), create_database, now=db.now, idle_timeout_seconds=3600)
    monkeypatch.setattr(shrunk, "_cleanup_start", lambda: blockers[0])
    root = db.port()
    if legacy:
        before_sessions = sorted(
            await private.sessions.find_many(), key=lambda row: row.id
        )
        before_refresh = sorted(
            await private.refresh_tokens.find_many(), key=lambda row: row.id
        )
        for _ in range(2):
            tally = PassCounts()
            await shrunk._cleanup(CountingPort(root, root, tally), False)
            assert tally.candidates == blockers
            assert tally.session_queries == 1 and tally.auth_deleted == 0
            assert (
                sorted(await private.sessions.find_many(), key=lambda row: row.id)
                == before_sessions
            )
            assert (
                sorted(await private.refresh_tokens.find_many(), key=lambda row: row.id)
                == before_refresh
            )

        monkeypatch.setattr(shrunk, "_cleanup_start", lambda: dead[1])
        tally = PassCounts()
        await shrunk._cleanup(CountingPort(root, root, tally), False)
        assert tally.candidates == [dead[1], *blockers[:31]]
        assert tally.session_queries == 2 and tally.auth_deleted == 2
        assert await private.sessions.find_by_id({"id": dead[1]}) is None
        assert await private.sessions.find_by_id({"id": dead[0]}) is not None

        random_core = Auth(
            db.port(), create_database, now=db.now, idle_timeout_seconds=3600
        )
        for _ in range(8):
            tally = PassCounts()
            await random_core._cleanup(CountingPort(root, root, tally), False)
            assert tally.session_queries <= 2 and len(tally.candidates) <= 32
            assert len(set(tally.candidates)) == len(tally.candidates)
            if await private.sessions.find_by_id({"id": dead[0]}) is None:
                break
        assert await private.sessions.find_by_id({"id": dead[0]}) is None
        assert sorted(await private.sessions.find_many(), key=lambda row: row.id) == [
            row for row in before_sessions if row.id in blockers
        ]
        assert sorted(
            await private.refresh_tokens.find_many(), key=lambda row: row.id
        ) == sorted(
            [row for row in before_refresh if row.session_id in blockers],
            key=lambda row: row.id,
        )
        db.instant = issued + timedelta(seconds=3600, microseconds=-1)
        tally = PassCounts()
        await shrunk._cleanup(CountingPort(root, root, tally), False)
        assert tally.auth_deleted == 0 and tally.candidates == blockers
        db.instant = issued + timedelta(seconds=3600)

    for access, refresh in credentials:
        for reject in (shrunk.session(access), shrunk.refresh(refresh)):
            with pytest.raises(OperationError) as expired:
                await reject
            assert expired.value.status == 401
    for _ in range(2):
        tally = PassCounts()
        await shrunk._cleanup(CountingPort(root, root, tally), False)
        assert tally.auth_attempts <= 96
    assert not await private.sessions.find_many()
    assert not await private.refresh_tokens.find_many()


async def test_legacy_cleanup_selection_uses_seven_day_upper_bound(db: Harness) -> None:
    """CLEANUP-SEL 3: catch removing the legacy created_at < now - 7 days filter."""
    core = Auth(db.port(), create_database, now=db.now)
    private = PrivateDatabase(db.port())
    owner = await private.users.insert({"email": "legacy-upper-bound@example.test"})
    sessions: list[str] = []
    refresh_ids: list[str] = []
    for offset in (-1, 0, 1):
        created = db.now() - timedelta(days=7) + timedelta(microseconds=offset)
        session = await private.sessions.insert(
            {
                "user_id": owner.id,
                "token_hash": hash_token(random_token()),
                "user_session_version": 1,
                "created_at": format_timestamp(created),
                "expires_at": format_timestamp(db.now() + timedelta(seconds=900)),
                "first_login_at": None,
                "last_renewed_at": None,
            }
        )
        refresh = await private.refresh_tokens.insert(
            {
                "session_id": session.id,
                "token_hash": hash_token(random_token()),
                "created_at": format_timestamp(created),
                "expires_at": format_timestamp(created + timedelta(days=7)),
            }
        )
        sessions.append(session.id)
        refresh_ids.append(refresh.id)
    tally = PassCounts()
    root = db.port()
    await core._cleanup(CountingPort(root, root, tally), False)
    assert tally.candidates == sessions[:1]
    assert tally.auth_deleted == 2
    for index, session_id in enumerate(sessions):
        session_row = await private.sessions.find_by_id({"id": session_id})
        refresh_row = await private.refresh_tokens.find_by_id(
            {"id": refresh_ids[index]}
        )
        if index == 0:
            assert session_row is None and refresh_row is None
        else:
            assert session_row is not None and session_row.revoked_at is None
            assert refresh_row is not None


@pytest.mark.parametrize("minutes", [30, 120])
async def test_legacy_cleanup_selection_uses_safe_issue_bound(
    db: Harness, minutes: int
) -> None:
    """CLEANUP-SEL: detect premature selection, no legacy progress, or early access expiry."""
    core = Auth(db.port(), create_database, now=db.now, idle_timeout_seconds=3600)
    tokens = await core.signup(
        "legacy-cleanup@example.test", "a long cleanup test password"
    )
    private = PrivateDatabase(db.port())
    issued = db.now() - timedelta(minutes=minutes)
    await private.sessions.update(
        {"id": tokens.session_id},
        {
            "created_at": format_timestamp(db.now() - timedelta(days=1)),
            "first_login_at": None,
            "last_renewed_at": None,
            "expires_at": format_timestamp(issued + timedelta(seconds=900)),
        },
    )
    refresh = (await private.refresh_tokens.find_many())[0]
    await private.refresh_tokens.update(
        {"id": refresh.id},
        {
            "created_at": format_timestamp(issued),
            "expires_at": format_timestamp(db.now() + timedelta(days=6)),
        },
    )
    for _ in range(100):
        await private.refresh_tokens.insert(
            {
                "session_id": tokens.session_id,
                "token_hash": hash_token(random_token()),
                "created_at": format_timestamp(db.now() - timedelta(days=1)),
                "consumed_at": format_timestamp(issued),
                "expires_at": format_timestamp(db.now() + timedelta(days=6)),
            }
        )
    tally = PassCounts()
    root = db.port()
    for _ in range(4):
        await core._cleanup(CountingPort(root, root, tally), False)
    row = await private.sessions.find_by_id({"id": tokens.session_id})
    if minutes == 30:
        assert row is not None and tally.auth_attempts == 0
        assert tokens.session_id not in tally.candidates
    else:
        assert row is None and tally.auth_deleted == 102
        assert tokens.session_id in tally.candidates
