import asyncio
import json
import sys
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import TypeVar
from uuid import UUID

from chickinfry._auth_database import Database as PrivateDatabase
from chickinfry._auth_database import create_database
from chickinfry.auth import Auth, CleanupContext, hash_token, random_token
from chickinfry.orm import DatabasePort, format_timestamp
from chickinfry.postgres import PostgresPort

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
            }
        )
        await private.refresh_tokens.insert(
            {
                "id": str(UUID(int=i + 101)),
                "session_id": session.id,
                "token_hash": "veto" if i == 0 else hash_token(random_token()),
                "expires_at": old,
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
