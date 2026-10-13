import asyncio
from collections.abc import Coroutine

import pytest

import chickinfry.postgres as postgres_module
from chickinfry.auth import Auth, CleanupContext
from chickinfry.orm import DatabasePort
from chickinfry.postgres import PostgresPort

from .auth_fixture import create_database
from .server_fixture import Harness
from .server_peer import stalled_peer


async def received_by_database(db: Harness) -> None:
    observer = db.port()
    async with asyncio.timeout(2):
        while not await observer.query(
            "select pid from pg_stat_activity where query like '%pg_sleep(120)%' "
            "and pid <> pg_backend_pid() and state='active'",
            (),
        ):
            pass


@pytest.mark.parametrize("transaction", [False, True])
async def test_cancel_stalled_query_terminates_port(
    db: Harness, transaction: bool
) -> None:
    async with stalled_peer(db.postgres, b"pg_sleep") as peer:
        port = PostgresPort(peer.dsn(db.postgres))

        async def slow(tx: DatabasePort) -> None:
            await tx.query("select pg_sleep(120)", ())

        task = asyncio.create_task(
            port.transaction(slow) if transaction else slow(port)
        )
        try:
            await asyncio.wait_for(peer.received.wait(), 2)
            await received_by_database(db)
            task.cancel()
            done, _ = await asyncio.wait({task}, timeout=1)
            assert task in done, "Cancellation waited for a stalled database response."
            with pytest.raises(asyncio.CancelledError):
                await task
            await asyncio.wait_for(peer.closed.wait(), 1)
            assert port._closed and port._connection is None
        finally:
            port.terminate()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_rollback_stall_keeps_original_failure_and_terminates(
    db: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(postgres_module, "_CLEANUP_SECONDS", 0.1)
    async with stalled_peer(db.postgres, b"rollback") as peer:
        port = PostgresPort(peer.dsn(db.postgres))

        async def fail(tx: DatabasePort) -> None:
            raise ValueError("original business failure")

        task = asyncio.create_task(port.transaction(fail))
        try:
            await asyncio.wait_for(peer.received.wait(), 2)
            done, _ = await asyncio.wait({task}, timeout=1)
            assert task in done, "Rollback exceeded its cleanup deadline."
            with pytest.raises(ValueError, match="original business failure"):
                await task
            await asyncio.wait_for(peer.closed.wait(), 1)
            assert port._closed and port._connection is None
        finally:
            port.terminate()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_close_bounds_driver_pending_cancel(
    db: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(postgres_module, "_CLEANUP_SECONDS", 0.1)
    async with stalled_peer(db.postgres, b"pg_sleep") as peer:
        port = PostgresPort(peer.dsn(db.postgres))
        connection = await port._connect()
        query = asyncio.create_task(connection.fetch("select pg_sleep(120)"))
        closing: asyncio.Task[None] | None = None
        try:
            await asyncio.wait_for(peer.received.wait(), 2)
            await received_by_database(db)
            query.cancel()
            with pytest.raises(asyncio.CancelledError):
                await query
            closing = asyncio.create_task(port.close())
            done, _ = await asyncio.wait({closing}, timeout=1)
            assert closing in done, "Close waited indefinitely for pending cancel."
            with pytest.raises(TimeoutError):
                await closing
            await asyncio.wait_for(peer.closed.wait(), 1)
            assert port._closed and port._connection is None
        finally:
            port.terminate()
            query.cancel()
            if closing is not None:
                closing.cancel()
                await asyncio.gather(closing, return_exceptions=True)
            await asyncio.gather(query, return_exceptions=True)


async def test_auth_cleanup_bounds_nonreturning_close(db: Harness) -> None:
    class NonReturningClose(PostgresPort):
        async def close(self) -> None:
            await asyncio.Future[None]()

    port = NonReturningClose(db.postgres._dsn)
    tasks: list[asyncio.Task[None]] = []
    stages: list[str] = []

    def schedule(work: Coroutine[None, None, None]) -> None:
        tasks.append(asyncio.create_task(work))

    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        cleanup=CleanupContext(lambda: port, schedule, stages.append),
    )
    core._schedule_cleanup()
    try:
        done, _ = await asyncio.wait(set(tasks), timeout=6)
        assert len(done) == 1, "Auth cleanup close exceeded its deadline."
        await tasks[0]
        assert stages == ["close"] and port._closed and port._connection is None
    finally:
        port.terminate()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
