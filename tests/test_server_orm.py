import asyncio
from collections.abc import Mapping
from dataclasses import FrozenInstanceError

import pytest

from chickinfry.orm import (
    Column,
    Database,
    DatabasePort,
    Filter,
    Order,
    Repository,
    Table,
    and_,
    not_,
    or_,
)
from chickinfry.postgres import CommitOutcomeUnknown, PostgresPort

from .server_fixture import (
    HAPPENED,
    LABEL,
    NOTE,
    OBSERVED,
    RANK,
    Harness,
    Record,
    records,
)


async def test_defaults_keys_conditions_and_parameters(db: Harness) -> None:
    repo = records(db.port())
    row = await repo.insert({"label": "quote' ; \ud55c\U0001f389"})
    assert row.note == "default" and row.rank == 0
    with pytest.raises(FrozenInstanceError):
        setattr(row, "label", "changed")
    null = await repo.insert({"label": "nullable", "note": None, "rank": 1})
    await repo.insert({"label": "third", "rank": 2})
    assert await repo.find_by_id({"id": row.id}) == row
    assert (await repo.find_many(where=LABEL.equals(row.label))) == [row]
    assert (
        await repo.find_many(
            where=NOTE.in_([None, "default"]), order_by=[RANK.desc()], limit=2, offset=1
        )
    ) == [null, row]
    assert await repo.find_many(where=LABEL.in_([])) == []
    assert await repo.find_many(where=and_(NOTE.is_null(), RANK.greater_than(0))) == [
        null
    ]
    assert await repo.find_many(where=not_(NOTE.is_not_null())) == [null]
    assert await repo.find_many(
        where=or_(RANK.less_than(0), RANK.greater_than_or_equals(2))
    )
    updated = await repo.update({"id": row.id}, {"label": "updated"})
    assert updated.id == row.id and updated.note == "default"
    assert (
        await repo.update_if({"id": row.id}, LABEL.equals("unmatched"), {"rank": 9})
        is None
    )
    assert await repo.delete({"id": row.id}) == updated
    assert await repo.delete({"id": row.id}) is None
    with pytest.raises(ValueError, match="missing"):
        await repo.update({"id": row.id}, {"rank": 8})
    columns = {
        "org": Column[str]("org", "string"),
        "member": Column[str]("member", "string"),
        "role": Column[str]("role", "string"),
    }
    table = Table("memberships", columns, ("org", "member"), ("org", "member", "role"))

    def decode(value: Mapping[str, object]) -> Mapping[str, object]:
        return value

    members = Repository(db.port(), table, decode)
    await members.insert({"org": "one", "member": "two", "role": "owner"})
    assert await members.find_by_id({"org": "one", "member": "two"}) is not None
    with pytest.raises(ValueError, match="primary key"):
        await members.find_by_id({"org": "one"})
    with pytest.raises(ValueError, match="Unknown"):
        await members.update({"org": "one", "member": "two"}, {"member": "other"})


@pytest.mark.parametrize(
    "values",
    [
        {},
        {"label": None},
        {"label": "\0"},
        {"label": "ok", "rank": True},
        {"label": "ok", "rank": 2147483648},
        {"label": "ok", "rank": 1.5},
        {"label": "ok", "extra": 1},
        {"label": "ok", "happened_on": "2026-02-30"},
        {"label": "ok", "happened_on": "２０２６-01-01"},
        {"label": "ok", "observed_at": "2026-01-01T00:00:00"},
        {"label": "ok", "observed_at": "2026-01-01T00:00:60Z"},
        {"label": "ok", "observed_at": "2026-01-01T00:00:00.1234567Z"},
        {"label": "ok", "observed_at": "2026-01-01T00:00:00+01:60"},
        {"label": "ok", "observed_at": "0000-01-01T00:00:00Z"},
        {"label": "ok", "observed_at": "10000-01-01T00:00:00Z"},
        {"label": "ok", "observed_at": "0001-01-01T00:00:00+01:00"},
        {"label": "ok", "observed_at": "9999-12-31T23:59:59-01:00"},
    ],
)
async def test_invalid_orm_inputs(db: Harness, values: dict[str, object]) -> None:
    repo = records(db.port())
    with pytest.raises((ValueError, OverflowError)):
        await repo.insert(values)
    assert await repo.find_many() == []


async def test_invalid_queries_before_sql(db: Harness) -> None:
    port = db.port()
    repo = records(port)
    for limit in (True, -1, 9007199254740992):
        with pytest.raises(ValueError):
            await repo.find_many(limit=limit)
    for condition in (
        Filter("=", Column[str]("label", "string"), ("x",)),
        Filter(">", NOTE, (None,)),
        Filter("=", RANK, ("wrong",)),
        Filter("injection", LABEL, ("x",)),
    ):
        with pytest.raises(ValueError):
            await repo.find_many(where=condition)
    with pytest.raises(ValueError):
        await repo.find_many(order_by=[Order(Column[str]("label", "string"), "asc")])
    with pytest.raises(ValueError):
        await repo.update(
            {"id": "12345678-1234-1234-1234-123456789abc"}, {"id": "anything"}
        )
    with pytest.raises(ValueError):
        await repo.update({"id": "12345678-1234-1234-1234-123456789abc"}, {})
    assert port._connection is None


@pytest.mark.parametrize(
    "value,canonical",
    [
        ("2026-01-02T12:04:05.123456+09:00", "2026-01-02T03:04:05.123456Z"),
        ("2026-01-02 03:04:05.000001+00", "2026-01-02T03:04:05.000001Z"),
        ("2026-01-02T03:04:05.120000Z", "2026-01-02T03:04:05.120Z"),
        ("2026-01-02T03:04:05.123400Z", "2026-01-02T03:04:05.1234Z"),
        ("2026-01-02T03:04:05.123450Z", "2026-01-02T03:04:05.12345Z"),
        ("2026-01-02T03:04:05Z", "2026-01-02T03:04:05.000Z"),
        ("0001-01-01T00:00:00Z", "0001-01-01T00:00:00.000Z"),
        ("9999-12-31T23:59:59.999999Z", "9999-12-31T23:59:59.999999Z"),
        ("2026-01-01T00:00:00.100001+01:00", "2025-12-31T23:00:00.100001Z"),
    ],
)
async def test_temporal_precision(db: Harness, value: str, canonical: str) -> None:
    repo = records(db.port())
    row = await repo.insert(
        {"label": "time", "happened_on": "0001-01-01", "observed_at": value}
    )
    assert row.happened_on == "0001-01-01" and row.observed_at == canonical
    assert await repo.find_many(
        where=and_(HAPPENED.equals("0001-01-01"), OBSERVED.equals(canonical))
    ) == [row]
    again = await repo.update(
        {"id": row.id}, {"observed_at": row.observed_at, "happened_on": "9999-12-31"}
    )
    assert again.observed_at == canonical and again.happened_on == "9999-12-31"


@pytest.mark.parametrize("kind", ["date", "timestamptz"])
@pytest.mark.parametrize("value", ["infinity", "-infinity"])
async def test_infinity_rejected(db: Harness, kind: str, value: str) -> None:
    with pytest.raises(ValueError):
        await db.port().query(f"select $1::text::{kind}", (value,))


async def test_transaction_lifetime_and_root_reentry(db: Harness) -> None:
    port = db.port()
    repo = records(port)
    saved: list[DatabasePort] = []
    backend = (await port.query("select pg_backend_pid() as pid", ()))[0]["pid"]

    async def work(tx: DatabasePort) -> None:
        saved.append(tx)
        assert (await tx.query("select pg_backend_pid() as pid", ()))[0][
            "pid"
        ] == backend
        await records(tx).insert({"label": "committed"})
        with pytest.raises(RuntimeError, match="Nested"):
            await tx.transaction(work)
        with pytest.raises(RuntimeError, match="reentry"):
            await repo.find_many()
        with pytest.raises(RuntimeError, match="reentry"):
            await asyncio.create_task(repo.find_many())

    await port.transaction(work)
    assert len(await repo.find_many()) == 1
    with pytest.raises(RuntimeError, match="no longer active"):
        await records(saved[0]).find_many()

    async def fail(tx: Repository[Record]) -> None:
        await tx.insert({"label": "rolled back"})
        raise ValueError("original failure")

    with pytest.raises(ValueError, match="original failure"):
        await Database(port, records).transaction(fail)
    assert len(await repo.find_many()) == 1


async def test_uncertain_commit_is_not_retried(db: Harness) -> None:
    class LostCommit(PostgresPort):
        commits = 0

        async def _execute(self, sql: str) -> None:
            await super()._execute(sql)
            if sql == "commit":
                self.commits += 1
                raise ConnectionError("acknowledgement lost")

    port = LostCommit(db.postgres._dsn)
    db.ports.append(port)
    calls = 0

    async def work(tx: DatabasePort) -> None:
        nonlocal calls
        calls += 1
        await records(tx).insert({"label": "persisted"})

    with pytest.raises(CommitOutcomeUnknown) as failure:
        await port.transaction(work)
    assert failure.value.outcome_unknown and calls == 1 and port.commits == 1
    assert port._closed and port._connection is None
    assert len(await records(db.port()).find_many()) == 1


async def test_cancel_rolls_back_and_closes_connection(db: Harness) -> None:
    port = db.port()
    started = asyncio.Event()

    async def work(tx: DatabasePort) -> None:
        await records(tx).insert({"label": "cancelled"})
        started.set()
        await asyncio.Future[None]()

    task = asyncio.create_task(port.transaction(work))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await port.close()
    assert await records(db.port()).find_many() == []
    assert port._connection is None
