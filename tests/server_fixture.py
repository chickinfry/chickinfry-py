"""A disposable PostgreSQL fixture; credentials never leave this process."""

import os
import secrets
import shutil
import subprocess
import time
from collections.abc import AsyncIterator, Iterator, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
import pytest_asyncio

from chickinfry.orm import Column, DatabasePort, Repository, Table
from chickinfry.postgres import PostgresPort

from .auth_fixture import AUTH_DDL, read_int, read_optional, read_str

LABEL = Column[str]("label", "string")
NOTE = Column[str | None]('note"한', "string", True)
RANK = Column[int]("rank", "integer")
OBSERVED = Column[str | None]("observed_at", "timestamp", True)
HAPPENED = Column[str | None]("happened_on", "date", True)
RECORDS = Table(
    'records"한',
    {
        "id": Column[str]("id", "id"),
        "label": LABEL,
        "note": NOTE,
        "rank": RANK,
        "observed_at": OBSERVED,
        "happened_on": HAPPENED,
    },
    ("id",),
    ("label",),
)

PUBLIC_DDL = """
create table "records""한" (
    id uuid primary key default gen_random_uuid(), label text not null,
    "note""한" text default 'default', rank integer not null default 0,
    happened_on date, observed_at timestamptz
);
create table memberships (org text not null, member text not null, role text not null,
    primary key (org, member));
"""


@dataclass(frozen=True, slots=True)
class Record:
    id: str
    label: str
    note: str | None
    rank: int
    observed_at: str | None
    happened_on: str | None


def records(port: DatabasePort) -> Repository[Record]:
    def decode(row: Mapping[str, object]) -> Record:
        return Record(
            read_str(row["id"]),
            read_str(row["label"]),
            read_optional(row["note"]),
            read_int(row["rank"]),
            read_optional(row["observed_at"]),
            read_optional(row["happened_on"]),
        )

    return Repository(port, RECORDS, decode)


@dataclass(repr=False)
class PostgreSQL:
    _dsn: str
    certificate: Path

    def port(self) -> PostgresPort:
        return PostgresPort(self._dsn)


@pytest.fixture(scope="session")
def postgres(tmp_path_factory: pytest.TempPathFactory) -> Iterator[PostgreSQL]:
    assert shutil.disk_usage(tmp_path_factory.getbasetemp()).free >= 4 * 1024**3
    tls_dir = tmp_path_factory.mktemp("postgres-tls")
    certificate, key = tls_dir / "server.crt", tls_dir / "server.key"
    generated = subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        capture_output=True,
        timeout=15,
    )
    assert generated.returncode == 0, (
        "Could not generate the disposable TLS certificate."
    )
    name = "chickinfry-py238-" + uuid4().hex[:12]
    password = secrets.token_urlsafe(32)
    env = {**os.environ, "POSTGRES_PASSWORD": password}
    labels = ["--label", "com.chickinfry.test=python"]
    if run_id := os.environ.get("GITHUB_RUN_ID"):
        labels.extend(["--label", f"com.chickinfry.run={run_id}"])
    result = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "--pull",
            "missing",
            *labels,
            "--name",
            name,
            "-p",
            "127.0.0.1::5432",
            "-e",
            "POSTGRES_PASSWORD",
            "-e",
            "POSTGRES_USER=test",
            "-e",
            "POSTGRES_DB=test",
            "-v",
            f"{tls_dir}:/tls:ro",
            "postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873",
            "sh",
            "-c",
            "cp /tls/server.crt /tmp/server.crt && cp /tls/server.key /tmp/server.key && "
            "chown postgres:postgres /tmp/server.key && chmod 600 /tmp/server.key && "
            "exec docker-entrypoint.sh postgres -c ssl=on -c ssl_cert_file=/tmp/server.crt "
            "-c ssl_key_file=/tmp/server.key",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
    )
    try:
        assert result.returncode == 0, (
            f"Could not start the pinned PostgreSQL image: {result.stderr.strip()}"
        )
        deadline = time.monotonic() + 30
        while True:
            ready = subprocess.run(
                ["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "test"],
                capture_output=True,
                timeout=5,
            )
            if ready.returncode == 0:
                break
            assert time.monotonic() < deadline, "PostgreSQL startup did not complete."
            time.sleep(0.1)
        port_result = subprocess.run(
            ["docker", "port", name, "5432/tcp"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        assert port_result.returncode == 0
        port = int(port_result.stdout.strip().split(":")[-1])
        yield PostgreSQL(
            f"postgresql://test:{password}@127.0.0.1:{port}/test?sslmode=disable",
            certificate,
        )
    finally:
        stopped = subprocess.run(
            ["docker", "rm", "-fv", name], capture_output=True, timeout=30
        )
        assert stopped.returncode == 0, "PostgreSQL container cleanup failed."
        shutil.rmtree(tls_dir)


@dataclass(repr=False)
class Harness:
    postgres: PostgreSQL
    ports: list[PostgresPort] = field(default_factory=list)
    instant: datetime = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def port(self) -> PostgresPort:
        port = self.postgres.port()
        self.ports.append(port)
        return port

    def now(self) -> datetime:
        return self.instant


@pytest_asyncio.fixture
async def db(postgres: PostgreSQL, tmp_path: Path) -> AsyncIterator[Harness]:
    if shutil.disk_usage(tmp_path).free < 3 * 1024**3:
        pytest.exit(
            "Disk below 3 GiB; stopping and reclaiming the owned database.",
            returncode=1,
        )
    harness = Harness(postgres)
    setup = harness.port()
    try:
        await setup._execute("drop schema public cascade")
        await setup._execute("create schema public")
        await setup._execute(AUTH_DDL)
        await setup._execute(PUBLIC_DDL)
        yield harness
    finally:
        for port in harness.ports:
            await port.close()
