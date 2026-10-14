import asyncio
import hashlib
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from datetime import timedelta
from typing import TypeVar
from uuid import uuid4

import pytest

from chickinfry._auth_database import (
    AppAuthInvitesRow,
    create_database,
)
from chickinfry._auth_database import (
    Database as PrivateDatabase,
)
from chickinfry.auth import (
    Auth,
    AuthDatabase,
    AuthHooks,
    AuthUser,
    CleanupContext,
    Identity,
    hash_token,
    random_token,
    validate_password,
)
from chickinfry.orm import DatabasePort, Filter, Repository, format_timestamp
from chickinfry.postgres import CommitOutcomeUnknown, PostgresPort
from chickinfry.server import ServerError, Session

from .server_fixture import Harness, records

PASSWORD = "a long test password 🎉"
T = TypeVar("T")


def auth(db: Harness, port: PostgresPort | None = None) -> Auth:
    return Auth(port if port is not None else db.port(), create_database, now=db.now)


async def test_tokens_expiry_and_logout(db: Harness) -> None:
    core = auth(db)
    initial = await core.signup(" New@Example.test ", PASSWORD)
    private = PrivateDatabase(db.port())
    user = await private.users.find_by_id({"id": initial.user_id})
    assert user is not None and user.email == "new@example.test"
    assert user.password_hash is not None and user.password_hash.startswith(
        "scrypt$32768$8$3$"
    )
    session = await private.sessions.find_by_id({"id": initial.session_id})
    refresh = (await private.refresh_tokens.find_many())[0]
    assert session is not None and session.token_hash == hash_token(
        initial.access_token
    )
    assert refresh.token_hash == hash_token(initial.refresh_token)
    assert (
        session.token_hash != initial.access_token
        and refresh.token_hash != initial.refresh_token
    )
    assert len(initial.access_token) == len(initial.refresh_token) == 43
    actor = await core.session(initial.access_token)
    assert (
        actor.id == initial.session_id
        and actor.user.id == initial.user_id
        and actor.id != actor.user.id
    )
    db.instant += timedelta(seconds=899)
    assert await core.session(initial.access_token) == actor
    db.instant += timedelta(seconds=1)
    with pytest.raises(ServerError) as expired:
        await core.session(initial.access_token)
    assert expired.value.code == "invalid_token"
    rotated = await core.refresh(initial.refresh_token)
    assert rotated.refresh_expires_at == initial.refresh_expires_at
    await core.logout(rotated.access_token)
    with pytest.raises(ServerError):
        await core.session(rotated.access_token)
    fresh = await core.signin("new@example.test", PASSWORD)
    db.instant += timedelta(days=7)
    with pytest.raises(ServerError) as family_expired:
        await core.refresh(fresh.refresh_token)
    assert family_expired.value.code == "session_revoked"
    revoked = await private.sessions.find_by_id({"id": fresh.session_id})
    assert revoked is not None and revoked.revoked_at is not None


async def test_missing_corrupt_and_mismatch_have_one_same_kdf(
    db: Harness, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = hashlib.scrypt
    calls: list[tuple[int, int, int, int, int, int]] = []

    def measured(
        password: bytes,
        *,
        salt: bytes,
        n: int,
        r: int,
        p: int,
        maxmem: int = 0,
        dklen: int = 64,
    ) -> bytes:
        key = original(password, salt=salt, n=n, r=r, p=p, maxmem=maxmem, dklen=dklen)
        calls.append((n, r, p, len(salt), len(key), maxmem))
        return key

    monkeypatch.setattr(hashlib, "scrypt", measured)
    core = Auth(db.port(), create_database, now=db.now)
    tokens = await core.signup("present@example.test", PASSWORD)
    calls.clear()
    for email in ("present@example.test", "absent@example.test"):
        with pytest.raises(ServerError) as failed:
            await core.signin(email, "a wrong long password")
        assert failed.value.code == "invalid_credentials"
    await PrivateDatabase(db.port()).users.update(
        {"id": tokens.user_id}, {"password_hash": "corrupt"}
    )
    with pytest.raises(ServerError):
        await core.signin("present@example.test", PASSWORD)
    assert calls == [(32768, 8, 3, 16, 32, 64 << 20)] * 3


@pytest.mark.parametrize(
    "password,accepted",
    [
        ("🎉" * 14, False),
        ("🎉" * 15, True),
        ("x" * 1023, True),
        ("x" * 1024, True),
        ("x" * 1025, False),
        ("🎉" * 256, True),
        ("🎉" * 257, False),
        ("x" * 14 + "\ud800", False),
    ],
)
def test_password_policy(password: str, accepted: bool) -> None:
    if accepted:
        validate_password(password)
    else:
        with pytest.raises(ServerError) as error:
            validate_password(password)
        assert error.value.code == "invalid_input"


class Rendezvous:
    def __init__(self) -> None:
        self.count = 0
        self.ready = asyncio.Event()

    async def arrive(self) -> None:
        self.count += 1
        if self.count == 2:
            self.ready.set()
        await self.ready.wait()


class ConcurrentPort(PostgresPort):
    def __init__(self, harness: Harness, gate: Rendezvous) -> None:
        super().__init__(harness.postgres._dsn)
        self.gate = gate
        harness.ports.append(self)

    async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
        await self.gate.arrive()
        return await super().transaction(work)


async def test_refresh_concurrency_commits_revocation(db: Harness) -> None:
    initial = await auth(db).signup("race@example.test", PASSWORD)
    gate = Rendezvous()
    cores = [auth(db, ConcurrentPort(db, gate)) for _ in range(2)]
    results = await asyncio.wait_for(
        asyncio.gather(
            *(core.refresh(initial.refresh_token) for core in cores),
            return_exceptions=True,
        ),
        10,
    )
    assert sum(not isinstance(result, BaseException) for result in results) == 1
    failures = [result for result in results if isinstance(result, ServerError)]
    assert len(failures) == 1 and failures[0].code == "session_revoked"
    private = PrivateDatabase(db.port())
    session = await private.sessions.find_by_id({"id": initial.session_id})
    assert session is not None and session.revoked_at is not None
    refresh = await private.refresh_tokens.find_many()
    assert (
        len(refresh) == 2 and sum(row.consumed_at is not None for row in refresh) == 1
    )


@pytest.mark.parametrize(
    "patch", [{"disabled_at": "2026-01-01T00:00:00Z"}, {"session_version": 2}]
)
async def test_user_revocation_checked_on_every_access_and_refresh(
    db: Harness, patch: dict[str, object]
) -> None:
    core = auth(db)
    tokens = await core.signup("revoke@example.test", PASSWORD)
    private = PrivateDatabase(db.port())
    await private.users.update({"id": tokens.user_id}, patch)
    with pytest.raises(ServerError):
        await core.session(tokens.access_token)
    with pytest.raises(ServerError):
        await core.refresh(tokens.refresh_token)
    row = await private.sessions.find_by_id({"id": tokens.session_id})
    assert row is not None and row.revoked_at is not None


async def test_native_rejects_browser_session(db: Harness) -> None:
    core = auth(db)
    tokens = await core.signup("browser@example.test", PASSWORD)
    await PrivateDatabase(db.port()).sessions.update(
        {"id": tokens.session_id}, {"transport": "browser"}
    )
    with pytest.raises(ServerError) as invalid:
        await core.session(tokens.access_token)
    assert invalid.value.code == "invalid_token"
    with pytest.raises(ServerError):
        await core.refresh(tokens.refresh_token)


async def test_creating_hook_rolls_back_business_user_session_and_invite(
    db: Harness,
) -> None:
    owner = await auth(db).signup("owner@example.test", PASSWORD)
    private = PrivateDatabase(db.port())
    code = random_token()
    invite = await private.invites.insert(
        {
            "email": "invited@example.test",
            "issued_by": owner.user_id,
            "code_hash": hash_token(code),
            "expires_at": format_timestamp(db.now() + timedelta(days=7)),
        }
    )
    committed: list[AuthUser] = []

    async def creating(port: DatabasePort, user: AuthUser) -> None:
        await records(port).insert({"label": user.id})
        raise ValueError("private hook details")

    async def created(user: AuthUser) -> None:
        committed.append(user)

    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        signup="invite-only",
        hooks=AuthHooks(user_creating=creating, user_created=created),
    )
    with pytest.raises(ServerError) as failed:
        await core.signup("invited@example.test", PASSWORD, code)
    assert failed.value.code == "user_creation_failed"
    assert await records(db.port()).find_many() == [] and committed == []
    assert (
        len(await private.users.find_many())
        == len(await private.sessions.find_many())
        == 1
    )
    again = await private.invites.find_by_id({"id": invite.id})
    assert again is not None and again.redeemed_at is None and again.redeemed_by is None


async def test_created_hook_observes_commit_failure_retains_account(
    db: Harness,
) -> None:
    calls = 0

    async def creating(port: DatabasePort, user: AuthUser) -> None:
        await records(port).insert({"label": user.id})

    async def created(user: AuthUser) -> None:
        nonlocal calls
        calls += 1
        assert (
            await PrivateDatabase(db.port()).users.find_by_id({"id": user.id})
            is not None
        )
        assert len(await records(db.port()).find_many()) == 1
        raise ValueError("external effect failed")

    core = Auth(
        db.port(), create_database, now=db.now, hooks=AuthHooks(creating, created)
    )
    with pytest.raises(ServerError) as failed:
        await core.signup("retained@example.test", PASSWORD)
    assert failed.value.code == "user_created_effect_failed" and calls == 1
    await core.signin("retained@example.test", PASSWORD)
    with pytest.raises(ServerError):
        await core.signup("retained@example.test", PASSWORD)
    assert calls == 1


async def test_unknown_signup_commit_does_not_call_created_or_repeat(
    db: Harness,
) -> None:
    class LostCommit(PostgresPort):
        async def _execute(self, sql: str) -> None:
            await super()._execute(sql)
            if sql == "commit":
                raise ConnectionError

    port = LostCommit(db.postgres._dsn)
    db.ports.append(port)
    calls = 0

    async def created(user: AuthUser) -> None:
        nonlocal calls
        calls += 1

    core = Auth(
        port, create_database, now=db.now, hooks=AuthHooks(user_created=created)
    )
    with pytest.raises(CommitOutcomeUnknown):
        await core.signup("uncertain@example.test", PASSWORD)
    assert calls == 0 and len(await PrivateDatabase(db.port()).users.find_many()) == 1


async def test_invite_management_replay_metadata_and_signup_race(db: Harness) -> None:
    owner = await auth(db).signup("owner@example.test", PASSWORD)
    project = str(uuid4())
    authorizations: list[str] = []

    async def manage(port: DatabasePort, actor: Session, project_id: str) -> None:
        assert actor.user.id == owner.user_id
        authorizations.append(project_id)

    hooks = AuthHooks(invite_managing=manage)
    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        signup="invite-only",
        project_id=project,
        hooks=hooks,
    )
    id = str(uuid4())
    issued = await core.invite_issue(owner.access_token, id, "Invited@Example.test")
    assert issued["email"] == "invited@example.test" and issued["status"] == "issued"
    with pytest.raises(ServerError) as replay:
        await core.invite_issue(owner.access_token, id, "invited@example.test")
    assert replay.value.code == "invite_issue_replayed"
    page = await core.invite_list(owner.access_token, "")
    assert isinstance(page["items"], list) and "code" not in page["items"][0]
    assert authorizations and set(authorizations) == {project}
    for email, code in (
        ("wrong@example.test", issued["code"]),
        ("invited@example.test", ""),
        ("invited@example.test", "A" * 42 + "B"),
    ):
        with pytest.raises(ServerError):
            await core.signup(email, PASSWORD, code)
    gate = Rendezvous()

    class Provider:
        id = "invited"

        async def verify(self, credential: object) -> Identity:
            return Identity("invited-subject", "invited@example.test")

    cores = [
        Auth(
            ConcurrentPort(db, gate),
            create_database,
            now=db.now,
            signup="invite-only",
            providers=[Provider()],
        )
        for _ in range(2)
    ]
    results = await asyncio.wait_for(
        asyncio.gather(
            cores[0].signup("invited@example.test", PASSWORD, issued["code"]),
            cores[1].signin_identity("invited", "credential", issued["code"]),
            return_exceptions=True,
        ),
        10,
    )
    assert sum(not isinstance(result, BaseException) for result in results) == 1
    private = PrivateDatabase(db.port())
    assert len(await private.users.find_many()) == 2

    invite = await private.invites.find_by_id({"id": id})
    assert (
        invite is not None
        and invite.redeemed_by is not None
        and invite.redeemed_at is not None
    )
    with pytest.raises(ServerError) as redeemed:
        await core.invite_revoke(owner.access_token, id)
    assert redeemed.value.code == "invite_already_redeemed"
    other_id = str(uuid4())
    other = await core.invite_issue(owner.access_token, other_id, "other@example.test")
    assert (await core.invite_revoke(owner.access_token, other_id))[
        "status"
    ] == "revoked"
    with pytest.raises(ServerError):
        await core.signup("other@example.test", PASSWORD, other["code"])
    assert len(await private.users.find_many()) == 2


@pytest.mark.parametrize("identity", [False, True])
async def test_invite_expiry_rechecked_after_real_lock(
    db: Harness, identity: bool
) -> None:
    private = PrivateDatabase(db.port())
    owner = await private.users.insert({"email": "owner@example.test"})
    expiry = db.now() + timedelta(seconds=10)
    code = random_token()
    invite = await private.invites.insert(
        {
            "email": "blocked@example.test",
            "issued_by": owner.id,
            "code_hash": hash_token(code),
            "expires_at": format_timestamp(expiry),
        }
    )
    held, attempted, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def lock(port: DatabasePort) -> None:
        await PrivateDatabase(port).invites.update(
            {"id": invite.id}, {"expires_at": invite.expires_at}
        )
        held.set()
        await release.wait()

    class ObservedInvites(Repository[AppAuthInvitesRow]):
        async def update_if(
            self,
            key: Mapping[str, object],
            condition: Filter,
            patch: Mapping[str, object],
        ) -> AppAuthInvitesRow | None:
            attempted.set()
            return await super().update_if(key, condition, patch)

    def observed(port: DatabasePort) -> AuthDatabase:
        database = PrivateDatabase(port)
        database.invites = ObservedInvites(
            port, database.invites.table, database.invites.row
        )
        return database

    class Provider:
        id = "blocked"

        async def verify(self, credential: object) -> Identity:
            return Identity("blocked-subject", "blocked@example.test")

    async def creating(port: DatabasePort, user: AuthUser) -> None:
        await records(port).insert({"label": user.id})

    core = Auth(
        db.port(),
        observed,
        now=db.now,
        signup="invite-only",
        providers=[Provider()],
        hooks=AuthHooks(user_creating=creating),
    )
    locker = asyncio.create_task(db.port().transaction(lock))
    signup: asyncio.Task[object] | None = None
    try:
        await asyncio.wait_for(held.wait(), 2)
        signup = asyncio.create_task(
            core.signin_identity("blocked", "credential", code)
            if identity
            else core.signup("blocked@example.test", PASSWORD, code)
        )
        await asyncio.wait_for(attempted.wait(), 2)
        observer = db.port()
        async with asyncio.timeout(2):
            while not await observer.query(
                "select pid from pg_stat_activity where wait_event_type='Lock' "
                "and query like '%app_auth_invites%'",
                (),
            ):
                pass
        db.instant = expiry
        release.set()
        with pytest.raises(ServerError) as expired:
            await asyncio.wait_for(signup, 2)
        assert expired.value.code == "invite_invalid"
        await locker
        assert len(await private.users.find_many()) == 1
        assert (
            await private.sessions.find_many() == []
            and await private.identities.find_many() == []
        )
        assert await records(db.port()).find_many() == []
        unconsumed = await private.invites.find_by_id({"id": invite.id})
        assert (
            unconsumed is not None
            and unconsumed.redeemed_at is None
            and unconsumed.redeemed_by is None
        )
    finally:
        release.set()
        if signup is not None:
            signup.cancel()
            await asyncio.gather(signup, return_exceptions=True)
        locker.cancel()
        await asyncio.gather(locker, return_exceptions=True)


@pytest.mark.parametrize("variant", ["missing", "wrong-email", "expired", "valid"])
async def test_invite_only_requires_invite_for_new_identity(
    db: Harness, variant: str
) -> None:
    private = PrivateDatabase(db.port())
    owner = await private.users.insert({"email": "owner@example.test"})
    email = "identity-invite@example.test"
    code = random_token()
    invite = await private.invites.insert(
        {
            "email": "wrong@example.test" if variant == "wrong-email" else email,
            "issued_by": owner.id,
            "code_hash": hash_token(code),
            "expires_at": format_timestamp(
                db.now() + timedelta(seconds=-1 if variant == "expired" else 900)
            ),
        }
    )

    class Provider:
        id = "invited"

        async def verify(self, credential: object) -> Identity:
            return Identity("verified-subject", email)

    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        signup="invite-only",
        providers=[Provider()],
    )
    if variant == "valid":
        tokens = await core.signin_identity("invited", "credential", code)
        assert (
            await core.signin_identity("invited", "credential")
        ).user_id == tokens.user_id
        assert (
            len(await private.users.find_many()) == 2
            and len(await private.identities.find_many()) == 1
        )
        redeemed = await private.invites.find_by_id({"id": invite.id})
        assert redeemed is not None and redeemed.redeemed_by == tokens.user_id
    else:
        with pytest.raises(ServerError) as denied:
            await core.signin_identity(
                "invited", "credential", "" if variant == "missing" else code
            )
        assert denied.value.status == 403
        assert len(await private.users.find_many()) == 1
        assert (
            await private.sessions.find_many() == []
            and await private.identities.find_many() == []
        )
        unconsumed = await private.invites.find_by_id({"id": invite.id})
        assert unconsumed is not None and unconsumed.redeemed_at is None


async def test_invite_management_requires_hook_project_and_session(db: Harness) -> None:
    owner = await auth(db).signup("owner@example.test", PASSWORD)
    core = Auth(db.port(), create_database, now=db.now, signup="invite-only")
    with pytest.raises(ServerError) as denied:
        await core.invite_list(owner.access_token, "")
    assert denied.value.code == "permission_denied"

    async def allowed(port: DatabasePort, actor: Session, project: str) -> None:
        return None

    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        signup="invite-only",
        hooks=AuthHooks(invite_managing=allowed),
    )
    with pytest.raises(ServerError) as unbound:
        await core.invite_list(owner.access_token, "")
    assert unbound.value.code == "service_unavailable"
    with pytest.raises(ServerError):
        await core.invite_list(random_token(), "")


async def test_custom_identity_does_not_link_by_email_and_charges_failures(
    db: Harness,
) -> None:
    calls: list[AuthUser] = []

    async def created(user: AuthUser) -> None:
        calls.append(user)

    class Provider:
        id = "external"

        async def verify(self, credential: object) -> Identity:
            if credential == "bad":
                raise ValueError
            assert isinstance(credential, str)
            return Identity(credential, "identity@example.test")

    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        providers=[Provider()],
        hooks=AuthHooks(user_created=created),
    )
    first = await core.signin_identity("external", "subject-one")
    assert (
        await core.signin_identity("external", "subject-one")
    ).user_id == first.user_id
    assert len(calls) == 1
    with pytest.raises(ServerError) as conflict:
        await core.signin_identity("external", "subject-two")
    assert conflict.value.code == "identity_conflict"
    private = PrivateDatabase(db.port())
    await private.rate_limits.insert(
        {
            "action": "identity_attempt",
            "key_hash": hash_token("budget"),
            "attempt_count": 99,
            "expires_at": format_timestamp(db.now() + timedelta(seconds=60)),
        }
    )

    class BudgetProvider(Provider):
        id = "budget"

    budget = Auth(db.port(), create_database, now=db.now, providers=[BudgetProvider()])
    with pytest.raises(ServerError) as invalid:
        await budget.signin_identity("budget", "bad")
    assert invalid.value.code == "invalid_credentials"
    with pytest.raises(ServerError) as limited:
        await budget.signin_identity("budget", "different")
    assert limited.value.code == "rate_limited"
    assert len(await private.users.find_many()) == 1


async def test_cleanup_separate_connection_bounded_and_preserves_referenced_sessions(
    db: Harness,
) -> None:
    core = auth(db)
    owner = await core.signup("cleanup@example.test", PASSWORD)
    private = PrivateDatabase(db.port())
    old = format_timestamp(db.now() - timedelta(days=40))
    for i in range(33):
        await private.rate_limits.insert(
            {"action": "old", "key_hash": str(i), "attempt_count": 1, "expires_at": old}
        )
        await private.invites.insert(
            {
                "email": "expired@example.test",
                "code_hash": hash_token(random_token()),
                "issued_by": owner.user_id,
                "expires_at": old,
            }
        )
    expired_session = await private.sessions.insert(
        {
            "user_id": owner.user_id,
            "token_hash": hash_token(random_token()),
            "user_session_version": 1,
            "expires_at": old,
        }
    )
    await private.refresh_tokens.insert(
        {
            "session_id": expired_session.id,
            "token_hash": hash_token(random_token()),
            "expires_at": format_timestamp(db.now() + timedelta(days=1)),
        }
    )
    tasks: list[asyncio.Task[None]] = []
    ports: list[PostgresPort] = []

    def create_port() -> PostgresPort:
        port = db.port()
        ports.append(port)
        return port

    def schedule(work: Coroutine[None, None, None]) -> None:
        tasks.append(asyncio.create_task(work))

    cleanup = CleanupContext(create_port, schedule)
    sign = Auth(db.port(), create_database, now=db.now, cleanup=cleanup)
    tokens = await sign.signin("cleanup@example.test", PASSWORD)
    await asyncio.gather(*tasks)
    assert await sign.session(tokens.access_token)
    assert len(ports) == 1 and ports[0]._closed and ports[0]._connection is None
    assert (
        len(
            await private.rate_limits.find_many(
                where=Filter("=", private.rate_limits.table.columns["action"], ("old",))
            )
        )
        == 1
    )
    assert len(await private.invites.find_many()) == 1
    assert await private.sessions.find_by_id({"id": expired_session.id}) is not None
    stages: list[str] = []

    def broken_port() -> PostgresPort:
        raise RuntimeError("details that must stay private")

    broken = Auth(
        db.port(),
        create_database,
        now=db.now,
        cleanup=CleanupContext(broken_port, schedule, stages.append),
    )
    tokens = await broken.signin("cleanup@example.test", PASSWORD)
    await asyncio.gather(*tasks)
    assert await broken.session(tokens.access_token) and stages == ["port"]


async def test_schema_absence_never_triggers_runtime_ddl(db: Harness) -> None:
    port = db.port()
    await port._execute("drop schema public cascade")
    await port._execute("create schema public")
    with pytest.raises(Exception):
        await auth(db).signup("absent@example.test", PASSWORD)
    tables = await port.query(
        "select tablename from pg_tables where schemaname='public'", ()
    )
    assert tables == []
