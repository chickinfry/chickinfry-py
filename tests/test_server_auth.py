import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable, Coroutine, Mapping
from datetime import datetime, timedelta
from typing import TypeVar, cast
from uuid import uuid4

import pytest

from chickinfry._auth_database import (
    AppAuthInvitesRow,
    AppAuthSessionsRow,
    AppAuthUsersRow,
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
    Tokens,
    hash_token,
    random_token,
    validate_password,
)
from chickinfry.orm import (
    DatabasePort,
    Filter,
    Repository,
    format_timestamp,
    parse_timestamp,
)
from chickinfry.postgres import CommitOutcomeUnknown, PostgresPort
from chickinfry.server import OperationError, Session

from .server_fixture import Harness, records

PASSWORD = "a long test password 🎉"
T = TypeVar("T")


def auth(
    db: Harness,
    port: PostgresPort | None = None,
    *,
    idle: int = 2592000,
    absolute: int = 0,
) -> Auth:
    return Auth(
        port if port is not None else db.port(),
        create_database,
        now=db.now,
        idle_timeout_seconds=idle,
        absolute_lifetime_seconds=absolute,
    )


@pytest.mark.parametrize("operation", ["signin", "refresh"])
async def test_email_verified_wire_output(db: Harness, operation: str) -> None:
    core = auth(db)
    initial = await core.signup("verification@example.test", PASSWORD)
    tokens = (
        await core.signin("verification@example.test", PASSWORD)
        if operation == "signin"
        else await core.refresh(initial.refresh_token)
    )
    wire = json.loads(json.dumps(tokens.to_wire()))
    assert type(wire.get("email_verified")) is bool
    assert wire.pop("email_verified") is False
    unchanged = wire == {
        "access_token": tokens.access_token,
        "refresh_token": tokens.refresh_token,
        "expires_at": tokens.expires_at,
        "refresh_expires_at": tokens.refresh_expires_at,
        "user_id": tokens.user_id,
        "session_id": tokens.session_id,
    }
    assert unchanged


async def test_tokens_expiry_and_logout(db: Harness) -> None:
    """M01/S-M3, M06/M07: reject fixed family expiry and access-driven renewal."""
    db.instant += timedelta(microseconds=123456)
    started = db.now()
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
    assert (
        session.created_at
        == session.first_login_at
        == session.last_renewed_at
        == format_timestamp(started)
    )
    assert refresh.created_at == format_timestamp(started)
    assert parse_timestamp(initial.refresh_expires_at) == started + timedelta(days=30)
    actor = await core.session(initial.access_token)
    assert type(actor.user.email_verified) is bool
    assert actor.user.email_verified is False
    assert (
        actor.id == initial.session_id
        and actor.user.id == initial.user_id
        and actor.id != actor.user.id
    )
    db.instant += timedelta(seconds=899)
    assert await core.session(initial.access_token) == actor
    observed = await private.sessions.find_by_id({"id": initial.session_id})
    assert observed is not None and observed.last_renewed_at == session.last_renewed_at
    db.instant += timedelta(seconds=1)
    with pytest.raises(OperationError) as expired:
        await core.session(initial.access_token)
    assert expired.value.code == "invalid_token"
    rotated = await core.refresh(initial.refresh_token)
    assert parse_timestamp(rotated.refresh_expires_at) == db.now() + timedelta(days=30)
    await core.logout(rotated.access_token)
    with pytest.raises(OperationError):
        await core.session(rotated.access_token)
    fresh = await core.signin("new@example.test", PASSWORD)
    first = db.now()
    for days in (29, 31):
        db.instant = first + timedelta(days=days)
        fresh = await core.refresh(fresh.refresh_token)
        observed = await private.sessions.find_by_id({"id": fresh.session_id})
        assert observed is not None
        assert observed.created_at == observed.first_login_at == format_timestamp(first)
        assert observed.last_renewed_at == format_timestamp(db.now())
        assert parse_timestamp(observed.expires_at) == db.now() + timedelta(seconds=900)
        assert parse_timestamp(fresh.refresh_expires_at) == first + timedelta(
            days=days + 30
        )
    db.instant += timedelta(days=30)
    with pytest.raises(OperationError) as family_expired:
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
        with pytest.raises(OperationError) as failed:
            await core.signin(email, "a wrong long password")
        assert failed.value.code == "invalid_credentials"
    await PrivateDatabase(db.port()).users.update(
        {"id": tokens.user_id}, {"password_hash": "corrupt"}
    )
    with pytest.raises(OperationError):
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
        with pytest.raises(OperationError) as error:
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
    """M11: detect missing single-consumption or rolled-back family revocation."""
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
    failures = [result for result in results if isinstance(result, OperationError)]
    assert len(failures) == 1 and failures[0].code == "session_revoked"
    private = PrivateDatabase(db.port())
    session = await private.sessions.find_by_id({"id": initial.session_id})
    assert session is not None and session.revoked_at is not None
    refresh = await private.refresh_tokens.find_many()
    assert (
        len(refresh) == 2 and sum(row.consumed_at is not None for row in refresh) == 1
    )
    assert session.last_renewed_at == format_timestamp(db.now())
    winner = next(result for result in results if isinstance(result, Tokens))
    for tokens in (initial, winner):
        with pytest.raises(OperationError):
            await auth(db).session(tokens.access_token)
        with pytest.raises(OperationError):
            await auth(db).refresh(tokens.refresh_token)
    unchanged = await private.sessions.find_by_id({"id": session.id}) == session
    assert unchanged


@pytest.mark.parametrize(
    "patch", [{"disabled_at": "2026-01-01T00:00:00Z"}, {"session_version": 2}]
)
async def test_user_revocation_checked_on_every_access_and_refresh(
    db: Harness, patch: dict[str, object]
) -> None:
    core = auth(db)
    tokens = await core.signup("revoke@example.test", PASSWORD)
    private = PrivateDatabase(db.port())
    before = await private.sessions.find_by_id({"id": tokens.session_id})
    previous = await private.refresh_tokens.find_many()
    await private.users.update({"id": tokens.user_id}, patch)
    with pytest.raises(OperationError):
        await core.session(tokens.access_token)
    with pytest.raises(OperationError):
        await core.refresh(tokens.refresh_token)
    row = await private.sessions.find_by_id({"id": tokens.session_id})
    assert row is not None and row.revoked_at is not None
    assert before is not None and (
        row.first_login_at,
        row.last_renewed_at,
        row.expires_at,
    ) == (before.first_login_at, before.last_renewed_at, before.expires_at)
    unchanged = await private.refresh_tokens.find_many() == previous
    assert unchanged


async def test_native_rejects_browser_session(db: Harness) -> None:
    core = auth(db)
    tokens = await core.signup("browser@example.test", PASSWORD)
    await PrivateDatabase(db.port()).sessions.update(
        {"id": tokens.session_id}, {"transport": "browser"}
    )
    with pytest.raises(OperationError) as invalid:
        await core.session(tokens.access_token)
    assert invalid.value.code == "invalid_token"
    with pytest.raises(OperationError):
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
    with pytest.raises(OperationError) as failed:
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
    with pytest.raises(OperationError) as failed:
        await core.signup("retained@example.test", PASSWORD)
    assert failed.value.code == "user_created_effect_failed" and calls == 1
    await core.signin("retained@example.test", PASSWORD)
    with pytest.raises(OperationError):
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
    with pytest.raises(OperationError) as replay:
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
        with pytest.raises(OperationError):
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
    with pytest.raises(OperationError) as redeemed:
        await core.invite_revoke(owner.access_token, id)
    assert redeemed.value.code == "invite_already_redeemed"
    other_id = str(uuid4())
    other = await core.invite_issue(owner.access_token, other_id, "other@example.test")
    assert (await core.invite_revoke(owner.access_token, other_id))[
        "status"
    ] == "revoked"
    with pytest.raises(OperationError):
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
        with pytest.raises(OperationError) as expired:
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
        with pytest.raises(OperationError) as denied:
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
    """M16: reject absolute-expired families before management hooks or writes."""
    owner = await auth(db).signup("owner@example.test", PASSWORD)
    core = Auth(db.port(), create_database, now=db.now, signup="invite-only")
    with pytest.raises(OperationError) as denied:
        await core.invite_list(owner.access_token, "")
    assert denied.value.code == "permission_denied"

    calls = 0

    async def allowed(port: DatabasePort, actor: Session, project: str) -> None:
        nonlocal calls
        calls += 1

    core = Auth(
        db.port(),
        create_database,
        now=db.now,
        signup="invite-only",
        hooks=AuthHooks(invite_managing=allowed),
    )
    with pytest.raises(OperationError) as unbound:
        await core.invite_list(owner.access_token, "")
    assert unbound.value.code == "service_unavailable"
    with pytest.raises(OperationError):
        await core.invite_list(random_token(), "")
    core.project_id = str(uuid4())
    core.absolute_lifetime_seconds = 3600
    db.instant += timedelta(seconds=3599)
    rotated = await core.refresh(owner.refresh_token)
    db.instant += timedelta(seconds=1)
    with pytest.raises(OperationError) as expired:
        await core.invite_issue(rotated.access_token, str(uuid4()), "new@example.test")
    assert expired.value.code == "invalid_token"
    assert calls == 0 and await PrivateDatabase(db.port()).invites.find_many() == []


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
    issued = await PrivateDatabase(db.port()).sessions.find_by_id(
        {"id": first.session_id}
    )
    assert (
        issued is not None
        and issued.created_at
        == issued.first_login_at
        == issued.last_renewed_at
        == format_timestamp(db.now())
    )
    assert (
        await core.signin_identity("external", "subject-one")
    ).user_id == first.user_id
    assert len(calls) == 1
    with pytest.raises(OperationError) as conflict:
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
    with pytest.raises(OperationError) as invalid:
        await budget.signin_identity("budget", "bad")
    assert invalid.value.code == "invalid_credentials"
    with pytest.raises(OperationError) as limited:
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


@pytest.mark.parametrize(
    "idle,absolute", [(3600, 0), (31536000, 0), (7200, 3600), (3600, 31536000)]
)
async def test_policy_ranges_and_single_issue_clock(
    db: Harness, idle: int, absolute: int
) -> None:
    """M15: detect ignored settings; N03: detect multiple issuance clock reads."""
    core = auth(db, idle=idle, absolute=absolute)
    calls = 0

    def clock() -> datetime:
        nonlocal calls
        calls += 1
        return db.now() + timedelta(microseconds=calls)

    core.now = clock
    private = PrivateDatabase(db.port())
    user = await private.users.insert({"email": "clock@example.test"})

    async def issue(port: DatabasePort) -> Tokens:
        return await core._issue(create_database(port), user)

    tokens = await core.port.transaction(issue)
    assert calls == 1
    issued = db.now() + timedelta(microseconds=1)
    row = await private.sessions.find_by_id({"id": tokens.session_id})
    refresh = (await private.refresh_tokens.find_many())[0]
    assert (
        row is not None
        and row.created_at
        == row.first_login_at
        == row.last_renewed_at
        == refresh.created_at
        == format_timestamp(issued)
    )
    assert parse_timestamp(tokens.expires_at) == issued + timedelta(seconds=900)
    assert parse_timestamp(tokens.refresh_expires_at) == issued + timedelta(
        seconds=min(idle, absolute) if absolute else idle
    )
    calls = 0
    rotated = await core.refresh(tokens.refresh_token)
    assert calls == 1 and parse_timestamp(rotated.expires_at) == issued + timedelta(
        seconds=900
    )


@pytest.mark.parametrize("field", ["idle_timeout_seconds", "absolute_lifetime_seconds"])
@pytest.mark.parametrize(
    "value", [True, False, None, "3600", 3600.0, -1, 3599, 31536001]
)
def test_invalid_policy_rejected_before_database(field: str, value: object) -> None:
    """M15: detect bool-as-int, coercion, or silently clamped policy input."""

    def forbidden(port: DatabasePort) -> AuthDatabase:
        raise AssertionError("Invalid policy reached the database.")

    with pytest.raises(ValueError, match="auth.session." + field + " must be"):
        Auth(
            cast(DatabasePort, object()),
            forbidden,
            idle_timeout_seconds=cast(int, value)
            if field == "idle_timeout_seconds"
            else 2592000,
            absolute_lifetime_seconds=cast(int, value)
            if field == "absolute_lifetime_seconds"
            else 0,
        )


def test_idle_zero_rejected_before_database() -> None:
    with pytest.raises(ValueError, match="idle_timeout_seconds must be"):
        Auth(cast(DatabasePort, object()), create_database, idle_timeout_seconds=0)


@pytest.mark.parametrize("offset", [-1, 0, 1])
@pytest.mark.parametrize("absolute", [0, 3600])
async def test_family_expiry_boundary(db: Harness, offset: int, absolute: int) -> None:
    """M04/M06: detect missing absolute cap or a strict-greater expiry check."""
    db.instant += timedelta(microseconds=654321)
    core = auth(db, idle=7200 if absolute else 2592000, absolute=absolute)
    initial = await core.signup("boundary@example.test", PASSWORD)
    private = PrivateDatabase(db.port())
    before = await private.sessions.find_by_id({"id": initial.session_id})
    db.instant = parse_timestamp(initial.refresh_expires_at) + timedelta(seconds=offset)
    if offset < 0:
        rotated = await core.refresh(initial.refresh_token)
        assert await core.session(rotated.access_token)
        if absolute:
            db.instant += timedelta(seconds=1)
            with pytest.raises(OperationError):
                await core.session(rotated.access_token)
            with pytest.raises(OperationError):
                await core.refresh(rotated.refresh_token)
    else:
        with pytest.raises(OperationError) as expired:
            await core.refresh(initial.refresh_token)
        assert expired.value.code == "session_revoked"
        after = await private.sessions.find_by_id({"id": initial.session_id})
        assert before is not None and after is not None
        unchanged = (after.first_login_at, after.last_renewed_at, after.expires_at) == (
            before.first_login_at,
            before.last_renewed_at,
            before.expires_at,
        )
        assert unchanged and after.revoked_at is not None
        assert len(await private.refresh_tokens.find_many()) == 1


async def test_absolute_preserves_first_login_through_rolling(db: Harness) -> None:
    """M03: detect first-login reset on rotation and absolute cap extension."""
    core = auth(db, absolute=60 * 86400)
    initial = await core.signup("absolute@example.test", PASSWORD)
    started = db.now()
    tokens = initial
    for day, expiry in ((29, 59), (58, 60)):
        db.instant = started + timedelta(days=day)
        tokens = await core.refresh(tokens.refresh_token)
        row = await PrivateDatabase(db.port()).sessions.find_by_id(
            {"id": tokens.session_id}
        )
        assert row is not None and row.first_login_at == format_timestamp(started)
        assert tokens.session_id == initial.session_id
        assert parse_timestamp(tokens.refresh_expires_at) == started + timedelta(
            days=expiry
        )


async def legacy(db: Harness, tokens: Tokens, issued: datetime) -> None:
    private = PrivateDatabase(db.port())
    row = await private.sessions.find_by_id({"id": tokens.session_id})
    assert row is not None
    await private.sessions.update(
        {"id": row.id},
        {
            "first_login_at": None,
            "last_renewed_at": None,
            "expires_at": format_timestamp(issued + timedelta(seconds=900)),
        },
    )
    refresh = (
        await private.refresh_tokens.find_many(
            where=Filter(
                "=",
                private.refresh_tokens.table.columns["token_hash"],
                (hash_token(tokens.refresh_token),),
            )
        )
    )[0]
    await private.refresh_tokens.update(
        {"id": refresh.id},
        {
            "created_at": format_timestamp(issued),
            "expires_at": format_timestamp(
                parse_timestamp(row.created_at) + timedelta(days=7)
            ),
        },
    )


@pytest.mark.parametrize("day", [6, 7])
@pytest.mark.parametrize("absolute", [0, 8 * 86400])
async def test_legacy_conversion_preserves_stored_expiry(
    db: Harness, day: int, absolute: int
) -> None:
    """M05: detect now/refresh-created fallback or revival before legacy expiry check."""
    core = auth(db, absolute=absolute)
    tokens = await core.signup("legacy@example.test", PASSWORD)
    started = db.now()
    await legacy(db, tokens, started + timedelta(days=5))
    db.instant = started + timedelta(days=day)
    private = PrivateDatabase(db.port())
    if day == 6:
        converted = await core.refresh(tokens.refresh_token)
        row = await private.sessions.find_by_id({"id": tokens.session_id})
        assert (
            row is not None
            and row.created_at == row.first_login_at == format_timestamp(started)
        )
        assert row.last_renewed_at == format_timestamp(db.now())
        assert parse_timestamp(converted.refresh_expires_at) == started + timedelta(
            days=8 if absolute else 36
        )
    else:
        await private.sessions.update(
            {"id": tokens.session_id},
            {"expires_at": format_timestamp(db.now() + timedelta(seconds=900))},
        )
        with pytest.raises(OperationError) as access_expired:
            await core.session(tokens.access_token)
        assert access_expired.value.code == "invalid_token"
        with pytest.raises(OperationError):
            await core.refresh(tokens.refresh_token)
        row = await private.sessions.find_by_id({"id": tokens.session_id})
        assert (
            row is not None
            and row.first_login_at is None
            and row.last_renewed_at is None
        )
        assert len(await private.refresh_tokens.find_many()) == 1


@pytest.mark.parametrize("offset", [-1, 0, 1])
async def test_legacy_idle_uses_latest_successful_issue(
    db: Harness, offset: int
) -> None:
    """Q1: detect family/access base, first refresh base, or rejected-request renewal."""
    core = auth(db, idle=3600)
    tokens = await auth(db).signup("legacy-idle@example.test", PASSWORD)
    started = db.now()
    newest = started + timedelta(days=5)
    await legacy(db, tokens, newest)
    private = PrivateDatabase(db.port())
    old = random_token()
    await private.refresh_tokens.insert(
        {
            "session_id": tokens.session_id,
            "token_hash": hash_token(old),
            "created_at": format_timestamp(started),
            "consumed_at": format_timestamp(newest),
            "expires_at": format_timestamp(started + timedelta(days=7)),
        }
    )
    db.instant = newest + timedelta(seconds=3600 + offset)
    await private.sessions.update(
        {"id": tokens.session_id},
        {"expires_at": format_timestamp(db.now() + timedelta(seconds=900))},
    )
    with pytest.raises(OperationError):
        await core.refresh("malformed")
    with pytest.raises(OperationError):
        await core.refresh(random_token())
    if offset < 0:
        assert (await core.session(tokens.access_token)).id == tokens.session_id
        rotated = await core.refresh(tokens.refresh_token)
        assert parse_timestamp(rotated.refresh_expires_at) == db.now() + timedelta(
            seconds=3600
        )
        renewed = await private.sessions.find_by_id({"id": tokens.session_id})
        with pytest.raises(OperationError):
            await core.refresh(old)
        revoked = await private.sessions.find_by_id({"id": tokens.session_id})
        assert (
            renewed is not None
            and revoked is not None
            and revoked.last_renewed_at == renewed.last_renewed_at
        )
    else:
        with pytest.raises(OperationError) as access_expired:
            await core.session(tokens.access_token)
        assert access_expired.value.code == "invalid_token"
        with pytest.raises(OperationError):
            await core.refresh(tokens.refresh_token)
        revoked = await private.sessions.find_by_id({"id": tokens.session_id})
        assert revoked is not None and revoked.last_renewed_at is None
        assert len(await private.refresh_tokens.find_many()) == 2


@pytest.mark.parametrize("mode", ["consume_zero", "insert_failure", "commit_unknown"])
async def test_refresh_failure_is_atomic(db: Harness, mode: str) -> None:
    """M02: detect renewal before consume, partial writes, or exposed unknown-commit success."""
    core = auth(db)
    tokens = await core.signup("atomic@example.test", PASSWORD)
    private = PrivateDatabase(db.port())
    before = await private.sessions.find_by_id({"id": tokens.session_id})
    refresh_before = await private.refresh_tokens.find_many()
    db.instant += timedelta(days=1)
    if mode == "commit_unknown":

        class LostCommit(PostgresPort):
            async def _execute(self, sql: str) -> None:
                await super()._execute(sql)
                if sql == "commit":
                    raise OSError("Commit response lost.")

        port = LostCommit(db.postgres._dsn)
        db.ports.append(port)
        with pytest.raises(CommitOutcomeUnknown):
            await auth(db, port).refresh(tokens.refresh_token)
        assert len(await private.refresh_tokens.find_many()) == 2
        with pytest.raises(OperationError):
            await core.refresh(tokens.refresh_token)
        return
    setup = db.port()
    await setup._execute("""
        create function fail_refresh_write() returns trigger language plpgsql as $$
        begin
            if TG_OP = 'UPDATE' then return null; end if;
            raise exception 'Refresh insert failed';
        end $$;
    """)
    action = "update" if mode == "consume_zero" else "insert"
    await setup._execute(
        f"create trigger fail_refresh_write before {action} on app_auth_refresh_tokens for each row execute function fail_refresh_write()"
    )
    with pytest.raises(OperationError if mode == "consume_zero" else Exception):
        await core.refresh(tokens.refresh_token)
    after = await private.sessions.find_by_id({"id": tokens.session_id})
    assert before is not None and after is not None
    unchanged = (
        after.first_login_at,
        after.last_renewed_at,
        after.expires_at,
        after.token_hash,
    ) == (
        before.first_login_at,
        before.last_renewed_at,
        before.expires_at,
        before.token_hash,
    )
    assert unchanged
    refresh_unchanged = await private.refresh_tokens.find_many() == refresh_before
    assert refresh_unchanged
    assert (after.revoked_at is not None) == (mode == "consume_zero")


@pytest.mark.parametrize("expiry_source", ["idle", "absolute", "stored"])
@pytest.mark.parametrize("legacy_family", [False, True], ids=["modern", "legacy"])
@pytest.mark.parametrize("lock_target", ["session", "user"])
async def test_refresh_expiry_rechecked_after_real_lock(
    db: Harness, expiry_source: str, legacy_family: bool, lock_target: str
) -> None:
    """M10: catch pre-lock clocks, policy bypass, or stored-expiry revival of either family."""
    initial = await auth(
        db, idle=3600 if expiry_source == "stored" else 2592000
    ).signup("blocked-refresh@example.test", PASSWORD)
    if legacy_family:
        await legacy(db, initial, db.now())
        if expiry_source == "stored":
            private = PrivateDatabase(db.port())
            stored_refresh = (await private.refresh_tokens.find_many())[0]
            await private.refresh_tokens.update(
                {"id": stored_refresh.id}, {"expires_at": initial.refresh_expires_at}
            )
    core = auth(
        db,
        idle=3600 if expiry_source == "idle" else 7200,
        absolute=3600 if expiry_source == "absolute" else 0,
    )
    expiry = db.now() + timedelta(seconds=3600)
    db.instant = expiry - timedelta(seconds=1)
    held, attempted, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    async def hold(port: DatabasePort) -> None:
        private = PrivateDatabase(port)
        if lock_target == "session":
            await private.sessions.update(
                {"id": initial.session_id}, {"transport": "native"}
            )
        else:
            await private.users.update({"id": initial.user_id}, {"session_version": 1})
        held.set()
        await release.wait()

    class ObservedSessions(Repository[AppAuthSessionsRow]):
        async def update_if(
            self,
            key: Mapping[str, object],
            condition: Filter,
            patch: Mapping[str, object],
        ) -> AppAuthSessionsRow | None:
            attempted.set()
            return await super().update_if(key, condition, patch)

    class ObservedUsers(Repository[AppAuthUsersRow]):
        async def update_if(
            self,
            key: Mapping[str, object],
            condition: Filter,
            patch: Mapping[str, object],
        ) -> AppAuthUsersRow | None:
            attempted.set()
            return await super().update_if(key, condition, patch)

    def observed(port: DatabasePort) -> AuthDatabase:
        database = PrivateDatabase(port)
        if lock_target == "session":
            database.sessions = ObservedSessions(
                port, database.sessions.table, database.sessions.row
            )
        else:
            database.users = ObservedUsers(
                port, database.users.table, database.users.row
            )
        return database

    core.create_database = observed
    locker = asyncio.create_task(db.port().transaction(hold))
    rotation: asyncio.Task[Tokens] | None = None
    try:
        await asyncio.wait_for(held.wait(), 2)
        rotation = asyncio.create_task(core.refresh(initial.refresh_token))
        await asyncio.wait_for(attempted.wait(), 2)
        observer = db.port()
        async with asyncio.timeout(2):
            while not await observer.query(
                "select pid from pg_stat_activity where wait_event_type='Lock' "
                f"and query like '%app_auth_{'sessions' if lock_target == 'session' else 'users'}%'",
                (),
            ):
                pass
        db.instant = expiry
        release.set()
        with pytest.raises(OperationError) as expired:
            await asyncio.wait_for(rotation, 2)
        assert expired.value.code == "session_revoked"
        await locker
        row = await PrivateDatabase(db.port()).sessions.find_by_id(
            {"id": initial.session_id}
        )
        assert row is not None and row.revoked_at == format_timestamp(expiry)
        assert row.last_renewed_at == (
            None
            if legacy_family
            else format_timestamp(expiry - timedelta(seconds=3600))
        )
        assert len(await PrivateDatabase(db.port()).refresh_tokens.find_many()) == 1
    finally:
        release.set()
        if rotation is not None:
            rotation.cancel()
            await asyncio.gather(rotation, return_exceptions=True)
        locker.cancel()
        await asyncio.gather(locker, return_exceptions=True)


@pytest.mark.parametrize(
    "change",
    [
        "shorten_idle",
        "expand_idle",
        "enable_absolute",
        "change_absolute",
        "disable_absolute",
    ],
)
async def test_current_policy_keeps_original_bases_and_never_revives(
    db: Harness, change: str
) -> None:
    """M14: detect pinned issuance policy, reset bases, or expanded-policy revival."""
    core = auth(
        db,
        idle=3600 if change == "expand_idle" else 2592000,
        absolute=3600
        if change == "disable_absolute"
        else 7200
        if change == "change_absolute"
        else 0,
    )
    tokens = await core.signup("policy@example.test", PASSWORD)
    started = db.now()
    if change == "shorten_idle":
        core.idle_timeout_seconds = 3600
    elif change == "expand_idle":
        core.idle_timeout_seconds = 2592000
    elif change in ("enable_absolute", "change_absolute"):
        core.absolute_lifetime_seconds = 3600
    else:
        core.absolute_lifetime_seconds = 0
    db.instant += timedelta(seconds=3599)
    rotated = await core.refresh(tokens.refresh_token)
    assert parse_timestamp(rotated.refresh_expires_at) == (
        started + timedelta(seconds=3600)
        if change in ("enable_absolute", "change_absolute")
        else db.now() + timedelta(seconds=core.idle_timeout_seconds)
    )
    # The old stored cap remains a credential limit until successful renewal.
    db.instant = parse_timestamp(rotated.refresh_expires_at)
    core.idle_timeout_seconds = 31536000
    core.absolute_lifetime_seconds = 0
    with pytest.raises(OperationError):
        await core.refresh(rotated.refresh_token)
    row = await PrivateDatabase(db.port()).sessions.find_by_id(
        {"id": tokens.session_id}
    )
    assert row is not None and row.first_login_at == format_timestamp(started)
    with pytest.raises(OperationError):
        await core.refresh(rotated.refresh_token)


@pytest.mark.parametrize("reuse_first", [False, True])
async def test_reuse_and_latest_rotation_commit_orders(
    db: Harness, reuse_first: bool
) -> None:
    """M13: detect post-revocation renewal or a latest credential escaping replay."""
    core = auth(db)
    initial = await core.signup("replay-order@example.test", PASSWORD)
    db.instant += timedelta(days=1)
    current = await core.refresh(initial.refresh_token)
    private = PrivateDatabase(db.port())
    previous = await private.sessions.find_by_id({"id": current.session_id})
    prepared, release = asyncio.Event(), asyncio.Event()

    class PausedCommit(PostgresPort):
        async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
            async def paused(port: DatabasePort) -> T:
                result = await work(port)
                prepared.set()
                await release.wait()
                return result

            return await super().transaction(paused)

    port = PausedCommit(db.postgres._dsn)
    db.ports.append(port)
    leader = auth(db, port)
    db.instant += timedelta(days=1)
    first = asyncio.create_task(
        leader.refresh(initial.refresh_token if reuse_first else current.refresh_token)
    )
    second: asyncio.Task[Tokens] | None = None
    try:
        await asyncio.wait_for(prepared.wait(), 2)
        second = asyncio.create_task(
            core.refresh(
                current.refresh_token if reuse_first else initial.refresh_token
            )
        )
        observer = db.port()
        async with asyncio.timeout(2):
            while not await observer.query(
                "select pid from pg_stat_activity where wait_event_type='Lock' and query like '%app_auth_sessions%'",
                (),
            ):
                pass
        release.set()
        results = await asyncio.gather(first, second, return_exceptions=True)
        assert sum(isinstance(result, Tokens) for result in results) == int(
            not reuse_first
        )
        revoked = await private.sessions.find_by_id({"id": initial.session_id})
        assert (
            revoked is not None
            and revoked.revoked_at is not None
            and previous is not None
        )
        assert revoked.last_renewed_at == (
            previous.last_renewed_at if reuse_first else format_timestamp(db.now())
        )
        for result in results:
            if isinstance(result, Tokens):
                with pytest.raises(OperationError):
                    await core.session(result.access_token)
                with pytest.raises(OperationError):
                    await core.refresh(result.refresh_token)
    finally:
        release.set()
        for task in (first, second):
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)


async def test_cleanup_rechecks_after_waiting_for_rotation(db: Harness) -> None:
    """M13: detect refresh-first lock order or stale cleanup revoking a live family."""
    core = auth(db, idle=3600)
    initial = await core.signup("cleanup-race@example.test", PASSWORD)
    started = db.now()
    prepared, release = asyncio.Event(), asyncio.Event()

    class PausedCommit(PostgresPort):
        async def transaction(self, work: Callable[[DatabasePort], Awaitable[T]]) -> T:
            async def paused(port: DatabasePort) -> T:
                result = await work(port)
                prepared.set()
                await release.wait()
                return result

            return await super().transaction(paused)

    port = PausedCommit(db.postgres._dsn)
    db.ports.append(port)
    leader = auth(db, port, idle=3600)
    db.instant += timedelta(seconds=3599)
    rotation = asyncio.create_task(leader.refresh(initial.refresh_token))
    cleaning: asyncio.Task[None] | None = None
    try:
        await asyncio.wait_for(prepared.wait(), 2)
        db.instant += timedelta(seconds=1)
        cleaning = asyncio.create_task(core._cleanup(db.port(), False))
        observer = db.port()
        async with asyncio.timeout(2):
            while not await observer.query(
                "select pid from pg_stat_activity where wait_event_type='Lock' and query like '%app_auth_sessions%'",
                (),
            ):
                pass
        release.set()
        tokens = await rotation
        await cleaning
        assert await core.session(tokens.access_token)
        private = PrivateDatabase(db.port())
        row = await private.sessions.find_by_id({"id": tokens.session_id})
        assert row is not None and row.revoked_at is None
        assert row.last_renewed_at == format_timestamp(
            started + timedelta(seconds=3599)
        )
        assert len(await private.refresh_tokens.find_many()) == 2
    finally:
        release.set()
        for task in (rotation, cleaning):
            if task is not None:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)
