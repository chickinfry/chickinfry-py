"""The auth core receives create_database(port) from the canonical repository's
generated private ORM.

The generated ORM provides users/sessions/refresh_tokens/identities/invites/
rate_limits repositories with snake_case row fields and Table metadata. The
generator owns the schema; this core creates no tables. Hook wiring builds a
public context through the transaction port, and native wire connections
reply with Tokens.to_wire() using only the declared methods.
"""

import asyncio
import base64
import hashlib
import json
import re
import secrets
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Protocol, TypeVar

from ._password import CPythonScrypt, PasswordKDF, hash_password, verify_password
from .orm import (
    DatabasePort,
    Filter,
    Order,
    Table,
    and_,
    format_timestamp,
    or_,
    parse_timestamp,
)
from .server import ServerError, Session, User

R_co = TypeVar("R_co", covariant=True)
T = TypeVar("T")


class AuthRepository(Protocol[R_co]):
    @property
    def table(self) -> Table: ...
    async def find_by_id(self, key: Mapping[str, object]) -> R_co | None: ...
    async def find_many(
        self,
        *,
        where: Filter | None = None,
        order_by: Sequence[Order] = (),
        limit: int | None = None,
        offset: int | None = None,
    ) -> Sequence[R_co]: ...
    async def insert(self, values: Mapping[str, object]) -> R_co: ...
    async def update(
        self, key: Mapping[str, object], patch: Mapping[str, object]
    ) -> R_co: ...
    async def update_if(
        self, key: Mapping[str, object], condition: Filter, patch: Mapping[str, object]
    ) -> R_co | None: ...
    async def delete(self, key: Mapping[str, object]) -> R_co | None: ...


class UserRecord(Protocol):
    @property
    def id(self) -> str: ...
    @property
    def email(self) -> str: ...
    @property
    def password_hash(self) -> str | None: ...
    @property
    def disabled_at(self) -> str | None: ...
    @property
    def session_version(self) -> int: ...
    @property
    def created_at(self) -> str: ...


class SessionRecord(Protocol):
    @property
    def id(self) -> str: ...
    @property
    def user_id(self) -> str: ...
    @property
    def token_hash(self) -> str: ...
    @property
    def user_session_version(self) -> int: ...
    @property
    def transport(self) -> str: ...
    @property
    def expires_at(self) -> str: ...
    @property
    def revoked_at(self) -> str | None: ...


class RefreshRecord(Protocol):
    @property
    def id(self) -> str: ...
    @property
    def session_id(self) -> str: ...
    @property
    def expires_at(self) -> str: ...
    @property
    def consumed_at(self) -> str | None: ...


class IdentityRecord(Protocol):
    @property
    def user_id(self) -> str: ...


class InviteRecord(Protocol):
    @property
    def id(self) -> str: ...
    @property
    def email(self) -> str: ...
    @property
    def expires_at(self) -> str: ...
    @property
    def created_at(self) -> str: ...
    @property
    def redeemed_at(self) -> str | None: ...
    @property
    def redeemed_by(self) -> str | None: ...
    @property
    def revoked_at(self) -> str | None: ...


class RateLimitRecord(Protocol):
    @property
    def action(self) -> str: ...
    @property
    def key_hash(self) -> str: ...
    @property
    def attempt_count(self) -> int: ...
    @property
    def expires_at(self) -> str: ...


class AuthDatabase(Protocol):
    @property
    def users(self) -> AuthRepository[UserRecord]: ...
    @property
    def sessions(self) -> AuthRepository[SessionRecord]: ...
    @property
    def refresh_tokens(self) -> AuthRepository[RefreshRecord]: ...
    @property
    def identities(self) -> AuthRepository[IdentityRecord]: ...
    @property
    def invites(self) -> AuthRepository[InviteRecord]: ...
    @property
    def rate_limits(self) -> AuthRepository[RateLimitRecord]: ...


class ClosablePort(DatabasePort, Protocol):
    async def close(self) -> None: ...
    def terminate(self) -> None: ...


@dataclass(frozen=True, slots=True)
class AuthUser:
    id: str
    email: str
    created_at: str


@dataclass(frozen=True, slots=True, repr=False)
class Tokens:
    access_token: str
    refresh_token: str
    expires_at: str
    refresh_expires_at: str
    user_id: str
    session_id: str

    def to_wire(self) -> Mapping[str, str]:
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires_at": self.expires_at,
            "refresh_expires_at": self.refresh_expires_at,
            "user_id": self.user_id,
            "session_id": self.session_id,
        }


@dataclass(frozen=True, slots=True)
class AuthHooks:
    user_creating: Callable[[DatabasePort, AuthUser], Awaitable[None]] | None = None
    user_created: Callable[[AuthUser], Awaitable[None]] | None = None
    invite_managing: Callable[[DatabasePort, Session, str], Awaitable[None]] | None = (
        None
    )


@dataclass(frozen=True, slots=True)
class Identity:
    subject: str
    verified_email: str


class IdentityProvider(Protocol):
    @property
    def id(self) -> str: ...
    async def verify(self, credential: object) -> Identity: ...


@dataclass(frozen=True, slots=True)
class CleanupContext:
    create_port: Callable[[], ClosablePort]
    wait_until: Callable[[Coroutine[None, None, None]], None]
    failure: Callable[[str], None] | None = None


def random_token() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")


def hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: str) -> bool:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        return False
    return (
        base64.urlsafe_b64encode(base64.urlsafe_b64decode(value + "="))
        .decode()
        .rstrip("=")
        == value
    )


def _validate_token(value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", value):
        raise ServerError("invalid_token", 401)


def normalize_email(value: str) -> str:
    if not isinstance(value, str):
        raise ServerError("invalid_input", 400)
    email = value.strip().lower()
    if (
        "\0" in email
        or len(email) > 320
        or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email)
    ):
        raise ServerError("invalid_input", 400)
    return email


def validate_password(value: str) -> None:
    try:
        if (
            not isinstance(value, str)
            or len(value) < 15
            or len(value.encode("utf-8")) > 1024
        ):
            raise ValueError
    except (ValueError, UnicodeError):
        raise ServerError("invalid_input", 400) from None


def _filter(
    repo: AuthRepository[object], name: str, operator: str, *values: object
) -> Filter:
    return Filter(operator, repo.table.columns[name], values)


def _unique(error: Exception) -> bool:
    return getattr(error, "sqlstate", None) == "23505"


def _invite_id(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(
        r"[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}", value
    ):
        raise ServerError("invalid_input", 400)
    return value.lower()


class Auth:
    """Per-request auth core; the factory and hooks share one real DatabasePort."""

    def __init__(
        self,
        port: DatabasePort,
        create_database: Callable[[DatabasePort], AuthDatabase],
        *,
        now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
        hooks: AuthHooks = AuthHooks(),
        signup: str = "open",
        project_id: str | None = None,
        providers: Sequence[IdentityProvider] = (),
        cleanup: CleanupContext | None = None,
        _kdf: PasswordKDF | None = None,
    ) -> None:
        if signup not in ("open", "invite-only"):
            raise ValueError("Invalid signup policy.")
        self.port, self.create_database = port, create_database
        self.db = create_database(port)
        self.now, self.hooks, self.signup_policy, self.project_id = (
            now,
            hooks,
            signup,
            project_id,
        )
        self.cleanup_context = cleanup
        self._kdf = _kdf if _kdf is not None else CPythonScrypt()
        self.providers: dict[str, IdentityProvider] = {}
        for provider in providers:
            if (
                not re.fullmatch(r"[a-z][a-z0-9_-]{0,62}", provider.id)
                or provider.id == "password"
                or provider.id in self.providers
            ):
                raise ValueError("Invalid or duplicate identity provider.")
            self.providers[provider.id] = provider

    def _timestamp(self, seconds: int = 0) -> str:
        return format_timestamp(self.now() + timedelta(seconds=seconds))

    async def _issue(self, db: AuthDatabase, user: UserRecord) -> Tokens:
        access, refresh = random_token(), random_token()
        issued = self.now()
        expiry = format_timestamp(issued + timedelta(seconds=900))
        family = format_timestamp(issued + timedelta(seconds=604800))
        session = await db.sessions.insert(
            {
                "user_id": user.id,
                "token_hash": hash_token(access),
                "user_session_version": user.session_version,
                "expires_at": expiry,
                "transport": "native",
            }
        )
        await db.refresh_tokens.insert(
            {
                "session_id": session.id,
                "token_hash": hash_token(refresh),
                "expires_at": family,
            }
        )
        return Tokens(access, refresh, expiry, family, user.id, session.id)

    async def _creating(self, port: DatabasePort, user: UserRecord) -> AuthUser:
        public = AuthUser(user.id, user.email, user.created_at)
        if self.hooks.user_creating is not None:
            try:
                await self.hooks.user_creating(port, public)
            except Exception:
                raise ServerError("user_creation_failed", 500) from None
        return public

    async def _created(self, user: AuthUser) -> None:
        if self.hooks.user_created is not None:
            try:
                await self.hooks.user_created(user)
            except Exception:
                raise ServerError("user_created_effect_failed", 500) from None

    async def signup(self, email: str, password: str, invite_code: str = "") -> Tokens:
        email = normalize_email(email)
        validate_password(password)
        if not isinstance(invite_code, str):
            raise ServerError("invalid_input", 400)
        await self._rate_limit("signup", email)
        if self.signup_policy == "invite-only":
            await self._check_invite(self.db, email, invite_code)
        password_hash = hash_password(password, self._kdf)

        async def work(port: DatabasePort) -> tuple[Tokens, AuthUser]:
            db = self.create_database(port)
            invite = await self._lock_invite(db, email, invite_code)
            user = await db.users.insert(
                {"email": email, "password_hash": password_hash}
            )
            if invite is not None:
                await db.invites.update(
                    {"id": invite.id},
                    {"redeemed_at": self._timestamp(), "redeemed_by": user.id},
                )
            public = await self._creating(port, user)
            return await self._issue(db, user), public

        try:
            tokens, public = await self.port.transaction(work)
        except Exception as error:
            if _unique(error):
                raise ServerError("account_exists", 409) from None
            raise
        await self._created(public)
        self._schedule_cleanup()
        return tokens

    async def signin(self, email: str, password: str) -> Tokens:
        email = normalize_email(email)
        validate_password(password)
        await self._rate_limit("signin", email)
        users = await self.db.users.find_many(
            where=_filter(self.db.users, "email", "=", email), limit=1
        )
        user = users[0] if users else None
        matched = verify_password(
            password, user.password_hash if user is not None else None, self._kdf
        )
        if not matched or user is None or user.disabled_at is not None:
            raise ServerError("invalid_credentials", 401)

        async def issue(port: DatabasePort) -> Tokens:
            return await self._issue(self.create_database(port), user)

        result = await self.port.transaction(issue)
        self._schedule_cleanup()
        return result

    async def signin_identity(
        self, provider_id: str, credential: object, invite_code: str = ""
    ) -> Tokens:
        if not isinstance(invite_code, str):
            raise ServerError("invalid_input", 400)
        provider = self.providers.get(provider_id)
        if provider is None:
            raise ServerError("unsupported_identity_provider", 400)
        await self._rate_limit("identity_attempt", provider_id, 100, 60)
        try:
            identity = await provider.verify(credential)
        except Exception:
            raise ServerError("invalid_credentials", 401) from None
        email = normalize_email(identity.verified_email)
        if (
            not isinstance(identity.subject, str)
            or not identity.subject
            or len(identity.subject) > 2048
        ):
            raise ServerError("invalid_credentials", 401)
        await self._rate_limit("identity", provider_id + ":" + identity.subject)
        key = {"provider": provider_id, "subject": identity.subject}
        if (
            self.signup_policy == "invite-only"
            and await self.db.identities.find_by_id(key) is None
        ):
            await self._rate_limit("signup", email)
            await self._check_invite(self.db, email, invite_code)

        async def work(port: DatabasePort) -> tuple[Tokens, AuthUser | None]:
            db = self.create_database(port)
            stored = await db.identities.find_by_id(key)
            invite = (
                await self._lock_invite(db, email, invite_code)
                if stored is None
                else None
            )
            user = (
                await db.users.find_by_id({"id": stored.user_id})
                if stored is not None
                else await db.users.insert({"email": email, "password_hash": None})
            )
            if user is None or user.disabled_at is not None:
                raise ServerError("invalid_credentials", 401)
            public = None
            if stored is None:
                if invite is not None:
                    await db.invites.update(
                        {"id": invite.id},
                        {"redeemed_at": self._timestamp(), "redeemed_by": user.id},
                    )
                await db.identities.insert({**key, "user_id": user.id})
                public = await self._creating(port, user)
            return await self._issue(db, user), public

        try:
            tokens, public = await self.port.transaction(work)
        except Exception as error:
            if _unique(error):
                raise ServerError("identity_conflict", 409) from None
            raise
        if public is not None:
            await self._created(public)
        self._schedule_cleanup()
        return tokens

    async def _validate_session(self, record: SessionRecord | None) -> Session:
        if (
            record is None
            or record.transport != "native"
            or record.revoked_at is not None
            or parse_timestamp(record.expires_at) <= self.now()
        ):
            raise ServerError("invalid_token", 401)
        user = await self.db.users.find_by_id({"id": record.user_id})
        if (
            user is None
            or user.disabled_at is not None
            or user.session_version != record.user_session_version
        ):
            raise ServerError("invalid_token", 401)
        return Session(record.id, User(user.id, user.email))

    async def session(self, access_token: str) -> Session:
        _validate_token(access_token)
        rows = await self.db.sessions.find_many(
            where=_filter(
                self.db.sessions, "token_hash", "=", hash_token(access_token)
            ),
            limit=1,
        )
        return await self._validate_session(rows[0] if rows else None)

    async def logout(self, access_token: str) -> None:
        session = await self.session(access_token)
        await self.db.sessions.update_if(
            {"id": session.id},
            _filter(self.db.sessions, "revoked_at", "is null"),
            {"revoked_at": self._timestamp()},
        )

    async def refresh(self, refresh_token: str) -> Tokens:
        _validate_token(refresh_token)
        rows = await self.db.refresh_tokens.find_many(
            where=_filter(
                self.db.refresh_tokens, "token_hash", "=", hash_token(refresh_token)
            ),
            limit=1,
        )
        if not rows:
            raise ServerError("invalid_token", 401)
        stored = rows[0]

        async def consume(port: DatabasePort) -> Tokens | None:
            db = self.create_database(port)
            session = await db.sessions.update_if(
                {"id": stored.session_id},
                _filter(db.sessions, "revoked_at", "is null"),
                {"revoked_at": None},
            )
            if session is None or session.transport != "native":
                return None
            current = await db.refresh_tokens.find_by_id({"id": stored.id})
            user = await db.users.find_by_id({"id": session.user_id})
            if (
                current is None
                or current.consumed_at is not None
                or parse_timestamp(current.expires_at) <= self.now()
                or user is None
                or user.disabled_at is not None
                or user.session_version != session.user_session_version
            ):
                await db.sessions.update(
                    {"id": session.id}, {"revoked_at": self._timestamp()}
                )
                return None
            consumed = await db.refresh_tokens.update_if(
                {"id": current.id},
                _filter(db.refresh_tokens, "consumed_at", "is null"),
                {"consumed_at": self._timestamp()},
            )
            if consumed is None:
                await db.sessions.update(
                    {"id": session.id}, {"revoked_at": self._timestamp()}
                )
                return None
            access, refresh = random_token(), random_token()
            expiry = self._timestamp(900)
            await db.sessions.update(
                {"id": session.id},
                {"token_hash": hash_token(access), "expires_at": expiry},
            )
            await db.refresh_tokens.insert(
                {
                    "session_id": session.id,
                    "token_hash": hash_token(refresh),
                    "expires_at": current.expires_at,
                }
            )
            return Tokens(
                access, refresh, expiry, current.expires_at, user.id, session.id
            )

        outcome = await self.port.transaction(consume)
        if outcome is None:
            raise ServerError("session_revoked", 401)
        self._schedule_cleanup()
        return outcome

    async def _check_invite(
        self, db: AuthDatabase, email: str, code: str
    ) -> InviteRecord:
        if not code:
            raise ServerError("invite_required", 403)
        if not _canonical(code):
            raise ServerError("invite_invalid", 403)
        rows = await db.invites.find_many(
            where=_filter(db.invites, "code_hash", "=", hash_token(code)), limit=1
        )
        row = rows[0] if rows else None
        if (
            row is None
            or row.email != email
            or row.redeemed_at is not None
            or row.redeemed_by is not None
            or row.revoked_at is not None
            or parse_timestamp(row.expires_at) <= self.now()
        ):
            raise ServerError("invite_invalid", 403)
        return row

    async def _lock_invite(
        self, db: AuthDatabase, email: str, code: str
    ) -> InviteRecord | None:
        if self.signup_policy != "invite-only":
            return None
        row = await self._check_invite(db, email, code)
        locked = await db.invites.update_if(
            {"id": row.id},
            and_(
                _filter(db.invites, "code_hash", "=", hash_token(code)),
                _filter(db.invites, "email", "=", email),
                _filter(db.invites, "redeemed_at", "is null"),
                _filter(db.invites, "redeemed_by", "is null"),
                _filter(db.invites, "revoked_at", "is null"),
                _filter(db.invites, "expires_at", "=", row.expires_at),
                _filter(db.invites, "expires_at", ">", self._timestamp()),
            ),
            {"expires_at": row.expires_at},
        )
        if locked is None or parse_timestamp(locked.expires_at) <= self.now():
            raise ServerError("invite_invalid", 403)
        return locked

    async def _rate_limit(
        self, action: str, value: str, maximum: int = 10, window: int = 900
    ) -> None:
        key = {"action": action, "key_hash": hash_token(value)}
        for _ in range(4):
            row = await self.db.rate_limits.find_by_id(key)
            expires = self._timestamp(window)
            if row is None:
                try:
                    await self.db.rate_limits.insert(
                        {**key, "attempt_count": 1, "expires_at": expires}
                    )
                    return
                except Exception as error:
                    if not _unique(error):
                        raise
                continue
            expired = parse_timestamp(row.expires_at) <= self.now()
            if not expired and row.attempt_count >= maximum:
                raise ServerError("rate_limited", 429)
            updated = await self.db.rate_limits.update_if(
                key,
                and_(
                    _filter(
                        self.db.rate_limits, "attempt_count", "=", row.attempt_count
                    ),
                    _filter(self.db.rate_limits, "expires_at", "=", row.expires_at),
                ),
                {
                    "attempt_count": 1 if expired else row.attempt_count + 1,
                    "expires_at": expires if expired else row.expires_at,
                },
            )
            if updated is not None:
                return
        raise ServerError("rate_limited", 429)

    async def _manage(
        self, access: str, work: Callable[[AuthDatabase, Session], Awaitable[T]]
    ) -> T:
        if self.signup_policy != "invite-only":
            raise ServerError("not_found", 404)
        _validate_token(access)

        async def run(port: DatabasePort) -> T:
            db = self.create_database(port)
            rows = await db.sessions.find_many(
                where=_filter(db.sessions, "token_hash", "=", hash_token(access)),
                limit=1,
            )
            if not rows:
                raise ServerError("invalid_token", 401)
            candidate = rows[0]
            session = await db.sessions.update_if(
                {"id": candidate.id},
                and_(
                    _filter(db.sessions, "token_hash", "=", hash_token(access)),
                    _filter(db.sessions, "revoked_at", "is null"),
                    _filter(db.sessions, "transport", "=", "native"),
                    _filter(db.sessions, "expires_at", ">", self._timestamp()),
                ),
                {"expires_at": candidate.expires_at},
            )
            if session is None or parse_timestamp(session.expires_at) <= self.now():
                raise ServerError("invalid_token", 401)
            user = await db.users.update_if(
                {"id": session.user_id},
                and_(
                    _filter(db.users, "disabled_at", "is null"),
                    _filter(
                        db.users, "session_version", "=", session.user_session_version
                    ),
                ),
                {"session_version": session.user_session_version},
            )
            if user is None:
                raise ServerError("invalid_token", 401)
            if self.hooks.invite_managing is None:
                raise ServerError("permission_denied", 403)
            if self.project_id is None:
                raise ServerError("service_unavailable", 503)
            try:
                project = _invite_id(self.project_id)
            except ServerError:
                raise ServerError("service_unavailable", 503) from None
            actor = Session(session.id, User(user.id, user.email))
            try:
                await self.hooks.invite_managing(port, actor, project)
            except ServerError:
                raise
            except Exception:
                raise ServerError("permission_denied", 403) from None
            return await work(db, actor)

        result = await self.port.transaction(run)
        self._schedule_cleanup(invites_only=True)
        return result

    def _summary(self, row: InviteRecord) -> dict[str, str]:
        if (row.redeemed_at is None) != (row.redeemed_by is None) or (
            row.redeemed_at is not None and row.revoked_at is not None
        ):
            raise ServerError("operation_failed", 500)
        status = (
            "redeemed"
            if row.redeemed_at is not None
            else "revoked"
            if row.revoked_at is not None
            else "expired"
            if parse_timestamp(row.expires_at) <= self.now()
            else "issued"
        )
        return {
            "id": row.id,
            "email": row.email,
            "status": status,
            "created_at": row.created_at,
            "expires_at": row.expires_at,
        }

    async def invite_issue(self, access: str, id: str, email: str) -> Mapping[str, str]:
        id, email = _invite_id(id), normalize_email(email)

        async def issue(db: AuthDatabase, actor: Session) -> Mapping[str, str]:
            if await db.invites.find_by_id({"id": id}) is not None:
                raise ServerError("invite_issue_replayed", 409)
            code = random_token()
            issued = self.now()
            row = await db.invites.insert(
                {
                    "id": id,
                    "email": email,
                    "code_hash": hash_token(code),
                    "issued_by": actor.user.id,
                    "created_at": format_timestamp(issued),
                    "expires_at": format_timestamp(issued + timedelta(days=7)),
                }
            )
            return {**self._summary(row), "code": code}

        try:
            return await self._manage(access, issue)
        except Exception as error:
            if (
                _unique(error)
                and await self.db.invites.find_by_id({"id": id}) is not None
            ):
                raise ServerError("invite_issue_replayed", 409) from None
            raise

    async def invite_list(self, access: str, cursor: str) -> Mapping[str, object]:
        after: tuple[str, str] | None = None
        if not isinstance(cursor, str):
            raise ServerError("invalid_input", 400)
        if cursor:
            try:
                if len(cursor) > 512 or not re.fullmatch(r"[A-Za-z0-9_-]+", cursor):
                    raise ValueError
                raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
                if base64.urlsafe_b64encode(raw).decode().rstrip("=") != cursor:
                    raise ValueError
                value: object = json.loads(raw)
                if (
                    not isinstance(value, list)
                    or len(value) != 2
                    or not isinstance(value[0], str)
                    or not isinstance(value[1], str)
                    or format_timestamp(parse_timestamp(value[0])) != value[0]
                ):
                    raise ValueError
                after = value[0], _invite_id(value[1])
            except (ValueError, ServerError):
                raise ServerError("invalid_input", 400) from None

        async def page(db: AuthDatabase, actor: Session) -> Mapping[str, object]:
            where = (
                None
                if after is None
                else or_(
                    _filter(db.invites, "created_at", ">", after[0]),
                    and_(
                        _filter(db.invites, "created_at", "=", after[0]),
                        _filter(db.invites, "id", ">", after[1]),
                    ),
                )
            )
            rows = await db.invites.find_many(
                where=where,
                order_by=(
                    Order(db.invites.table.columns["created_at"], "asc"),
                    Order(db.invites.table.columns["id"], "asc"),
                ),
                limit=51,
            )
            next_cursor = ""
            if len(rows) > 50:
                last = rows[49]
                raw = json.dumps(
                    [last.created_at, last.id], separators=(",", ":")
                ).encode()
                next_cursor = base64.urlsafe_b64encode(raw).decode().rstrip("=")
            return {
                "items": [self._summary(row) for row in rows[:50]],
                "next_cursor": next_cursor,
            }

        return await self._manage(access, page)

    async def invite_revoke(self, access: str, id: str) -> Mapping[str, str]:
        id = _invite_id(id)

        async def revoke(db: AuthDatabase, actor: Session) -> Mapping[str, str]:
            candidate = await db.invites.find_by_id({"id": id})
            if candidate is None:
                raise ServerError("not_found", 404)
            row = await db.invites.update_if(
                {"id": id},
                _filter(db.invites, "expires_at", "=", candidate.expires_at),
                {"expires_at": candidate.expires_at},
            )
            if row is None:
                raise ServerError("not_found", 404)
            status = self._summary(row)["status"]
            if status == "redeemed":
                raise ServerError("invite_already_redeemed", 409)
            if status == "issued":
                await db.invites.update({"id": id}, {"revoked_at": self._timestamp()})
                status = "revoked"
            return {"id": id, "status": status}

        return await self._manage(access, revoke)

    def _cleanup_failure(self, stage: str) -> None:
        context = self.cleanup_context
        if context is not None and context.failure is not None:
            try:
                context.failure(stage)
            except Exception:
                pass

    def _schedule_cleanup(self, invites_only: bool = False) -> None:
        context = self.cleanup_context
        if context is None:
            return

        async def run() -> None:
            port: ClosablePort | None = None
            try:
                async with asyncio.timeout(5):
                    port = context.create_port()
                    await self._cleanup(port, invites_only)
            except Exception:
                self._cleanup_failure("port")
            finally:
                if port is not None:
                    try:
                        async with asyncio.timeout(5):
                            await port.close()
                    except BaseException as error:
                        port.terminate()
                        self._cleanup_failure("close")
                        if isinstance(error, asyncio.CancelledError):
                            raise

        work = run()
        try:
            context.wait_until(work)
        except Exception:
            work.close()
            self._cleanup_failure("schedule")

    async def _cleanup(self, port: DatabasePort, invites_only: bool) -> None:
        db = self.create_database(port)
        cutoff = self._timestamp()
        stage = "refresh"
        try:
            if not invites_only:
                refresh = await db.refresh_tokens.find_many(
                    where=_filter(db.refresh_tokens, "expires_at", "<=", cutoff),
                    limit=32,
                    order_by=(
                        Order(db.refresh_tokens.table.columns["expires_at"], "asc"),
                        Order(db.refresh_tokens.table.columns["id"], "asc"),
                    ),
                )
                for row in refresh:

                    async def delete_refresh(
                        tx_port: DatabasePort, candidate: RefreshRecord = row
                    ) -> None:
                        tx = self.create_database(tx_port)
                        locked = await tx.refresh_tokens.update_if(
                            {"id": candidate.id},
                            and_(
                                _filter(
                                    tx.refresh_tokens,
                                    "expires_at",
                                    "=",
                                    candidate.expires_at,
                                ),
                                _filter(tx.refresh_tokens, "expires_at", "<=", cutoff),
                            ),
                            {"expires_at": candidate.expires_at},
                        )
                        if locked is not None:
                            await tx.refresh_tokens.delete({"id": locked.id})

                    await port.transaction(delete_refresh)
                stage = "session"
                sessions = await db.sessions.find_many(
                    where=_filter(db.sessions, "expires_at", "<=", cutoff),
                    limit=32,
                    order_by=(
                        Order(db.sessions.table.columns["expires_at"], "asc"),
                        Order(db.sessions.table.columns["id"], "asc"),
                    ),
                )
                for session in sessions:

                    async def delete_session(
                        tx_port: DatabasePort, candidate: SessionRecord = session
                    ) -> None:
                        tx = self.create_database(tx_port)
                        locked = await tx.sessions.update_if(
                            {"id": candidate.id},
                            and_(
                                _filter(
                                    tx.sessions, "expires_at", "=", candidate.expires_at
                                ),
                                _filter(tx.sessions, "expires_at", "<=", cutoff),
                            ),
                            {"expires_at": candidate.expires_at},
                        )
                        if locked is not None and not await tx.refresh_tokens.find_many(
                            where=_filter(
                                tx.refresh_tokens, "session_id", "=", locked.id
                            ),
                            limit=1,
                        ):
                            await tx.sessions.delete({"id": locked.id})

                    await port.transaction(delete_session)
                stage = "rate_limit"
                limits = await db.rate_limits.find_many(
                    where=_filter(db.rate_limits, "expires_at", "<=", cutoff),
                    limit=32,
                    order_by=(
                        Order(db.rate_limits.table.columns["expires_at"], "asc"),
                        Order(db.rate_limits.table.columns["action"], "asc"),
                        Order(db.rate_limits.table.columns["key_hash"], "asc"),
                    ),
                )
                for limit in limits:

                    async def delete_limit(
                        tx_port: DatabasePort, candidate: RateLimitRecord = limit
                    ) -> None:
                        tx = self.create_database(tx_port)
                        key = {
                            "action": candidate.action,
                            "key_hash": candidate.key_hash,
                        }
                        locked = await tx.rate_limits.update_if(
                            key,
                            and_(
                                _filter(
                                    tx.rate_limits,
                                    "expires_at",
                                    "=",
                                    candidate.expires_at,
                                ),
                                _filter(
                                    tx.rate_limits,
                                    "attempt_count",
                                    "=",
                                    candidate.attempt_count,
                                ),
                                _filter(tx.rate_limits, "expires_at", "<=", cutoff),
                            ),
                            {"attempt_count": candidate.attempt_count},
                        )
                        if locked is not None:
                            await tx.rate_limits.delete(key)

                    await port.transaction(delete_limit)
        except Exception:
            self._cleanup_failure(stage)
        try:
            cutoff_invite = self._timestamp(-30 * 86400)
            invites = await db.invites.find_many(
                where=_filter(db.invites, "expires_at", "<=", cutoff_invite),
                limit=32,
                order_by=(
                    Order(db.invites.table.columns["expires_at"], "asc"),
                    Order(db.invites.table.columns["id"], "asc"),
                ),
            )
            for invite in invites:

                async def delete_invite(
                    tx_port: DatabasePort, candidate: InviteRecord = invite
                ) -> None:
                    tx = self.create_database(tx_port)
                    locked = await tx.invites.update_if(
                        {"id": candidate.id},
                        and_(
                            _filter(
                                tx.invites, "expires_at", "=", candidate.expires_at
                            ),
                            _filter(tx.invites, "expires_at", "<=", cutoff_invite),
                        ),
                        {"expires_at": candidate.expires_at},
                    )
                    if locked is not None:
                        await tx.invites.delete({"id": locked.id})

                await port.transaction(delete_invite)
        except Exception:
            self._cleanup_failure("invite")
