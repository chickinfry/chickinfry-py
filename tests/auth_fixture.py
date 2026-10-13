"""Test-only auth ORM derived from canonical generated metadata.
Source: chickinfry-js/src/auth/private/database.ts
Commit: ef83082deb867cd098cfa6ef859af2e210a4d475
Defaults: CLI auth/schema.go at 06752cc4a588fed6a11102405a401aa1cad430d1.
Replace with the CLI-generated Python private ORM when that renderer lands.
"""

from collections.abc import Mapping
from dataclasses import dataclass

from chickinfry.auth import AuthDatabase
from chickinfry.orm import Column, DatabasePort, Repository, Table


@dataclass(frozen=True, slots=True)
class AppAuthIdentitiesRow:
    created_at: str
    provider: str
    subject: str
    user_id: str


APPAUTHIDENTITIES_TABLE = Table(
    "app_auth_identities",
    {
        "created_at": Column[str]("created_at", "timestamp", False),
        "provider": Column[str]("provider", "string", False),
        "subject": Column[str]("subject", "string", False),
        "user_id": Column[str]("user_id", "id", False),
    },
    ("provider", "subject"),
    ("provider", "subject", "user_id"),
)


def decode_appAuthIdentities(row: Mapping[str, object]) -> AppAuthIdentitiesRow:
    return AppAuthIdentitiesRow(
        created_at=read_str(row["created_at"]),
        provider=read_str(row["provider"]),
        subject=read_str(row["subject"]),
        user_id=read_str(row["user_id"]),
    )


@dataclass(frozen=True, slots=True)
class AppAuthInvitesRow:
    code_hash: str
    created_at: str
    email: str
    expires_at: str
    id: str
    issued_by: str
    redeemed_at: str | None
    redeemed_by: str | None
    revoked_at: str | None


APPAUTHINVITES_TABLE = Table(
    "app_auth_invites",
    {
        "code_hash": Column[str]("code_hash", "string", False),
        "created_at": Column[str]("created_at", "timestamp", False),
        "email": Column[str]("email", "string", False),
        "expires_at": Column[str]("expires_at", "timestamp", False),
        "id": Column[str]("id", "id", False),
        "issued_by": Column[str]("issued_by", "id", False),
        "redeemed_at": Column[str | None]("redeemed_at", "timestamp", True),
        "redeemed_by": Column[str | None]("redeemed_by", "id", True),
        "revoked_at": Column[str | None]("revoked_at", "timestamp", True),
    },
    ("id",),
    ("code_hash", "email", "expires_at", "issued_by"),
)


def decode_appAuthInvites(row: Mapping[str, object]) -> AppAuthInvitesRow:
    return AppAuthInvitesRow(
        code_hash=read_str(row["code_hash"]),
        created_at=read_str(row["created_at"]),
        email=read_str(row["email"]),
        expires_at=read_str(row["expires_at"]),
        id=read_str(row["id"]),
        issued_by=read_str(row["issued_by"]),
        redeemed_at=read_optional(row["redeemed_at"]),
        redeemed_by=read_optional(row["redeemed_by"]),
        revoked_at=read_optional(row["revoked_at"]),
    )


@dataclass(frozen=True, slots=True)
class AppAuthRateLimitsRow:
    action: str
    attempt_count: int
    expires_at: str
    key_hash: str


APPAUTHRATELIMITS_TABLE = Table(
    "app_auth_rate_limits",
    {
        "action": Column[str]("action", "string", False),
        "attempt_count": Column[int]("attempt_count", "integer", False),
        "expires_at": Column[str]("expires_at", "timestamp", False),
        "key_hash": Column[str]("key_hash", "string", False),
    },
    ("action", "key_hash"),
    ("action", "attempt_count", "expires_at", "key_hash"),
)


def decode_appAuthRateLimits(row: Mapping[str, object]) -> AppAuthRateLimitsRow:
    return AppAuthRateLimitsRow(
        action=read_str(row["action"]),
        attempt_count=read_int(row["attempt_count"]),
        expires_at=read_str(row["expires_at"]),
        key_hash=read_str(row["key_hash"]),
    )


@dataclass(frozen=True, slots=True)
class AppAuthRefreshTokensRow:
    consumed_at: str | None
    created_at: str
    expires_at: str
    id: str
    session_id: str
    token_hash: str


APPAUTHREFRESHTOKENS_TABLE = Table(
    "app_auth_refresh_tokens",
    {
        "consumed_at": Column[str | None]("consumed_at", "timestamp", True),
        "created_at": Column[str]("created_at", "timestamp", False),
        "expires_at": Column[str]("expires_at", "timestamp", False),
        "id": Column[str]("id", "id", False),
        "session_id": Column[str]("session_id", "id", False),
        "token_hash": Column[str]("token_hash", "string", False),
    },
    ("id",),
    ("expires_at", "session_id", "token_hash"),
)


def decode_appAuthRefreshTokens(row: Mapping[str, object]) -> AppAuthRefreshTokensRow:
    return AppAuthRefreshTokensRow(
        consumed_at=read_optional(row["consumed_at"]),
        created_at=read_str(row["created_at"]),
        expires_at=read_str(row["expires_at"]),
        id=read_str(row["id"]),
        session_id=read_str(row["session_id"]),
        token_hash=read_str(row["token_hash"]),
    )


@dataclass(frozen=True, slots=True)
class AppAuthSessionsRow:
    created_at: str
    expires_at: str
    id: str
    revoked_at: str | None
    token_hash: str
    transport: str
    user_id: str
    user_session_version: int


APPAUTHSESSIONS_TABLE = Table(
    "app_auth_sessions",
    {
        "created_at": Column[str]("created_at", "timestamp", False),
        "expires_at": Column[str]("expires_at", "timestamp", False),
        "id": Column[str]("id", "id", False),
        "revoked_at": Column[str | None]("revoked_at", "timestamp", True),
        "token_hash": Column[str]("token_hash", "string", False),
        "transport": Column[str]("transport", "string", False),
        "user_id": Column[str]("user_id", "id", False),
        "user_session_version": Column[int]("user_session_version", "integer", False),
    },
    ("id",),
    ("expires_at", "token_hash", "user_id", "user_session_version"),
)


def decode_appAuthSessions(row: Mapping[str, object]) -> AppAuthSessionsRow:
    return AppAuthSessionsRow(
        created_at=read_str(row["created_at"]),
        expires_at=read_str(row["expires_at"]),
        id=read_str(row["id"]),
        revoked_at=read_optional(row["revoked_at"]),
        token_hash=read_str(row["token_hash"]),
        transport=read_str(row["transport"]),
        user_id=read_str(row["user_id"]),
        user_session_version=read_int(row["user_session_version"]),
    )


@dataclass(frozen=True, slots=True)
class AppAuthUsersRow:
    created_at: str
    disabled_at: str | None
    email: str
    id: str
    password_hash: str | None
    session_version: int


APPAUTHUSERS_TABLE = Table(
    "app_auth_users",
    {
        "created_at": Column[str]("created_at", "timestamp", False),
        "disabled_at": Column[str | None]("disabled_at", "timestamp", True),
        "email": Column[str]("email", "string", False),
        "id": Column[str]("id", "id", False),
        "password_hash": Column[str | None]("password_hash", "string", True),
        "session_version": Column[int]("session_version", "integer", False),
    },
    ("id",),
    ("email",),
)


def decode_appAuthUsers(row: Mapping[str, object]) -> AppAuthUsersRow:
    return AppAuthUsersRow(
        created_at=read_str(row["created_at"]),
        disabled_at=read_optional(row["disabled_at"]),
        email=read_str(row["email"]),
        id=read_str(row["id"]),
        password_hash=read_optional(row["password_hash"]),
        session_version=read_int(row["session_version"]),
    )


def read_str(value: object) -> str:
    assert isinstance(value, str)
    return value


def read_int(value: object) -> int:
    assert type(value) is int
    return value


def read_optional(value: object) -> str | None:
    assert value is None or isinstance(value, str)
    return value


class PrivateDatabase:
    def __init__(self, port: DatabasePort) -> None:
        self.identities = Repository(
            port, APPAUTHIDENTITIES_TABLE, decode_appAuthIdentities
        )
        self.invites = Repository(port, APPAUTHINVITES_TABLE, decode_appAuthInvites)
        self.rate_limits = Repository(
            port, APPAUTHRATELIMITS_TABLE, decode_appAuthRateLimits
        )
        self.refresh_tokens = Repository(
            port, APPAUTHREFRESHTOKENS_TABLE, decode_appAuthRefreshTokens
        )
        self.sessions = Repository(port, APPAUTHSESSIONS_TABLE, decode_appAuthSessions)
        self.users = Repository(port, APPAUTHUSERS_TABLE, decode_appAuthUsers)


def create_database(port: DatabasePort) -> AuthDatabase:
    return PrivateDatabase(port)


AUTH_DDL = 'create table "public"."app_auth_users" ("created_at" timestamptz not null default now(), "disabled_at" timestamptz, "email" text not null unique, "id" uuid not null default gen_random_uuid(), "password_hash" text, "session_version" integer not null default 1, primary key ("id"));\ncreate table "public"."app_auth_sessions" ("created_at" timestamptz not null default now(), "expires_at" timestamptz not null, "id" uuid not null default gen_random_uuid(), "revoked_at" timestamptz, "token_hash" text not null unique, "transport" text not null default \'native\', "user_id" uuid not null references "public"."app_auth_users" ("id"), "user_session_version" integer not null, primary key ("id"));\ncreate table "public"."app_auth_refresh_tokens" ("consumed_at" timestamptz, "created_at" timestamptz not null default now(), "expires_at" timestamptz not null, "id" uuid not null default gen_random_uuid(), "session_id" uuid not null references "public"."app_auth_sessions" ("id"), "token_hash" text not null unique, primary key ("id"));\ncreate table "public"."app_auth_identities" ("created_at" timestamptz not null default now(), "provider" text not null, "subject" text not null, "user_id" uuid not null references "public"."app_auth_users" ("id"), primary key ("provider", "subject"));\ncreate table "public"."app_auth_rate_limits" ("action" text not null, "attempt_count" integer not null, "expires_at" timestamptz not null, "key_hash" text not null, primary key ("action", "key_hash"));\ncreate table "public"."app_auth_invites" ("code_hash" text not null unique, "created_at" timestamptz not null default now(), "email" text not null, "expires_at" timestamptz not null, "id" uuid not null default gen_random_uuid(), "issued_by" uuid not null references "public"."app_auth_users" ("id"), "redeemed_at" timestamptz, "redeemed_by" uuid references "public"."app_auth_users" ("id"), "revoked_at" timestamptz, primary key ("id"));'
