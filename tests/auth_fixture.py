"""Test-only DDL and public-row readers; auth repositories are CLI-generated."""


def read_str(value: object) -> str:
    assert isinstance(value, str)
    return value


def read_int(value: object) -> int:
    assert type(value) is int
    return value


def read_optional(value: object) -> str | None:
    assert value is None or isinstance(value, str)
    return value


AUTH_DDL = 'create table "public"."app_auth_users" ("created_at" timestamptz not null default now(), "disabled_at" timestamptz, "email" text not null unique, "id" uuid not null default gen_random_uuid(), "password_hash" text, "session_version" integer not null default 1, primary key ("id"));\ncreate table "public"."app_auth_sessions" ("created_at" timestamptz not null default now(), "expires_at" timestamptz not null, "id" uuid not null default gen_random_uuid(), "revoked_at" timestamptz, "token_hash" text not null unique, "transport" text not null default \'native\', "user_id" uuid not null references "public"."app_auth_users" ("id"), "user_session_version" integer not null, primary key ("id"));\ncreate table "public"."app_auth_refresh_tokens" ("consumed_at" timestamptz, "created_at" timestamptz not null default now(), "expires_at" timestamptz not null, "id" uuid not null default gen_random_uuid(), "session_id" uuid not null references "public"."app_auth_sessions" ("id"), "token_hash" text not null unique, primary key ("id"));\ncreate table "public"."app_auth_identities" ("created_at" timestamptz not null default now(), "provider" text not null, "subject" text not null, "user_id" uuid not null references "public"."app_auth_users" ("id"), primary key ("provider", "subject"));\ncreate table "public"."app_auth_rate_limits" ("action" text not null, "attempt_count" integer not null, "expires_at" timestamptz not null, "key_hash" text not null, primary key ("action", "key_hash"));\ncreate table "public"."app_auth_invites" ("code_hash" text not null unique, "created_at" timestamptz not null default now(), "email" text not null, "expires_at" timestamptz not null, "id" uuid not null default gen_random_uuid(), "issued_by" uuid not null references "public"."app_auth_users" ("id"), "redeemed_at" timestamptz, "redeemed_by" uuid references "public"."app_auth_users" ("id"), "revoked_at" timestamptz, primary key ("id"));'
