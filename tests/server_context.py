"""Context shapes consumed by runtime tests; production generation belongs to the CLI."""

from dataclasses import dataclass

from chickinfry.orm import Repository
from chickinfry.server import AuthContext, RequestInfo, Session

from .server_fixture import Record


@dataclass(frozen=True, slots=True, kw_only=True)
class ProtectedContext:
    auth: AuthContext[Session]
    db: Repository[Record]
    request: RequestInfo


@dataclass(frozen=True, slots=True, kw_only=True)
class PublicContext:
    auth: AuthContext[Session | None]
    db: Repository[Record]
    request: RequestInfo


@dataclass(frozen=True, slots=True, kw_only=True)
class Context:
    request: RequestInfo


@dataclass(frozen=True, slots=True, kw_only=True)
class DatabaseContext:
    db: Repository[Record]
    request: RequestInfo
