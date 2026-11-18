import asyncio
import re
import threading
import time
from collections.abc import Iterator
from contextlib import AbstractContextManager, contextmanager
from dataclasses import asdict, dataclass, field, replace
from typing import Literal, Protocol, cast, runtime_checkable

from ._conformance import _ClearAttempt, _HookError, _observer
from ._origin import canonical_origin
from ._request_state import _RequestState
from .errors import ClientError, FieldError, OperationError, _local_error
from .wire import read_record, read_string


def _valid_token(token: object) -> bool:
    return (
        isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9_-]{43}", token) is not None
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class SessionCredentials:
    """Immutable native session credentials; tokens are omitted from repr."""

    access_token: str = field(repr=False)
    refresh_token: str = field(repr=False)
    expires_at: str
    refresh_expires_at: str
    user_id: str
    session_id: str


def _validate(credentials: SessionCredentials) -> None:
    if (
        not isinstance(credentials, SessionCredentials)
        or not _valid_token(credentials.access_token)
        or not _valid_token(credentials.refresh_token)
        or any(
            not isinstance(value, str) or not value
            for value in (
                credentials.expires_at,
                credentials.refresh_expires_at,
                credentials.user_id,
                credentials.session_id,
            )
        )
    ):
        raise ClientError("failed_precondition")


def _read_credentials(value: object) -> SessionCredentials:
    record = read_record(value)
    credentials = SessionCredentials(
        access_token=read_string(record.get("access_token")),
        refresh_token=read_string(record.get("refresh_token")),
        expires_at=read_string(record.get("expires_at")),
        refresh_expires_at=read_string(record.get("refresh_expires_at")),
        user_id=read_string(record.get("user_id")),
        session_id=read_string(record.get("session_id")),
    )
    try:
        _validate(credentials)
        return credentials
    except ClientError:
        pass
    raise ClientError("internal")


@dataclass(frozen=True, slots=True)
class _Failure:
    code: str
    status: int | None = None
    operation: bool = False
    valid_error_envelope: bool = False
    retryable: bool = False
    outcome_unknown: bool = False
    hook_failed: bool = False
    storage_failure: bool = False
    reason: str | None = field(default=None, repr=False)
    response_message: str | None = field(default=None, repr=False)
    fields: tuple[FieldError, ...] = field(default=(), repr=False)

    @classmethod
    def from_error(cls, error: ClientError) -> "_Failure":
        return cls(
            error.code,
            error.status,
            isinstance(error, OperationError),
            error._valid_error_envelope if isinstance(error, OperationError) else False,
            outcome_unknown=error._outcome_unknown,
            storage_failure=error._storage_failure,
            reason=error._reason,
            response_message=error.response_message
            if isinstance(error, OperationError)
            else None,
            fields=error.fields if isinstance(error, OperationError) else (),
        )

    def error(self) -> ClientError:
        if self.hook_failed:
            raise _HookError()
        error: ClientError
        if self.operation and self.status is not None:
            error = OperationError(
                self.code, self.status, self.response_message, self.fields
            )
            error._valid_error_envelope = self.valid_error_envelope
        else:
            error = _local_error(self.code, self.reason or self.code, self.status)
            error._storage_failure = self.storage_failure
        error._outcome_unknown = self.outcome_unknown
        return error


@dataclass(slots=True)
class _SyncFlight:
    deadline: float
    settled: bool = False
    result: _Failure | None = None
    producer_done: bool = False
    thread: threading.Thread | None = None
    start_uncertain: bool = False
    start_watch: threading.Timer | None = None
    request_state: _RequestState = field(default_factory=_RequestState, repr=False)


_SESSION_ISSUERS = frozenset(
    {"auth.identity", "auth.signin", "auth.signup", "auth.verify_email"}
)


def _refresh_candidate(operation: str, error: ClientError) -> bool:
    return (
        operation != "auth.refresh"
        and isinstance(error, OperationError)
        and error.status == 401
        and error.code == "invalid_token"
    )


@runtime_checkable
class _SessionStore(Protocol):
    _condition: threading.Condition
    _blocked_generation: int | None
    _flights: dict[int, asyncio.Task[_Failure | None]]
    _sync_flights: dict[int, _SyncFlight]

    def _locked(
        self, deadline: float | None = None
    ) -> AbstractContextManager[None]: ...
    def _attach(self, mode: Literal["sync", "async"], origin: str) -> None: ...
    def credentials(self) -> SessionCredentials | None: ...
    def replace(self, credentials: SessionCredentials) -> None: ...
    def clear(self, expected: SessionCredentials) -> None: ...
    def _register(
        self, deadline: float | None = None, *, allow_empty: bool = False
    ) -> tuple[SessionCredentials | None, int]: ...
    def _current(
        self, snapshot: SessionCredentials | None, generation: int
    ) -> bool: ...
    def _new_credentials(self, generation: int) -> SessionCredentials | None: ...
    def _begin_refresh(self, snapshot: SessionCredentials, generation: int) -> None: ...
    def _apply_refresh(
        self,
        snapshot: SessionCredentials,
        generation: int,
        credentials: SessionCredentials | None,
        failure: _Failure | None,
    ) -> None: ...
    def _release(self, generation: int) -> None: ...
    def _reclaim(self, generation: int) -> None: ...
    def _settled(
        self, generation: int, task: asyncio.Task[_Failure | None]
    ) -> None: ...


def _finish_auth(
    store: _SessionStore,
    operation: str,
    response: object,
    snapshot: SessionCredentials | None,
    generation: int,
    deadline: float | None = None,
) -> None:
    if operation not in _SESSION_ISSUERS and operation != "auth.logout":
        return
    record = read_record(response)
    if operation == "auth.logout":
        read_string(record.get("status"))
        credentials = None
    else:
        if operation == "auth.signup" and "access_token" not in record:
            return
        if "email_verified" in record and type(record["email_verified"]) is not bool:
            raise ClientError("internal")
        credentials = _read_credentials(record)

    with store._locked(deadline):
        if not store._current(snapshot, generation):
            if snapshot is None:
                return
            snapshot = store._new_credentials(generation)
            if snapshot is None:
                return
        if credentials is not None:
            store.replace(credentials)
        elif snapshot is not None:
            store.clear(snapshot)


class _DeviceSession(Protocol):
    _auth_generation: int
    _credentials: SessionCredentials | None

    def _snapshot(self) -> dict[str, object]: ...
    def _accept_login(
        self,
        credentials: SessionCredentials,
        *,
        expected_generation: int,
        user_id: str,
        screens: tuple[str, ...] = (),
        expected_auth_generation: int | None = None,
    ) -> bool: ...
    def _keep_memory(
        self,
        credentials: SessionCredentials,
        *,
        persisted_auth_generation: int,
        persisted_session: object,
        screens: tuple[str, ...] = (),
    ) -> None: ...


def _commit_device_refresh(
    store: _DeviceSession,
    previous: SessionCredentials,
    auth_generation: int | None,
    credentials: SessionCredentials,
) -> None:
    if auth_generation is None:
        return
    try:
        for _ in range(3):
            state = store._snapshot()
            if (
                state["auth_generation"] != auth_generation
                or state["session"] != asdict(previous)
                or state["auth_unknown"]
            ):
                raise ClientError("failed_precondition")
            if store._accept_login(
                credentials,
                user_id=credentials.user_id,
                expected_generation=cast(int, state["generation"]),
                expected_auth_generation=auth_generation,
            ):
                return
        state = store._snapshot()
        if (
            state["auth_generation"] != auth_generation
            or state["session"] != asdict(previous)
            or state["auth_unknown"]
        ):
            raise ClientError("failed_precondition")
    except ClientError as error:
        if not error._storage_failure or error.code not in {
            "failed_precondition",
            "resource_exhausted",
        }:
            raise
    if store._auth_generation != auth_generation or store._credentials != previous:
        raise ClientError("failed_precondition")
    store._keep_memory(
        credentials,
        persisted_auth_generation=auth_generation,
        persisted_session=asdict(previous),
    )


class MemoryStore:
    """An origin-bound store fixed to sync threads or one asyncio loop on attachment."""

    def __init__(
        self, origin: str, credentials: SessionCredentials | None = None
    ) -> None:
        self._origin = canonical_origin(origin)
        self._condition = threading.Condition()
        self._mode: Literal["sync", "async"] | None = None
        self._credentials: SessionCredentials | None = None
        self._generation = 0
        self._session_boundary = 0
        self._blocked_generation: int | None = None
        self._loop: asyncio.AbstractEventLoop | None = None
        self._active: dict[int, int] = {}
        self._flights: dict[int, asyncio.Task[_Failure | None]] = {}
        self._sync_flights: dict[int, _SyncFlight] = {}
        self._clear_attempts: list[_ClearAttempt] | None = None
        if credentials is not None:
            self.replace(credentials)

    @contextmanager
    def _locked(self, deadline: float | None = None) -> Iterator[None]:
        if deadline is None:
            self._condition.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._condition.acquire(timeout=remaining):
                raise ClientError("deadline_exceeded")
        try:
            if deadline is not None and time.monotonic() >= deadline:
                raise ClientError("deadline_exceeded")
            yield
        finally:
            self._condition.release()

    def _check_loop(self) -> None:
        if self._mode == "sync":
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if self._loop is not None and loop is not self._loop:
            raise _local_error("failed_precondition", "wrong_event_loop")
        if loop is not None:
            self._loop = loop

    def _attach(self, mode: Literal["sync", "async"], origin: str) -> None:
        with self._locked():
            if origin != self._origin:
                raise _local_error("failed_precondition", "origin_mismatch")
            if self._mode is not None and self._mode != mode:
                raise ClientError("failed_precondition")
            if self._credentials is not None:
                _validate(self._credentials)
            if mode == "async":
                self._check_loop()
            else:
                self._loop = None
            self._mode = mode

    def credentials(self) -> SessionCredentials | None:
        with self._locked():
            self._check_loop()
            return self._credentials

    def replace(self, credentials: SessionCredentials) -> None:
        with self._locked():
            self._check_loop()
            self._install(credentials)
            self._session_boundary = self._generation

    def _install(self, credentials: SessionCredentials) -> None:
        _validate(credentials)
        self._credentials = replace(credentials)
        self._blocked_generation = None
        self._generation += 1
        self._condition.notify_all()

    def clear(self, expected: SessionCredentials) -> None:
        with self._locked():
            self._check_loop()
            removed = self._credentials is expected
            if removed:
                self._credentials = None
                self._generation += 1
                self._session_boundary = self._generation
                self._condition.notify_all()
            observation = _observer.get()
            if observation is not None and self._clear_attempts is not None:
                self._clear_attempts.append(
                    _ClearAttempt(observation.call_id, expected, removed)
                )

    def _register(
        self, deadline: float | None = None, *, allow_empty: bool = False
    ) -> tuple[SessionCredentials | None, int]:
        with self._locked(deadline):
            self._check_loop()
            snapshot = self._credentials
            generation = self._generation
            if snapshot is None:
                if not allow_empty or self._blocked_generation == generation:
                    raise ClientError("unauthenticated")
            else:
                _validate(snapshot)
            self._active[generation] = self._active.get(generation, 0) + 1
            return snapshot, generation

    def _current(self, snapshot: SessionCredentials | None, generation: int) -> bool:
        return self._generation == generation and self._credentials is snapshot

    def _new_credentials(self, generation: int) -> SessionCredentials | None:
        if self._session_boundary <= generation < self._generation:
            return self._credentials
        return None

    def _begin_refresh(self, snapshot: SessionCredentials, generation: int) -> None:
        pass

    def _apply_refresh(
        self,
        snapshot: SessionCredentials,
        generation: int,
        credentials: SessionCredentials | None,
        failure: _Failure | None,
    ) -> None:
        if failure is not None and failure.hook_failed:
            return
        if not self._current(snapshot, generation):
            observation = _observer.get()
            if (
                observation is not None
                and self._clear_attempts is not None
                and failure is not None
                and failure.valid_error_envelope
                and failure.status == 401
            ):
                self._clear_attempts.append(
                    _ClearAttempt(observation.call_id, snapshot, False)
                )
            return
        if failure is None and credentials is not None:
            self._install(credentials)
        elif failure is not None:
            if failure.valid_error_envelope and failure.status == 401:
                self.clear(snapshot)
            elif not failure.retryable:
                self._blocked_generation = generation

    def _reclaim(self, generation: int) -> None:
        if generation in self._active:
            return
        flight = self._flights.get(generation)
        if flight is not None and flight.done():
            del self._flights[generation]
        sync_flight = self._sync_flights.get(generation)
        if sync_flight is not None and (
            sync_flight.producer_done
            or (
                sync_flight.start_uncertain
                and sync_flight.settled
                and time.monotonic() >= sync_flight.deadline
                and (sync_flight.thread is None or not sync_flight.thread.is_alive())
            )
        ):
            del self._sync_flights[generation]

    def _release(self, generation: int) -> None:
        with self._locked():
            remaining = self._active[generation] - 1
            if remaining:
                self._active[generation] = remaining
            else:
                del self._active[generation]
            self._reclaim(generation)

    def _settled(self, generation: int, task: asyncio.Task[_Failure | None]) -> None:
        if not task.cancelled():
            task.exception()
        with self._locked():
            self._reclaim(generation)
