import functools
import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from http.cookiejar import CookieJar
from typing import TYPE_CHECKING, Protocol, Self, cast

from ._conformance import _HookError, _Observation, _observer
from ._device import _device_store, _DeviceStore, _persist_settings
from ._http_common import (
    _HEADERS,
    _Body,
    _check_environment,
    _NoCookies,
    _operation,
    _response,
    _serialize,
    _timeout,
)
from ._origin import canonical_origin
from ._request_logs import _request_logs
from ._request_state import _RequestState, _state
from .errors import ClientError, OperationError, _local_error
from .session import (
    SessionCredentials,
    _Failure,
    _finish_auth,
    _read_credentials,
    _refresh_candidate,
    _SessionStore,
    _SyncFlight,
    _valid_token,
)

if TYPE_CHECKING:
    import httpx


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ClientError("deadline_exceeded")


class Transport(Protocol):
    """The synchronous operation contract consumed by generated clients."""

    def invoke(self, operation: str, payload: bytes | Mapping[str, object]) -> object:
        """Invoke one operation and return its parsed JSON value."""
        ...


class HttpTransport:
    """An origin-bound synchronous transport with a pool shared safely by threads."""

    def __init__(
        self,
        origin: str,
        *,
        timeout: float = 30.0,
        persist: bool | Mapping[str, object] = True,
    ) -> None:
        _check_environment()
        self._origin = canonical_origin(origin)
        self._timeout = _timeout(timeout)
        self._persist = _persist_settings(persist)
        self._lock = threading.RLock()
        self._closed = False
        self._client: httpx.Client | None = None

    @contextmanager
    def _locked(self, deadline: float | None = None) -> Iterator[None]:
        if deadline is None:
            self._lock.acquire()
        else:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self._lock.acquire(timeout=remaining):
                raise ClientError("deadline_exceeded")
        try:
            if self._closed:
                raise _local_error("failed_precondition", "transport_closed")
            if deadline is not None:
                _check_deadline(deadline)
            yield
        finally:
            self._lock.release()

    def _http_client(self, deadline: float | None = None) -> "httpx.Client":
        _check_environment()
        with self._locked(deadline):
            if self._client is None:
                import httpx

                from ._sync_network import _Transport

                self._client = httpx.Client(
                    transport=_Transport(),
                    follow_redirects=False,
                    trust_env=False,
                    verify=True,
                    timeout=self._timeout,
                    cookies=CookieJar(policy=_NoCookies()),
                    headers=_HEADERS,
                )
            return self._client

    def __enter__(self) -> Self:
        self._http_client()
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            client = self._client
        if client is not None:
            client.close()

    def _device_store(
        self, *, app: str, project: str, environment: str
    ) -> _DeviceStore:
        return _device_store(
            self._origin,
            app=app,
            project=project,
            environment=environment,
            persist=self._persist,
        )

    def with_bearer(self, token: str) -> Transport:
        with self._locked():
            if not _valid_token(token):
                raise _local_error("invalid_argument", "invalid_token")
            return _Authenticated(self, token=token)

    def with_session(self, store: _SessionStore) -> Transport:
        with self._locked():
            if not isinstance(store, _SessionStore):
                raise ClientError("failed_precondition")
        store._attach("sync", self._origin)
        return _Authenticated(self, store=store)

    def invoke(self, operation: str, payload: bytes | Mapping[str, object]) -> object:
        return self._invoke(operation, payload, None, None)

    def invoke_public(
        self, operation: str, payload: bytes | Mapping[str, object]
    ) -> object:
        """Invoke an operation declared public by the generated SDK."""
        return self._invoke(operation, payload, None, None, public=True)

    def _invoke(
        self,
        operation: str,
        payload: bytes | Mapping[str, object],
        token: str | None,
        store: _SessionStore | None,
        *,
        public: bool = False,
    ) -> object:
        observation = _observer.get()
        if observation is not None:
            observation.notify("entered")
            observation.arrive("sdk-entered", {"entered": True})
        deadline = time.monotonic() + 3 * self._timeout
        _check_environment()
        with self._locked(deadline):
            pass
        _operation(operation)
        body = _serialize(payload)
        _check_deadline(deadline)
        snapshot: SessionCredentials | None = None
        generation = 0
        refresh_allowed = True
        if store is not None:
            with store._locked(deadline):
                snapshot, generation = store._register(deadline, allow_empty=public)
                refresh_allowed = store._blocked_generation != generation
            token = snapshot.access_token if snapshot is not None else None
        try:
            try:
                result = self._attempt(
                    operation,
                    body,
                    None if operation == "auth.refresh" else token,
                    deadline,
                )
            except OperationError as failure:
                if (
                    store is None
                    or snapshot is None
                    or not refresh_allowed
                    or not _refresh_candidate(operation, failure)
                ):
                    raise
                if observation is not None:
                    observation.arrive("both-originals-rejected", {"httpStatus": 401})
                self._refresh(store, snapshot, generation, deadline)
                with store._locked(deadline):
                    latest = store._new_credentials(generation)
                if latest is None:
                    raise failure
                result = self._attempt(operation, body, latest.access_token, deadline)
            if store is not None:
                _finish_auth(store, operation, result, snapshot, generation, deadline)
            return result
        finally:
            if store is not None:
                store._release(generation)

    def _refresh(
        self,
        store: _SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        deadline: float,
    ) -> None:
        elected = False
        with store._locked(deadline):
            if store._new_credentials(generation):
                return
            flight = store._sync_flights.get(generation)
            if flight is None:
                if not store._current(snapshot, generation):
                    return
                flight = _SyncFlight(time.monotonic() + self._timeout)
                store._sync_flights[generation] = flight
                elected = True
        observation = _observer.get()
        if observation is not None:
            observation.flight = flight
        if elected:
            thread: threading.Thread | None = None
            try:
                thread = threading.Thread(
                    target=self._produce,
                    args=(store, snapshot, generation, flight, observation)
                    if observation is not None
                    else (store, snapshot, generation, flight),
                    daemon=False,
                )
                with store._locked():
                    flight.thread = thread
                thread.start()
            except BaseException as error:
                if isinstance(error, RuntimeError) and (
                    thread is None or thread.ident is None
                ):
                    self._publish(
                        store,
                        snapshot,
                        generation,
                        flight,
                        None,
                        _Failure("unavailable", retryable=True),
                    )
                else:
                    self._watch_start(store, snapshot, generation, flight)
                    if not isinstance(error, Exception):
                        raise
        elif (
            observation is not None
            and observation.flight_ref is not None
            and not flight.settled
        ):
            observation.arrive(
                "refresh-joined", {"refreshRef": observation.flight_ref(flight)}
            )
        with store._locked(deadline):
            while not flight.settled:
                now = time.monotonic()
                if now >= flight.deadline:
                    flight.result = _Failure(
                        "deadline_exceeded",
                        outcome_unknown=flight.request_state.outcome_unknown,
                    )
                    store._apply_refresh(snapshot, generation, None, flight.result)
                    flight.settled = True
                    store._condition.notify_all()
                    break
                remaining = min(deadline, flight.deadline) - now
                if remaining <= 0:
                    raise ClientError("deadline_exceeded")
                store._condition.wait(remaining)
                _check_deadline(deadline)
            result = flight.result
        if result is not None:
            raise result.error()

    def _watch_start(
        self,
        store: _SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        flight: _SyncFlight,
    ) -> None:
        watch = threading.Timer(
            max(0.0, flight.deadline - time.monotonic()),
            self._expire_start,
            args=(store, snapshot, generation, flight),
        )
        watch.daemon = False
        with store._locked():
            flight.start_uncertain = True
            if flight.producer_done:
                return
            flight.start_watch = watch
        try:
            watch.start()
        except RuntimeError:
            # Even without thread-creation resources, the next store sweep enforces the deadline.
            pass

    def _expire_start(
        self,
        store: _SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        flight: _SyncFlight,
    ) -> None:
        with store._locked():
            if not flight.settled:
                flight.result = _Failure(
                    "deadline_exceeded",
                    outcome_unknown=flight.request_state.outcome_unknown,
                )
                store._apply_refresh(snapshot, generation, None, flight.result)
                flight.settled = True
            store._condition.notify_all()
            store._reclaim(generation)

    def _produce(
        self,
        store: _SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        flight: _SyncFlight,
        hook: _Observation | None = None,
    ) -> None:
        credentials: SessionCredentials | None = None
        failure: _Failure | None = _Failure("unavailable")
        observation = _state.set(flight.request_state)
        registration = _observer.set(hook) if hook is not None else None
        try:
            store._begin_refresh(snapshot, generation)
            credentials = cast(
                SessionCredentials,
                self._attempt(
                    "auth.refresh",
                    _serialize({"refresh_token": snapshot.refresh_token}),
                    None,
                    flight.deadline,
                    credentials=True,
                ),
            )
            failure = None
        except ClientError as error:
            failure = _Failure.from_error(error)
        except _HookError:
            failure = _Failure("unavailable", retryable=True, hook_failed=True)
        except BaseException:
            failure = _Failure("unavailable")
        finally:
            _state.reset(observation)
            self._publish(store, snapshot, generation, flight, credentials, failure)
            if registration is not None:
                _observer.reset(registration)

    def _publish(
        self,
        store: _SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        flight: _SyncFlight,
        credentials: SessionCredentials | None,
        failure: _Failure | None,
    ) -> None:
        with store._locked():
            if not flight.settled:
                if time.monotonic() >= flight.deadline:
                    failure = _Failure(
                        "deadline_exceeded",
                        failure.status if failure is not None else None,
                        outcome_unknown=flight.request_state.outcome_unknown,
                        hook_failed=failure.hook_failed
                        if failure is not None
                        else False,
                    )
                    credentials = None
                try:
                    store._apply_refresh(snapshot, generation, credentials, failure)
                except ClientError as error:
                    failure = _Failure.from_error(error)
                flight.result = failure
                flight.settled = True
            flight.producer_done = True
            store._condition.notify_all()
            store._reclaim(generation)
        if flight.start_watch is not None:
            flight.start_watch.cancel()

    def _attempt(
        self,
        operation: str,
        body: bytes,
        token: str | None,
        deadline: float,
        *,
        credentials: bool = False,
    ) -> object:
        refresh = operation == "auth.refresh"
        state = _state.get() or _RequestState()
        observation = _observer.get()
        if observation is not None:
            deadline = min(deadline, observation.deadline)
        with _request_logs():
            deadline = min(deadline, time.monotonic() + self._timeout)
            client = self._http_client(deadline)
            import httpcore
            import httpx

            from ._sync_network import _deadline, _remaining

            context = _deadline.set(deadline)
            status: int | None = None
            reason: str | None = None
            failure: ClientError | None = None
            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            try:
                try:
                    _remaining()
                    with client.stream(
                        "POST",
                        self._origin + "/" + operation,
                        content=body,
                        headers=headers,
                        extensions={
                            "trace": functools.partial(
                                observation.trace, state, refresh=credentials
                            )
                            if observation is not None
                            else state.trace
                        },
                    ) as response:
                        status = response.status_code
                        if observation is not None:
                            observation.notify("headers", response)
                            observation.record_headers(
                                status, response.headers.values()
                            )
                        if 300 <= status < 400:
                            if observation is not None:
                                observation.notify("redirect", response)
                            if not refresh:
                                state.finish()
                            raise _local_error("internal", "operation_failed", status)
                        decoder = _Body(
                            response.headers.get("content-encoding", "identity"), status
                        )
                        for chunk in response.iter_raw():
                            _remaining()
                            decoder.feed(chunk)
                            _remaining()
                        data = decoder.finish()
                        if observation is not None:
                            observation.record_body(data)
                        if not refresh:
                            state.finish()
                        value = _response(data, status)
                        if refresh:
                            try:
                                decoded = _read_credentials(value)
                            except ClientError:
                                reason = "internal"
                            else:
                                _remaining()
                                state.finish()
                                return decoded if credentials else value
                        else:
                            _remaining()
                            return value
                except (
                    TimeoutError,
                    httpcore.TimeoutException,
                    httpx.TimeoutException,
                ) as error:
                    if observation is not None:
                        observation.details.extend((type(error).__name__, str(error)))
                    reason = "deadline_exceeded"
                except (
                    httpcore.NetworkError,
                    httpcore.ProtocolError,
                    httpx.HTTPError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ) as error:
                    if observation is not None:
                        observation.details.extend((type(error).__name__, str(error)))
                    reason = "unavailable"
                except ClientError as error:
                    if (
                        refresh
                        and isinstance(error, OperationError)
                        and error._valid_error_envelope
                        and error.status == 401
                    ):
                        state.finish()
                    failure = error
            finally:
                _deadline.reset(context)
            if reason is not None:
                failure = ClientError(reason, status)
            if failure is not None:
                failure._outcome_unknown = state.outcome_unknown
                raise failure
            raise AssertionError


class _Authenticated:
    def __init__(
        self,
        owner: HttpTransport,
        *,
        token: str | None = None,
        store: _SessionStore | None = None,
    ) -> None:
        self._owner = owner
        self._token = token
        self._store = store

    def invoke(self, operation: str, payload: bytes | Mapping[str, object]) -> object:
        return self._owner._invoke(operation, payload, self._token, self._store)

    def invoke_public(
        self, operation: str, payload: bytes | Mapping[str, object]
    ) -> object:
        return self._owner._invoke(
            operation, payload, self._token, self._store, public=True
        )
