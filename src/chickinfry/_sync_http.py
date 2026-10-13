import threading
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from http.cookiejar import CookieJar
from typing import TYPE_CHECKING, Protocol, Self, cast

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
from .errors import ClientError, OperationError
from .session import (
    SessionCredentials,
    SessionStore,
    _Failure,
    _read_credentials,
    _refresh_candidate,
    _SyncFlight,
    _valid_token,
)

if TYPE_CHECKING:
    import httpx


def _check_deadline(deadline: float) -> None:
    if time.monotonic() >= deadline:
        raise ClientError("timeout")


class SyncClientTransport(Protocol):
    """The synchronous operation contract consumed by generated clients."""

    def invoke(self, operation: str, payload: bytes | Mapping[str, object]) -> object:
        """Invoke one operation and return its parsed JSON value."""
        ...


class HTTP:
    """An origin-bound synchronous transport with a pool shared safely by threads."""

    def __init__(self, origin: str, *, timeout: float = 30.0) -> None:
        _check_environment()
        self._origin = canonical_origin(origin)
        self._timeout = _timeout(timeout)
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
                raise ClientError("timeout")
        try:
            if self._closed:
                raise ClientError("transport_closed")
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

    def with_bearer(self, token: str) -> SyncClientTransport:
        with self._locked():
            if not _valid_token(token):
                raise ClientError("invalid_token")
            return _Authenticated(self, token=token)

    def with_session(self, store: SessionStore) -> SyncClientTransport:
        with self._locked():
            if not isinstance(store, SessionStore):
                raise ClientError("invalid_session")
        store._attach("sync", self._origin)
        return _Authenticated(self, store=store)

    def invoke(self, operation: str, payload: bytes | Mapping[str, object]) -> object:
        return self._invoke(operation, payload, None, None)

    def _invoke(
        self,
        operation: str,
        payload: bytes | Mapping[str, object],
        token: str | None,
        store: SessionStore | None,
    ) -> object:
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
                snapshot, generation = store._register(deadline)
                refresh_allowed = store._blocked_generation != generation
            token = snapshot.access_token
        try:
            try:
                return self._attempt(
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
                self._refresh(store, snapshot, generation, deadline)
                with store._locked(deadline):
                    latest = store._credentials
                if latest is None:
                    raise failure
                return self._attempt(operation, body, latest.access_token, deadline)
        finally:
            if store is not None:
                store._release(generation)

    def _refresh(
        self,
        store: SessionStore,
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
        if elected:
            thread: threading.Thread | None = None
            try:
                thread = threading.Thread(
                    target=self._produce,
                    args=(store, snapshot, generation, flight),
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
                        _Failure("network_error", retryable=True),
                    )
                else:
                    self._watch_start(store, snapshot, generation, flight)
                    if not isinstance(error, Exception):
                        raise
        with store._locked(deadline):
            while not flight.settled:
                now = time.monotonic()
                if now >= flight.deadline:
                    flight.result = _Failure(
                        "timeout", outcome_unknown=flight.request_state.outcome_unknown
                    )
                    store._apply_refresh(snapshot, generation, None, flight.result)
                    flight.settled = True
                    store._condition.notify_all()
                    break
                remaining = min(deadline, flight.deadline) - now
                if remaining <= 0:
                    raise ClientError("timeout")
                store._condition.wait(remaining)
                _check_deadline(deadline)
            result = flight.result
        if result is not None:
            raise result.error()

    def _watch_start(
        self,
        store: SessionStore,
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
        store: SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        flight: _SyncFlight,
    ) -> None:
        with store._locked():
            if not flight.settled:
                flight.result = _Failure(
                    "timeout", outcome_unknown=flight.request_state.outcome_unknown
                )
                store._apply_refresh(snapshot, generation, None, flight.result)
                flight.settled = True
            store._condition.notify_all()
            store._reclaim(generation)

    def _produce(
        self,
        store: SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        flight: _SyncFlight,
    ) -> None:
        credentials: SessionCredentials | None = None
        failure: _Failure | None = _Failure("network_error")
        observation = _state.set(flight.request_state)
        try:
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
        except BaseException:
            failure = _Failure("network_error")
        finally:
            _state.reset(observation)
            self._publish(store, snapshot, generation, flight, credentials, failure)

    def _publish(
        self,
        store: SessionStore,
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
                        "timeout",
                        failure.status if failure is not None else None,
                        outcome_unknown=flight.request_state.outcome_unknown,
                    )
                    credentials = None
                store._apply_refresh(snapshot, generation, credentials, failure)
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
        state = _state.get() or _RequestState()
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
                        extensions={"trace": state.trace},
                    ) as response:
                        status = response.status_code
                        if 300 <= status < 400:
                            state.finish()
                            raise OperationError("redirect_not_allowed", status)
                        decoder = _Body(
                            response.headers.get("content-encoding", "identity"), status
                        )
                        for chunk in response.iter_raw():
                            _remaining()
                            decoder.feed(chunk)
                            _remaining()
                        data = decoder.finish()
                        state.finish()
                        value = _response(data, status)
                        if credentials:
                            try:
                                value = _read_credentials(value)
                            except ClientError:
                                reason = "invalid_response"
                            else:
                                _remaining()
                                return value
                        else:
                            _remaining()
                            return value
                except (
                    TimeoutError,
                    httpcore.TimeoutException,
                    httpx.TimeoutException,
                ):
                    reason = "timeout"
                except (
                    httpcore.NetworkError,
                    httpcore.ProtocolError,
                    httpx.HTTPError,
                    OSError,
                    RuntimeError,
                    ValueError,
                ):
                    reason = "network_error"
                except ClientError as error:
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
        owner: HTTP,
        *,
        token: str | None = None,
        store: SessionStore | None = None,
    ) -> None:
        self._owner = owner
        self._token = token
        self._store = store

    def invoke(self, operation: str, payload: bytes | Mapping[str, object]) -> object:
        return self._owner._invoke(operation, payload, self._token, self._store)
