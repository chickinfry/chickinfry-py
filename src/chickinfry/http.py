import asyncio
import functools
from collections.abc import Mapping
from http.cookiejar import CookieJar
from typing import TYPE_CHECKING, Protocol, Self, cast

from ._conformance import _observer
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
from ._request_state import _RequestState
from .errors import ClientError, OperationError
from .session import (
    SessionCredentials,
    SessionStore,
    _Failure,
    _read_credentials,
    _refresh_candidate,
    _valid_token,
)

if TYPE_CHECKING:
    import httpx


def _check_deadline(deadline: float) -> None:
    if asyncio.get_running_loop().time() >= deadline:
        raise ClientError("timeout")


class ClientTransport(Protocol):
    """The shared async operation contract consumed by generated clients."""

    async def invoke(
        self, operation: str, payload: bytes | Mapping[str, object]
    ) -> object:
        """Invoke one operation and return its parsed JSON value."""
        ...


class AsyncHTTP:
    """An anonymous origin-bound transport owning the lifetime of its HTTP pool."""

    def __init__(self, origin: str, *, timeout: float = 30.0) -> None:
        _check_environment()
        self._origin = canonical_origin(origin)
        self._timeout = _timeout(timeout)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._client: httpx.AsyncClient | None = None
        self._closed = False

    def _check_loop(self) -> None:
        _check_environment()
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None
        if loop is None or (self._loop is not None and self._loop is not loop):
            raise ClientError("wrong_event_loop")
        self._loop = loop
        if self._closed:
            raise ClientError("transport_closed")

    def _http_client(self) -> "httpx.AsyncClient":
        self._check_loop()
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(
                transport=httpx.AsyncHTTPTransport(
                    retries=0, verify=True, trust_env=False
                ),
                follow_redirects=False,
                trust_env=False,
                verify=True,
                timeout=self._timeout,
                cookies=CookieJar(policy=_NoCookies()),
                headers=_HEADERS,
            )
        return self._client

    async def __aenter__(self) -> Self:
        self._http_client()
        return self

    async def __aexit__(self, *args: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._check_loop()
        self._closed = True
        if self._client is not None:
            await self._client.aclose()

    def with_bearer(self, token: str) -> ClientTransport:
        if not _valid_token(token):
            raise ClientError("invalid_token")
        return _Authenticated(self, token=token)

    def with_session(self, store: SessionStore) -> ClientTransport:
        if not isinstance(store, SessionStore):
            raise ClientError("invalid_session")
        store._attach("async", self._origin)
        return _Authenticated(self, store=store)

    async def invoke(
        self, operation: str, payload: bytes | Mapping[str, object]
    ) -> object:
        return await self._invoke(operation, payload, None, None)

    async def _invoke(
        self,
        operation: str,
        payload: bytes | Mapping[str, object],
        token: str | None,
        store: SessionStore | None,
    ) -> object:
        self._check_loop()
        deadline = asyncio.get_running_loop().time() + 3 * self._timeout
        _operation(operation)
        body = _serialize(payload)
        _check_deadline(deadline)
        snapshot: SessionCredentials | None = None
        generation = 0
        refresh_allowed = True
        if store is not None:
            with store._locked():
                snapshot, generation = store._register()
                refresh_allowed = store._blocked_generation != generation
            token = snapshot.access_token
        timed_out = False
        try:
            try:
                async with asyncio.timeout_at(deadline):
                    try:
                        return await self._attempt(
                            operation,
                            body,
                            None if operation == "auth.refresh" else token,
                            deadline=deadline,
                        )
                    except OperationError as failure:
                        if (
                            store is None
                            or snapshot is None
                            or not refresh_allowed
                            or not _refresh_candidate(operation, failure)
                        ):
                            raise
                        await self._refresh(store, snapshot, generation)
                        latest = store.credentials()
                        if latest is None:
                            raise failure
                        return await self._attempt(
                            operation, body, latest.access_token, deadline=deadline
                        )
            except TimeoutError:
                timed_out = True
        finally:
            if store is not None:
                store._release(generation)
        if timed_out:
            raise ClientError("timeout")
        raise AssertionError

    async def _refresh(
        self,
        store: SessionStore,
        snapshot: SessionCredentials,
        generation: int,
    ) -> None:
        with store._locked():
            if store._new_credentials(generation):
                return
            flight = store._flights.get(generation)
            if flight is None:
                if not store._current(snapshot, generation):
                    return
        if flight is None:
            flight = asyncio.create_task(
                self._rotate(
                    store,
                    snapshot,
                    generation,
                    asyncio.get_running_loop().time() + self._timeout,
                )
            )
            with store._locked():
                store._flights[generation] = flight
            flight.add_done_callback(functools.partial(store._settled, generation))
        failure = await asyncio.shield(flight)
        if failure is not None:
            raise failure.error()

    async def _rotate(
        self,
        store: SessionStore,
        snapshot: SessionCredentials,
        generation: int,
        deadline: float,
    ) -> _Failure | None:
        failure: _Failure | None = None
        credentials: SessionCredentials | None = None
        try:
            value = await self._attempt(
                "auth.refresh",
                _serialize({"refresh_token": snapshot.refresh_token}),
                None,
                credentials=True,
                deadline=deadline,
            )
            credentials = cast(SessionCredentials, value)
        except ClientError as error:
            failure = _Failure.from_error(error)
        with store._locked():
            if asyncio.get_running_loop().time() >= deadline:
                failure = _Failure(
                    "timeout",
                    failure.status if failure is not None else None,
                    outcome_unknown=failure.outcome_unknown
                    if failure is not None
                    else False,
                )
                credentials = None
            store._apply_refresh(snapshot, generation, credentials, failure)
        # Python 3.14's shield logs the inner exception after cancellation, so share the failure.
        return failure

    async def _attempt(
        self,
        operation: str,
        body: bytes,
        token: str | None,
        *,
        credentials: bool = False,
        deadline: float | None = None,
    ) -> object:
        now = asyncio.get_running_loop().time()
        deadline = min(
            deadline if deadline is not None else now + self._timeout,
            now + self._timeout,
        )
        observation = _observer.get()
        if observation is not None:
            deadline = min(deadline, observation.deadline)
        state = _RequestState()
        with _request_logs():
            import httpx

            headers = {"Content-Type": "application/json"}
            if token is not None:
                headers["Authorization"] = "Bearer " + token
            status: int | None = None
            failure: ClientError | None = None
            value: object = None
            try:
                async with asyncio.timeout_at(deadline):
                    _check_deadline(deadline)
                    client = self._http_client()
                    _check_deadline(deadline)
                    async with client.stream(
                        "POST",
                        self._origin + "/" + operation,
                        content=body,
                        headers=headers,
                        extensions={"trace": state.atrace},
                    ) as response:
                        status = response.status_code
                        if observation is not None:
                            observation.record_headers(
                                status, response.headers.values()
                            )
                        if 300 <= status < 400:
                            state.finish()
                            raise OperationError("redirect_not_allowed", status)
                        data = await _read_body(response)
                        if observation is not None:
                            observation.record_body(data)
                        state.finish()
                        _check_deadline(deadline)
                        value = _response(data, status)
                        if credentials:
                            try:
                                value = _read_credentials(value)
                            except ClientError:
                                failure = ClientError("invalid_response", status)
                        _check_deadline(deadline)
                    _check_deadline(deadline)
            except (TimeoutError, httpx.TimeoutException) as error:
                if observation is not None:
                    observation.details.extend((type(error).__name__, str(error)))
                failure = ClientError("timeout", status)
            except (httpx.HTTPError, OSError, RuntimeError) as error:
                if observation is not None:
                    observation.details.extend((type(error).__name__, str(error)))
                failure = ClientError("network_error", status)
            except ClientError as error:
                failure = error
            if asyncio.get_running_loop().time() >= deadline:
                failure = ClientError("timeout", status)
            if failure is not None:
                failure._outcome_unknown = state.outcome_unknown
                raise failure
            return value


class _Authenticated:
    def __init__(
        self,
        owner: AsyncHTTP,
        *,
        token: str | None = None,
        store: SessionStore | None = None,
    ) -> None:
        self._owner = owner
        self._token = token
        self._store = store

    async def invoke(
        self, operation: str, payload: bytes | Mapping[str, object]
    ) -> object:
        return await self._owner._invoke(operation, payload, self._token, self._store)


async def _read_body(response: "httpx.Response") -> bytes:
    body = _Body(
        response.headers.get("content-encoding", "identity"), response.status_code
    )
    async for chunk in response.aiter_raw():
        body.feed(chunk)
    return body.finish()
