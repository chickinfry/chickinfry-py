# chickinfry

Status: not yet supported (preview). APIs may change before support is announced.

Synchronous and async HTTP transport and in-memory native sessions for
Chickinfry clients. Requires Python 3.11 or newer. Browser, WebAssembly, and
Python Worker transports are not supported yet; use a regular Python process.

```sh
python -m pip install chickinfry
```

Use the synchronous transport in scripts and other blocking applications:

```python
from chickinfry import HTTP, ClientError, OperationError

with HTTP("https://api.example.com") as transport:
    try:
        result = transport.invoke("account.get_status", {})
        print(result)
    except OperationError as error:
        print(error)
    except ClientError as error:
        print(error)
```

Use the async transport with asyncio:

```python
import asyncio
from chickinfry import AsyncHTTP

async def main():
    async with AsyncHTTP("https://api.example.com") as transport:
        result = await transport.invoke("account.get_status", {})
        print(result)

asyncio.run(main())
```

`HTTP` can be shared by threads. `AsyncHTTP` stays on one asyncio event loop.
Generated synchronous clients consume `SyncClientTransport`; generated async
clients consume `ClientTransport`. Both return the same JSON values and use the
same errors and string-preserving readers in `chickinfry.wire`.

Use `transport.with_bearer(token)` for a separate authenticated transport, or
`transport.with_session(store)` with a `SessionStore(origin, credentials)`.
Neither changes the anonymous transport or its other copies. The original
transport owns the pool: `HTTP` closes it with `close()` or `with`, and
`AsyncHTTP` with `aclose()` or `async with`. Copies cannot close the pool.

`SessionCredentials` contains `access_token`, `refresh_token`, `expires_at`,
`refresh_expires_at`, `user_id`, and `session_id`. Tokens are hidden from its
representation. `store.credentials()` returns the current snapshot or `None`;
`replace(credentials)` installs a login and `clear(expected)` clears only that
exact snapshot. The first successful `with_session` permanently binds a store
to synchronous threads or one asyncio loop. Mixing both transports on that
store raises `ClientError("invalid_session")`, including after logout or close.
Use separate stores for the two modes. Do not concurrently copy the same
rotating credentials into separate stores.

Session transports share one refresh on `invalid_token`/401 and retry at most
once, using the original request bytes. Other failures are never resent.
A caller's interrupted or expired wait does not cancel a shared refresh.
Late refresh responses cannot overwrite a new login or restore a logout.
A refresh failure other than a well-formed 401 preserves credentials and
blocks further automatic refresh for that snapshot until `replace()` installs
new credentials. A well-formed 401 clears only the expected snapshot and does
not resend the original request. Invalid non-success error envelopes report
`invalid_response` with the received HTTP status.

Origins must be HTTPS or explicit IP loopback HTTP. Redirects, cookies,
environment proxies, and invalid tokens are rejected. Requests are limited to
4 MiB and responses to 1 MiB, including decompressed bytes. `timeout=30.0`
limits each complete network attempt, including pool waits, partial writes,
TLS, headers, and streamed bodies. A session call is bounded by three times
that value, with small platform scheduling and cleanup overhead.

Synchronous DNS resolution uses the operating system resolver, which cannot
be interrupted by this timeout. If DNS finishes after the deadline, no TCP
connection or request is started. The actual return time then depends on the
OS resolver; the 30-second attempt and 90-second call limits are not guaranteed
while DNS is blocked. A refresh producer remains tracked until it exits.

`OperationError` is a `ClientError` with the server's `code` and HTTP `status`.
Printing either error gives an English sentence with a next action; use the
`reason`, `code`, and `status` attributes for programmatic error handling.
Local failures expose a safe `reason` and an optional received `status`, without
request bodies, credentials, or raw network errors. Async cancellation and
synchronous `KeyboardInterrupt` propagate after cleanup. JSON retains strings,
including timestamps, without automatic date conversion.

## Contributing

Install development tools with `python -m pip install -r requirements-dev.txt`
and `python -m pip install --no-deps -e .`. Run `ruff check src tests`,
`ruff format --check src tests`, and `mypy --strict src tests`.

`pytest -q` runs both deadline tiers, including in CI. On an idle machine,
`pytest -q -m deadline_tight` checks the measured 0.05-second overshoot bound.
Do not increase that bound to accommodate competing heavy processes.
`pytest -q -m "not deadline_tight"` runs the remaining tests, including mechanism
checks with a phase timeout of at least 10 seconds and a 0.20-second remaining
deadline. Their wider scheduling margin is not evidence of the tight bound.
Deadline measurements are written under `.evidence/`.
