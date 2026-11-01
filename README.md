# chickinfry

Status: not yet supported (preview). APIs may change before support is announced.

Synchronous and async HTTP transport and in-memory native sessions for
Chickinfry clients. Requires Python 3.11 or newer. Browser, WebAssembly, and
Python Worker transports are not supported yet; use a regular Python process.

This preview is not published to PyPI. Install from a local source checkout:

```sh
python -m pip install .
```

Use the synchronous transport in scripts and other blocking applications:

```python
from chickinfry import HttpTransport, ClientError, OperationError

with HttpTransport("https://api.example.com") as transport:
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
from chickinfry import AsyncHttpTransport

async def main():
    async with AsyncHttpTransport("https://api.example.com") as transport:
        result = await transport.invoke("account.get_status", {})
        print(result)

asyncio.run(main())
```

`HttpTransport` can be shared by threads. `AsyncHttpTransport` stays on one asyncio event loop.
Generated synchronous clients consume `Transport`; generated async
clients consume `AsyncTransport`. Both return the same JSON values and use the
same errors and string-preserving readers in `chickinfry.wire`.

Use `transport.with_bearer(token)` for a separate authenticated transport, or
`transport.with_session(store)` with a `MemoryStore(origin, credentials)`.
Neither changes the anonymous transport or its other copies. The original
transport owns the pool: `HttpTransport` closes it with `close()` or `with`, and
`AsyncHttpTransport` with `aclose()` or `async with`. Copies cannot close the pool.

`SessionCredentials` contains `access_token`, `refresh_token`, `expires_at`,
`refresh_expires_at`, `user_id`, and `session_id`. Tokens are hidden from its
representation. `store.credentials()` returns the current snapshot or `None`;
`replace(credentials)` installs a login and `clear(expected)` clears only that
exact snapshot. The first successful `with_session` permanently binds a store
to synchronous threads or one asyncio loop. Mixing both transports on that
store raises `ClientError("failed_precondition")`, including after logout or close.
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
`ClientError("internal")` with the received HTTP status.

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

Generated clients use `create_client(transport)` and
`create_async_client(transport)` from the generated package, returning `Client`
and `AsyncClient` respectively. Both factories accept one transport argument.
The synchronous names are `Transport` and `HttpTransport`; async equivalents are
`AsyncTransport` and `AsyncHttpTransport`. No previous names are aliased.

Local `ClientError.code` values are `invalid_argument`, `failed_precondition`,
`resource_exhausted`, `deadline_exceeded`, `canceled`, `unavailable`, `data_loss`,
`unimplemented`, `internal`, `unknown`, and `unauthenticated`. Missing local
sessions use `unauthenticated`. Device storage access, capacity, corruption, and
unsupported versions use `failed_precondition`, `resource_exhausted`, `data_loss`,
and `unimplemented` respectively. Redirects and malformed responses use
`internal`. Local failures retain a received HTTP status or `None`; timeouts
and cancellation never invent one.

`OperationError` is a `ClientError` with the server's `code` and HTTP `status`.
Validated server descriptions are available as `response_message` (`None` when
absent or invalid; empty strings are preserved). For `invalid_input`, `fields`
is an immutable tuple of frozen `FieldError(path, code)` values. Invalid optional
details are discarded independently while code and HTTP status are preserved.
Session refresh failure snapshots preserve both details and the existing request
outcome uncertainty; they do not add automatic business retries.
Printing either error gives an English sentence with a next action; use the
`code` and `status` attributes for programmatic error handling.
Per-cause diagnostics retain their fixed, actionable wording; use common codes
for programmatic decisions. Local failures expose a common `code` and an optional
received `status`, without
request bodies, credentials, or raw network errors. Async cancellation and
synchronous `KeyboardInterrupt` propagate after cleanup. JSON retains strings,
including timestamps, without automatic date conversion.

## Server operation errors

Raise `chickinfry.server.OperationError(code, status, message=None, fields=())`
for an intentional public business failure. The server accepts every integer HTTP
status from 400 through 599, including 422 and custom codes at 501. Invalid codes,
booleans, non-integer statuses and out-of-range statuses return
`{"error":"operation_failed"}` with HTTP 500 and no details.

```python
from chickinfry.server import FieldError, OperationError

raise OperationError(
    "invalid_input", 422, "Quantity must be 10 or less.",
    (FieldError("quantity", "too_large"),),
)
```

The optional message must be valid Unicode, at most 1024 UTF-8 bytes, and contain
no control characters. Fields are sent only for `invalid_input`, with at most 32
valid path/code entries. Generated operations supply declared input paths through
`Operation.input_fields`. Hand-written operations default to no declared paths,
so field details are omitted unless that metadata is supplied. Invalid optional
details are discarded independently; valid code and status are preserved.
`str(error)` never includes the public message. Server errors and received SDK
errors have distinct type identities; received SDK errors are never trusted as
public server errors. The former server error name has no compatibility alias.

Generated SDKs use `SignupBinding` with the synchronous and asynchronous
transports for required email verification. Signup preserves the server's
`accepted` and `attempt` response instead of treating it as session credentials.
Verification and resend omit an unspecified target, or use this client's last
successful signup attempt when both targets are omitted. Providing both `email`
and `attempt` raises `ClientError` with code `invalid_argument` before HTTP.
The same error is returned without HTTP when no target or pending attempt exists.
Failed verification retains the attempt. Successful verification clears it for
the verified email when that email is known to the SDK; an unrelated explicit
attempt does not identify or clear this client's pending signup.
Successful sign-out clears this client's pending attempt. Successful sign-in
clears it only for the same signup email, compared after server-compatible
trimming and lowercase conversion. Other emails and failed calls retain it.
Older in-flight signup replies cannot restore a cleared email's binding, and
sign-out invalidates every older signup. State changes follow successful
decoding of the complete generated result.

This binding lasts for the client instance. Connecting generated sign-in,
signup, and reset to device storage is a separate follow-up; this does not
establish persistence through those public authentication paths.

## Server ORM

Generated repositories provide `upsert`, `increment`, and `increment_if` alongside
insert, lookup, update, and delete. Upserts require every primary key and update
only supplied mutable columns. Increments change integer columns atomically;
`increment_if` also checks a filter and applies a patch in the same statement.
An unmatched conditional write returns `None`; updating or incrementing a missing
row raises the public server `OperationError` with code `not_found` and status 404.
Column comparisons use `eq`, `ne`, `gt`, `gte`, `lt`, `lte`, and `is_in`.

## Contributing

Install development tools with `python -m pip install -r requirements-dev.txt`
and `python -m pip install --no-deps -e .`. Run `ruff check src tests`,
`ruff format --check src tests`, and `mypy --strict src tests`.

Runtime installation requirements are defined in `pyproject.toml`.

Install the development dependencies and package before running the full suite:

```sh
python -m pip install -r requirements-dev.txt
python -m pip install --no-deps -e .
python -m pytest
python -m ruff check src tests
python -m mypy --strict src tests
```

Server tests require asyncpg (included in the development dependencies), Docker,
and OpenSSL. They use
`postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873`
and pull the image only when that digest is missing locally. They create a
disposable database bound to loopback and remove its container and volumes.
The temporary test filesystem needs at least 4 GiB free before startup;
tests stop below 3 GiB. Client installations do not need the server extra.

The pinned asyncpg driver does not provide SCRAM-SHA-256-PLUS.
`channel_binding=require` is rejected before connecting; `prefer` permits
ordinary SCRAM when binding is unavailable, and `disable` does not use it.
Omitting that option does not require binding. These options do not change the
explicit TLS certificate and hostname checks selected by `sslmode`.

## Native session lifetime

Native bearer sessions use a 30-day idle timeout (2592000 seconds), with no
absolute lifetime cap by default (0). A successful refresh rolls the idle
expiry forward from its issue time; access tokens still expire after 900
seconds. Access checks do not renew the family. Expired or revoked credentials
are never revived, and refresh reuse revokes the entire family, including the
most recently issued credentials. Native responses never set or delete cookies.

The runtime accepts `idle_timeout_seconds` (3600–31536000 integer seconds) and
`absolute_lifetime_seconds` (0, or 3600–31536000 integer seconds) as keyword
arguments to `Auth`. The absolute cap may be shorter than idle and is measured
from the first login, including on access checks. Invalid values are rejected
before database use. Existing users may need to sign in again when a policy
is shortened or an absolute cap is enabled.

Existing sessions retain their stored refresh expiry until a successful
renewal converts them in the same transaction. Conversion preserves the
family's original creation time as first login and records the renewal time.
Before conversion, the current idle timeout is measured from the newest
successfully issued refresh credential's recorded creation time; rejected
requests and reuse do not move that baseline. The stored credential expiry
is checked separately, so a changed policy cannot revive an expired credential.

Cleanup selects ended families and preserves consumed credentials of live
families for reuse detection. For existing sessions without a recorded renewal
time, candidate selection can lag idle expiry by the access lifetime (900
seconds); families older than seven days are also selected. The final decision
is checked again under the family lock. Long-lived active families therefore
retain their credential history.

Non-default policy in generated Python applications is not supported yet:
the CLI's generator wiring and support gate remain separate work. Browser
cookie sessions are also unsupported. Cookie-only requests are anonymous in
this native-only runtime; the browser cookie/bearer mixing rule does not apply.

## Device persistence bridge (preview)

The runtime includes a private bridge for generated clients to supply trusted
app, canonical API origin, project/environment, user and signup-screen context.
Generated default wiring is integrated separately. Existing explicit
`MemoryStore` injection remains in memory and retains its loop/mode contract.

`HttpTransport` and `AsyncHttpTransport` accept `persist` alongside `timeout` and pass it to the
private context-bound bridge. Explicit `with_session` injection remains caller-owned.
The bridge accepts `persist=False` for explicit memory-only operation and
`persist={"dir": path}` for a state directory. Relative directories are resolved once against the
working directory when the transport is constructed; a later chdir does not
move the store. An empty string raises `failed_precondition`. Defaults
never fall back to the working directory. Omission selects Linux
`XDG_STATE_HOME` (or `HOME/.local/state`), macOS `HOME/Library/Application Support`,
or Windows `LOCALAPPDATA`. No SQLite, keychain or encryption dependency is used.
A directory is created lazily with 0700 permissions; an existing directory must
be owned by the user and not writable by others. Files use 0600; Windows
uses explicit current-user-only ACLs. Insecure existing permissions, symlinks and
foreign ownership are rejected. State files are not encrypted.

Each app/origin/project/environment has its own bundle and lock file. A process
lock serializes generation comparison and replacement. Writes flush a temporary
file, replace within the same directory, then flush the directory on POSIX.
Windows holds non-delete-sharing directory handles for every ancestor throughout
the transaction and rechecks ancestors after file open; unsafe/reparse paths or
unavailable pinning are refused. Windows skips directory flushing. Native Windows
execution and power-loss durability remain **UNVERIFIED**; fake API tests do not
establish real-host support.
No lock is held over a network call. Storage I/O and an OS lock wait can outlast
the transport network timeout. Separate sync and async stores use the same
file contract while keeping transport pools and event-loop state separate.
Request-scoped `with_bearer` credentials are never stored.

Session replacement, auth-selected attempt cleanup and generation changes are
one replacement. Refresh consumption-unknown state is durable before sending;
a crash or lost response never authorizes resending an old refresh. Auth passes
expired/confirmed screen IDs to `_save_attempt(..., remove_screens=...)`; the
adapter does not decide expiry with its own clock. Version 1 permits three
pending attempts and an 8 KiB serialized UTF-8 bundle, without silent eviction.
Original ISO expiry strings are preserved and range-checked.

A verified server login uses `_accept_login`. If only the following write fails,
the login succeeds and the new session stays in memory for this run; persistence
is not promised. Location-creation failures remain configuration errors.
Restore, pre-refresh and deletion failures are not converted to memory success.
Corruption and unknown/newer versions preserve the original and block access.
The existing `ClientError` channel retains `failed_precondition`,
`data_loss`, `resource_exhausted`, and
`unimplemented`, with no fabricated HTTP status.

Core/auth must connect generated defaults, explicit `auth.refresh` pre-send
claims and conditional transitions. No cache, offline queue or automatic reset
is implemented. Future cache/queue work must use the same scope and generation
boundary, and must not store auth requests as queued operations.

After a successful server refresh, local read, lock or write failure during
commit keeps
them in this run's memory and the original operation uses its normal single
retry. The durable in-flight marker remains, so a restart does not resubmit the
old refresh. Recording that marker must still succeed before any refresh send.

The private auth bridge can read `_snapshot()` and use separate bundle and auth
generations in a conditional transition. Attempt writes do not advance the auth
generation; session installs/changes, logout and scoped deletion do. Exact
attempt-only cleanup preserves the active session and refresh marker. Bounded
local CAS retries, attempt-reference checks and same-email cleanup selection are
owned by generated auth integration; the adapter never resends the server RPC.


The device bridge records an account-transition-unknown marker before an auth
bridge sends a login, confirmation, code login or OAuth completion that can
replace an existing session. It uses the existing conditional transition;
first login has no previous account to mark. A marker write failure prevents
the send. A definite auth failure removes the marker and preserves the previous
account; verified success installs the new session. If only the final write
fails, the new session remains usable in memory for this run and the marker
remains durable. On restart, the previous account is not restored, even if its
best-effort local cleanup fails. Generated auth-method wiring is follow-up work.

POSIX operations stay relative to a validated directory descriptor, including
locks, temporary writes, replacement and directory flush. Unsafe writable
ancestors and macOS ACL allow entries are rejected before credentials are
written. The shared session coordinator retries refresh commits locally at most
three times while the authentication generation and expected session match;
it never resends the refresh RPC. Run-local credentials recheck the persisted
authentication generation before use, including another instance's logout.


An E1 memory session retains the authentication generation last read from disk
when it was accepted. An I/O failure during the pre-call generation check keeps
that memory session usable. A confirmed generation advance discards it and ends
that call without adopting another account; later calls use the ordinary store
read. The existing no-session result is mapped by the generated auth bridge.

A persistent or memory-only device call retains its starting authentication generation through refresh coordination
and the final retry. A confirmed account change ends that call with
`invalid_session`, without sending its operation under the new account. The next
independent call can use the newly stored account. This also fences the fast path
that reuses credentials refreshed by another caller. Post-success I/O fallback
never overrides a confirmed account boundary, corrupt data or unsupported format.
Rereading an attempt-only change preserves the expected session for a pending
deletion only when both its authentication generation and credentials still match.
A new authentication generation remains protected even if its credentials match.

File-backed and `persist=False` device sessions use the same bundle transitions,
refresh commits and account-transition markers; only bundle I/O changes.
Saving or removing another screen's signup attempt preserves a successful refresh,
a confirmed 401 deletion and a consumption-unknown block. Later attempt changes
cannot authorize another send of a consumed or uncertain refresh credential.
