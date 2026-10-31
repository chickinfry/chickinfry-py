import asyncio
import builtins
import json
import os
import stat
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Iterator, cast

import pytest

from chickinfry import AsyncHttpTransport, ClientError, HttpTransport
from chickinfry import _device as device
from chickinfry._device import _device_store, _DeviceStore, _Record
from chickinfry.errors import _storage_error
from chickinfry.session import MemoryStore, _SessionStore

from .peer import Peer, Received, json_bytes, respond
from .test_session import credentials


@pytest.fixture(autouse=True)
def isolated_device(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for name in ("HOME", "XDG_STATE_HOME", "LOCALAPPDATA"):
        monkeypatch.setenv(name, str(tmp_path / name))


def store_at(
    root: Path, *, origin: str = "https://example.com", **kwargs: Any
) -> _DeviceStore:
    return _DeviceStore(
        origin, app="app", project="project", environment="test", path=root, **kwargs
    )


def bundle(store: _DeviceStore) -> Path:
    assert store._path is not None
    return store._path


def attempt() -> dict[str, object]:
    return {
        "attempt": "opaque-attempt",
        "email": "person@example.invalid",
        "started_at": (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
        "sequence": 1,
    }


def child(root: Path, script: str, *args: str) -> SimpleNamespace:
    prefix = """
from pathlib import Path
import os, sys
from chickinfry import _device as d
from tests.test_device_store import store_at, attempt, bundle
from tests.test_session import credentials
s=store_at(Path(sys.argv[1]))
"""
    result = subprocess.run(
        [sys.executable, "-c", prefix + script, str(root), *args],
        env={
            name: os.environ[name]
            for name in (
                "HOME",
                "PATH",
                "TMPDIR",
                "LANG",
                "LC_ALL",
                "XDG_STATE_HOME",
                "LOCALAPPDATA",
                "PYTHONPATH",
            )
            if name in os.environ
        },
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    return SimpleNamespace(returncode=result.returncode)


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_real_interpreter_restart(mode: str, tmp_path: Path) -> None:
    root = tmp_path / "state"
    assert (
        child(
            root,
            "s.replace(credentials())\nassert s._save_attempt('screen-a',attempt(),expected_generation=s._generation)\n",
        ).returncode
        == 0
    )
    assert (
        child(
            root,
            """
import asyncio
from chickinfry import HttpTransport, AsyncHttpTransport
async def run():
    assert s.credentials() is not None
    assert s._attempt('screen-a') is not None and s._attempt('screen-b') is None
    owner=AsyncHttpTransport(s._origin) if sys.argv[2]=='async' else HttpTransport(s._origin)
    owner.with_session(s)
    if sys.argv[2]=='async': await owner.aclose()
    else: owner.close()
asyncio.run(run())
""",
            mode,
        ).returncode
        == 0
    )
    assert (
        child(
            root, "old=s.credentials()\nassert old is not None\ns.clear(old)\n"
        ).returncode
        == 0
    )
    assert (
        child(
            root,
            "assert s.credentials() is None\nassert s._attempt('screen-a') is None\n",
        ).returncode
        == 0
    )


def test_explicit_off_and_directory_without_optional_modules(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    original = builtins.__import__

    def reject(name: str, *args: Any, **kwargs: Any) -> Any:
        if name in {"sqlite3", "keyring", "cryptography"}:
            raise AssertionError("Unexpected dependency")
        return original(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", reject)
    off = _device_store(
        "https://example.com",
        app="app",
        project="project",
        environment="test",
        persist=False,
    )
    off.replace(credentials())
    assert off._save_attempt("screen", attempt(), expected_generation=off._generation)
    assert off._attempt("screen") is not None and list(tmp_path.iterdir()) == []
    root = tmp_path / "custom"
    explicit = _device_store(
        "https://example.com",
        app="app",
        project="project",
        environment="test",
        persist={"dir": root},
    )
    assert not root.exists()
    assert explicit.credentials() is None
    assert root.is_dir() and root.stat().st_mode & 0o777 == 0o700
    assert list(root.glob("*.json")) == []


@pytest.mark.parametrize(
    "damage",
    [
        "permission",
        "directory",
        "symlink",
        "hardlink",
        "corrupt",
        "newer",
        "unknown",
        "scope",
        "fields",
        "time",
        "generation",
        "duplicate",
        "unknown-without-session",
    ],
)
def test_unsafe_or_corrupt_original_is_preserved(damage: str, tmp_path: Path) -> None:
    root = tmp_path / "state"
    s = store_at(root)
    s.replace(credentials())
    path = bundle(s)
    reason = "data_loss"
    if damage == "permission":
        path.chmod(0o644)
        reason = "failed_precondition"
    elif damage == "directory":
        root.chmod(0o777)
        reason = "failed_precondition"
    elif damage == "symlink":
        original = path.with_suffix(".original")
        path.rename(original)
        path.symlink_to(original)
        reason = "failed_precondition"
    elif damage == "hardlink":
        os.link(path, path.with_suffix(".linked"))
        reason = "failed_precondition"
    elif damage == "corrupt":
        path.write_bytes(b"invalid JSON")
    elif damage == "duplicate":
        path.write_bytes(b'{"version":99,' + path.read_bytes()[1:])
    else:
        state = json.loads(path.read_bytes())
        if damage in {"newer", "unknown"}:
            state["version"] = 99 if damage == "newer" else 0
            reason = "unimplemented"
        elif damage == "scope":
            state["scope"] = "another owner"
        elif damage == "fields":
            state.pop("attempts")
        elif damage == "time":
            state["session"]["expires_at"] = "invalid time"
        elif damage == "unknown-without-session":
            state["session"] = None
            state["refresh_unknown"] = True
        else:
            state["generation"] = device._MAX_INT + 1
        path.write_text(json.dumps(state))
    before = path.read_bytes()
    with pytest.raises(ClientError, check=lambda e: e.code == reason):
        store_at(root).credentials()
    assert bool(path.read_bytes() == before)


def test_namespace_owner_and_stale_generation(tmp_path: Path) -> None:
    root = tmp_path / "state"
    s = store_at(root)
    old = credentials()
    s.replace(old)
    assert s._save_attempt("a", attempt(), expected_generation=s._generation)
    assert s._save_attempt(
        "b", {**attempt(), "attempt": "other"}, expected_generation=s._generation
    )
    for change in (
        {"app": "other"},
        {"project": "other"},
        {"environment": "other"},
        {"origin": "https://other.example"},
    ):
        options: dict[str, Any] = dict(
            origin="https://example.com",
            app="app",
            project="project",
            environment="test",
            path=root,
        )
        options.update(change)
        other = _DeviceStore(**options)
        assert other.credentials() is None and other._attempt("a") is None
    with pytest.raises(ClientError):
        s._transition(old, user_id="another-user", expected_generation=s._generation)
    generation = s._generation
    updated = replace(old, user_id="new-user")
    assert s._transition(
        updated, user_id=updated.user_id, expected_generation=generation, screens=("a",)
    )
    assert s._attempt("a") is None and s._attempt("b") is not None
    assert not s._transition(
        old, user_id=old.user_id, expected_generation=generation, screens=None
    )
    assert bool(s.credentials() == updated)


def test_transition_failure_preserves_session_attempt_and_generation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    s = store_at(root)
    old = credentials()
    s.replace(old)
    assert s._save_attempt("screen", attempt(), expected_generation=s._generation)
    generation = s._generation
    original = device._atomic_write

    def reject(path: Path, raw: bytes, **kwargs: Any) -> None:
        state = json.loads(raw)
        if (
            state["session"]["session_id"] == "next"
            and "screen" not in state["attempts"]
        ):
            raise PermissionError
        original(path, raw, **kwargs)

    monkeypatch.setattr(device, "_atomic_write", reject)
    updated = replace(credentials(), session_id="next")
    with pytest.raises(ClientError):
        s._transition(
            updated,
            user_id=updated.user_id,
            expected_generation=generation,
            screens=("screen",),
        )
    restored = store_at(root)
    assert bool(restored.credentials() == old)
    assert (
        restored._generation == generation and restored._attempt("screen") is not None
    )


@pytest.mark.parametrize("phase", ["before-rename", "after-rename"])
def test_atomic_write_process_exit_is_whole_state(phase: str, tmp_path: Path) -> None:
    root = tmp_path / "state"
    assert (
        child(
            root,
            "s.replace(credentials())\nassert s._save_attempt('screen',attempt(),expected_generation=s._generation)\n",
        ).returncode
        == 0
    )
    script = """
import stat
from dataclasses import asdict, replace
s.credentials()
if sys.argv[2]=='before-rename':
    d.os.replace=lambda *args,**kwargs:os._exit(0)
else:
    original=d.os.fsync
    def sync(fd):
        if stat.S_ISDIR(os.fstat(fd).st_mode):os._exit(0)
        original(fd)
    d.os.fsync=sync
updated=replace(credentials(),session_id='next')
s._transition(updated,user_id=updated.user_id,expected_generation=s._generation,screens=('screen',))
"""
    assert child(root, script, phase).returncode == 0
    assert (
        child(
            root,
            """
current=s.credentials()
assert current is not None
assert (current.session_id=='next')==(sys.argv[2]=='after-rename')
assert (s._attempt('screen') is None)==(sys.argv[2]=='after-rename')
""",
            phase,
        ).returncode
        == 0
    )


def test_lock_process_exit_and_concurrent_refresh_claim(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store_at(root).replace(credentials())
    assert child(root, "with s._transaction():os._exit(0)\n").returncode == 0
    assert store_at(root).credentials() is not None
    script = """
try:
    old=s.credentials();s._begin_refresh(old,s._generation)
except Exception:sys.exit(3)
"""
    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(lambda _: child(root, script).returncode, range(2)))
    assert sorted(results) == [0, 3]
    assert (
        child(
            root, "s.credentials()\nassert s._blocked_generation==s._generation\n"
        ).returncode
        == 0
    )


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_lost_refresh_response_does_not_resend_after_restart(
    mode: str, tmp_path: Path
) -> None:
    refreshes = 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            writer.close()
        else:
            await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as peer:
        root = tmp_path / "state"
        script = f"""
import asyncio
from chickinfry import HttpTransport,AsyncHttpTransport,ClientError
s=store_at(Path(sys.argv[1]),origin={peer.origin!r})
if s.credentials() is None:s.replace(credentials())
async def run():
    if sys.argv[2]=='async':
        async with AsyncHttpTransport(s._origin) as t:
            try:await t.with_session(s).invoke('probe.echo',{{}})
            except ClientError:pass
    else:
        with HttpTransport(s._origin) as t:
            try:t.with_session(s).invoke('probe.echo',{{}})
            except ClientError:pass
asyncio.run(run())
os._exit(0)
"""
        assert (await asyncio.to_thread(child, root, script, mode)).returncode == 0
        assert (await asyncio.to_thread(child, root, script, mode)).returncode == 0
    assert refreshes == 1


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_refresh_record_failure_preserves_reason_and_prevents_send(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        calls.append(request.path)
        await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as peer:
        s = store_at(tmp_path / "state", origin=peer.origin)
        s.replace(credentials())

        def fail(*args: object) -> None:
            raise OSError(28, "No space")

        monkeypatch.setattr(s, "_write", fail)
        if mode == "async":
            async with AsyncHttpTransport(peer.origin) as transport:
                with pytest.raises(
                    ClientError, check=lambda e: e.code == "resource_exhausted"
                ):
                    await transport.with_session(s).invoke("probe.echo", {})
        else:

            def run() -> None:
                with HttpTransport(peer.origin) as transport:
                    with pytest.raises(
                        ClientError, check=lambda e: e.code == "resource_exhausted"
                    ):
                        transport.with_session(s).invoke("probe.echo", {})

            await asyncio.to_thread(run)
    assert calls == ["/probe.echo"]


def test_same_files_across_threads_and_event_loops(tmp_path: Path) -> None:
    root = tmp_path / "state"
    store_at(root).replace(credentials())

    def run(mode: str) -> None:
        async def one() -> None:
            s = store_at(root)
            if mode == "sync":
                with HttpTransport(s._origin) as transport:
                    transport.with_session(s)
            else:
                async with AsyncHttpTransport(s._origin) as transport:
                    transport.with_session(s)
            assert s.credentials() is not None

        asyncio.run(one())

    with ThreadPoolExecutor(2) as pool:
        list(pool.map(run, ["sync", "async"]))
    run("async")


def test_owner_only_files_and_write_order(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    s = store_at(root)
    events: list[str] = []
    sync, rename = os.fsync, os.replace

    def observe_sync(fd: int) -> None:
        events.append(
            "directory-sync" if stat.S_ISDIR(os.fstat(fd).st_mode) else "file-sync"
        )
        sync(fd)

    def observe_rename(source: Any, target: Any, **kwargs: Any) -> None:
        events.append("rename")
        rename(source, target, **kwargs)

    monkeypatch.setattr(os, "fsync", observe_sync)
    monkeypatch.setattr(os, "replace", observe_rename)
    s.replace(credentials())
    assert events == ["file-sync", "rename", "directory-sync"]
    assert root.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in root.iterdir())


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_post_login_write_failure_is_success_only_for_this_run(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    new = credentials()
    received: list[bool] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        received.append(
            bool(request.headers.get("authorization") == "Bearer " + new.access_token)
        )
        await respond(writer, json_bytes({}))

    async with Peer(handler) as peer:
        root = tmp_path / "state"
        s = store_at(root, origin=peer.origin)
        assert s.credentials() is None

        def fail(*args: object) -> None:
            raise PermissionError

        monkeypatch.setattr(s, "_write", fail)
        assert s._accept_login(new, user_id=new.user_id, expected_generation=0)
        assert bool(s.credentials() == new)
        if mode == "async":
            async with AsyncHttpTransport(peer.origin) as transport:
                await transport.with_session(s).invoke("probe.echo", {})
        else:

            def run() -> None:
                with HttpTransport(peer.origin) as transport:
                    transport.with_session(s).invoke("probe.echo", {})

            await asyncio.to_thread(run)
        assert received == [True]
        assert (
            child(
                root,
                f"s=store_at(Path(sys.argv[1]),origin={peer.origin!r})\nassert s.credentials() is None\n",
            ).returncode
            == 0
        )
        snapshot = s.credentials()
        assert snapshot is not None
        with pytest.raises(ClientError):
            s.clear(snapshot)
        with pytest.raises(ClientError):
            s.credentials()


def test_location_creation_failure_is_not_memory_success(tmp_path: Path) -> None:
    root = tmp_path / "file"
    root.write_text("not a directory")
    s = store_at(root)
    new = credentials()
    with pytest.raises(ClientError, check=lambda e: e.code == "failed_precondition"):
        s._accept_login(new, user_id=new.user_id, expected_generation=0)


@pytest.mark.parametrize("persistent", [False, True])
def test_attempt_cap_prunes_only_auth_selected_screens(
    persistent: bool, tmp_path: Path
) -> None:
    s = _device_store(
        "https://example.com",
        app="app",
        project="project",
        environment="test",
        persist={"dir": tmp_path / "state"} if persistent else False,
    )
    for index in range(3):
        assert s._save_attempt(str(index), attempt(), expected_generation=s._generation)
    before = s._generation
    with pytest.raises(ClientError, check=lambda e: e.code == "resource_exhausted"):
        s._save_attempt("fourth", attempt(), expected_generation=before)
    assert s._generation == before and all(
        s._attempt(str(index)) is not None for index in range(3)
    )
    assert s._save_attempt(
        "fourth", attempt(), expected_generation=before, remove_screens=("0",)
    )
    assert s._attempt("0") is None and s._attempt("fourth") is not None


def test_serialized_bundle_exact_byte_boundary(tmp_path: Path) -> None:
    root = tmp_path / "state"
    old = credentials()
    base = store_at(root)
    base.replace(old)
    with base._transaction() as record:
        raw = json.dumps(base._read(record), ensure_ascii=True, separators=(",", ":"))
    padding = device._MAX_BYTES - len(raw.encode())
    assert padding > 0
    at_limit = _DeviceStore(
        "https://example.com",
        app="app" + "x" * padding,
        project="project",
        environment="test",
        path=root,
    )
    at_limit.replace(old)
    assert bool(at_limit.credentials() == old)
    over = _DeviceStore(
        "https://example.com",
        app="app" + "x" * (padding + 1),
        project="project",
        environment="test",
        path=root,
    )
    with pytest.raises(ClientError, check=lambda e: e.code == "resource_exhausted"):
        over.replace(old)
    assert not bundle(over).exists()


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_request_bearer_is_never_persisted(mode: str, tmp_path: Path) -> None:
    token = credentials().access_token
    received: list[bool] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        received.append(bool(request.headers.get("authorization") == "Bearer " + token))
        await respond(writer, json_bytes({}))

    async with Peer(handler) as peer:
        if mode == "async":
            async with AsyncHttpTransport(peer.origin) as transport:
                await transport.with_bearer(token).invoke("probe.echo", {})
                await transport.invoke("probe.echo", {})
        else:

            def run() -> None:
                with HttpTransport(peer.origin) as transport:
                    transport.with_bearer(token).invoke("probe.echo", {})
                    transport.invoke("probe.echo", {})

            await asyncio.to_thread(run)
    assert received == [True, False] and list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_transport_accepts_structural_store(mode: str) -> None:
    original = MemoryStore("https://example.com", credentials())
    names = (
        "_condition",
        "_blocked_generation",
        "_flights",
        "_sync_flights",
        "_locked",
        "_attach",
        "credentials",
        "replace",
        "clear",
        "_register",
        "_current",
        "_new_credentials",
        "_begin_refresh",
        "_apply_refresh",
        "_release",
        "_reclaim",
        "_settled",
    )
    structural = SimpleNamespace(**{name: getattr(original, name) for name in names})
    assert not isinstance(structural, MemoryStore)
    if mode == "async":
        async with AsyncHttpTransport(original._origin) as transport:
            transport.with_session(cast(_SessionStore, structural))
    else:
        with HttpTransport(original._origin) as transport:
            transport.with_session(cast(_SessionStore, structural))


@pytest.mark.parametrize(
    "host,part",
    [
        ("linux", "XDG_STATE_HOME"),
        ("darwin", "Application Support"),
        ("win32", "LOCALAPPDATA"),
    ],
)
def test_default_os_locations(
    monkeypatch: pytest.MonkeyPatch, host: str, part: str
) -> None:
    monkeypatch.setattr(device, "_HOST", host)
    assert part in str(device._location("app"))


def test_xdg_does_not_require_home(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(device, "_HOST", "linux")
    monkeypatch.delenv("HOME")
    matches = str(device._location("app")).startswith(os.environ["XDG_STATE_HOME"])
    assert matches


@pytest.mark.parametrize("swap", [False, True])
def test_windows_acl_boundary_with_fake(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, swap: bool
) -> None:
    from chickinfry import _device_windows as windows

    checked: list[Path] = []

    def mkdir(path: Path) -> None:
        path.mkdir(mode=0o700)

    def create(path: Path) -> None:
        os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600))

    def check(path: Path) -> None:
        checked.append(path)
        expected = 0o700 if path.is_dir() else 0o600
        if path.stat().st_mode & 0o777 != expected:
            raise ClientError("failed_precondition")

    @contextmanager
    def lock(descriptor: int) -> Iterator[None]:
        yield

    monkeypatch.setattr(device, "_HOST", "win32")
    monkeypatch.setattr(windows, "_pin_directory", lambda path: lock(0), raising=False)
    monkeypatch.setattr(windows, "_mkdir", mkdir)
    monkeypatch.setattr(windows, "_create", create)
    monkeypatch.setattr(windows, "_check_acl", check)
    monkeypatch.setattr(device, "_process_lock", lock)
    root = tmp_path / "state"
    s = store_at(root)
    old = credentials()
    if swap:
        target = tmp_path / "redirect"
        target.mkdir(mode=0o700)
        original_open = device._open_private
        swapped = False

        def open_after_swap(path: Path, **kwargs: Any) -> int:
            nonlocal swapped
            if path.suffix == ".lock" and not swapped:
                swapped = True
                root.rename(tmp_path / "moved")
                root.symlink_to(target, target_is_directory=True)
            return original_open(path, **kwargs)

        monkeypatch.setattr(device, "_open_private", open_after_swap)
        with pytest.raises(
            ClientError, check=lambda e: e.code == "failed_precondition"
        ):
            s.replace(old)
        assert swapped
        assert not list(target.glob("*.json"))
        return
    s.replace(old)
    assert bool(s.credentials() == old)
    assert root in checked and bundle(s) in checked
    assert any(path.suffix == ".lock" for path in checked)
    assert any(path.suffix == ".tmp" for path in checked)
    os.link(bundle(s), root / "extra-link")
    with pytest.raises(ClientError):
        s.credentials()
    bundle(s).chmod(0o644)
    with pytest.raises(ClientError):
        s.credentials()


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_constructor_persist_settings_reach_private_store(
    mode: str, tmp_path: Path
) -> None:
    root = tmp_path / "selected"
    owner = (
        HttpTransport("https://example.com", persist={"dir": root})
        if mode == "sync"
        else AsyncHttpTransport("https://example.com", persist={"dir": root})
    )
    assert not root.exists()
    s = owner._device_store(app="app", project="project", environment="test")
    s.replace(credentials())
    assert root.is_dir() and list(root.glob("*.json"))
    off = (
        HttpTransport("https://example.com", persist=False)
        if mode == "sync"
        else AsyncHttpTransport("https://example.com", persist=False)
    )
    memory = off._device_store(app="app", project="project", environment="test")
    before = list(tmp_path.rglob("*"))
    memory.replace(credentials())
    assert memory.credentials() is not None
    assert list(tmp_path.rglob("*")) == before
    for transport in (owner, off):
        if isinstance(transport, HttpTransport):
            transport.close()
        else:
            await transport.aclose()


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_constructor_rejects_old_path_key(mode: str, tmp_path: Path) -> None:
    constructor = HttpTransport if mode == "sync" else AsyncHttpTransport
    with pytest.raises(
        ClientError, check=lambda error: error.code == "invalid_argument"
    ):
        constructor("https://example.com", persist={"path": tmp_path})


@pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX directory modes are validated on Unix hosts."
)
def test_existing_owned_directory_without_other_writers_is_preserved(
    tmp_path: Path,
) -> None:
    root = tmp_path / "existing"
    root.mkdir(mode=0o755)
    root.chmod(0o755)
    original = stat.S_IMODE(root.stat().st_mode)
    s = store_at(root)
    s.replace(credentials())
    assert stat.S_IMODE(root.stat().st_mode) == original
    assert bool(s.credentials() is not None)


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_refresh_commit_failure_keeps_memory_and_restart_marker(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, rotated = credentials(), credentials()
    refreshes = 0
    calls: list[str] = []

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            await respond(writer, json_bytes(asdict(rotated)))
        elif request.headers.get("authorization") == "Bearer " + rotated.access_token:
            calls.append("new")
            await respond(writer, json_bytes({"ok": True}))
        else:
            calls.append("old")
            await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as peer:
        root = tmp_path / "state"
        s = store_at(root, origin=peer.origin)
        s.replace(old)
        original_write = s._write

        def write(record: _Record, state: dict[str, object]) -> None:
            if refreshes and not state["refresh_unknown"]:
                raise PermissionError
            original_write(record, state)

        monkeypatch.setattr(s, "_write", write)
        if mode == "async":
            async with AsyncHttpTransport(peer.origin) as transport:
                assert await transport.with_session(s).invoke("probe.echo", {}) == {
                    "ok": True
                }
        else:

            def run() -> None:
                with HttpTransport(peer.origin) as transport:
                    assert transport.with_session(s).invoke("probe.echo", {}) == {
                        "ok": True
                    }

            await asyncio.to_thread(run)
        assert bool(s.credentials() == rotated)
        assert refreshes == 1 and calls == ["old", "new"]
        restored = store_at(root, origin=peer.origin)
        assert bool(restored.credentials() == old)
        assert restored._blocked_generation == restored._generation
        script = f"""
import asyncio
from chickinfry import HttpTransport, AsyncHttpTransport, OperationError
s=store_at(Path(sys.argv[1]),origin={peer.origin!r})
async def run():
    if sys.argv[2]=="async":
        async with AsyncHttpTransport(s._origin) as t:
            try:await t.with_session(s).invoke("probe.echo",{{}})
            except OperationError:pass
            else:raise AssertionError
    else:
        with HttpTransport(s._origin) as t:
            try:t.with_session(s).invoke("probe.echo",{{}})
            except OperationError:pass
            else:raise AssertionError
asyncio.run(run())
"""
        assert (await asyncio.to_thread(child, root, script, mode)).returncode == 0
        assert refreshes == 1 and calls == ["old", "new", "old"]


@pytest.mark.parametrize("persistent", [False, True])
def test_auth_generation_fences_logout_but_not_another_attempt(
    persistent: bool, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    store = _device_store(
        "https://example.com",
        app="app",
        project="project",
        environment="test",
        persist={"dir": root} if persistent else False,
    )
    assert store._save_attempt("a", attempt(), expected_generation=0)
    assert store._save_attempt(
        "a2", {**attempt(), "attempt": "second"}, expected_generation=store._generation
    )
    captured = store._snapshot()
    writer = store_at(root) if persistent else store
    assert writer._save_attempt(
        "b",
        {**attempt(), "attempt": "other", "email": "other@example.invalid"},
        expected_generation=cast(int, captured["generation"]),
    )
    authenticated = credentials()
    assert not store._transition(
        authenticated,
        user_id=authenticated.user_id,
        expected_generation=cast(int, captured["generation"]),
        expected_auth_generation=cast(int, captured["auth_generation"]),
        screens=("a", "a2"),
    )
    latest = store._snapshot()
    assert latest["auth_generation"] == captured["auth_generation"]
    assert store._transition(
        authenticated,
        user_id=authenticated.user_id,
        expected_generation=cast(int, latest["generation"]),
        expected_auth_generation=cast(int, captured["auth_generation"]),
        screens=("a", "a2"),
    )
    installed = store._snapshot()
    assert (
        store._attempt("a") is None
        and store._attempt("a2") is None
        and store._attempt("b") is not None
    )
    if persistent:
        assert (
            child(
                root, 'state=s._snapshot()\nassert state["auth_generation"] == 1\n'
            ).returncode
            == 0
        )
    reauthenticated = replace(authenticated, session_id="new-session")
    store.replace(reauthenticated)
    reauth = store._snapshot()
    assert cast(int, reauth["auth_generation"]) > cast(
        int, installed["auth_generation"]
    )
    current = store.credentials()
    assert current is not None
    store._begin_refresh(current, cast(int, reauth["generation"]))
    rotated_same_session = replace(
        credentials(), session_id=current.session_id, user_id=current.user_id
    )
    store._apply_refresh(
        current, cast(int, reauth["generation"]), rotated_same_session, None
    )
    refreshed = store._snapshot()
    assert refreshed["auth_generation"] == reauth["auth_generation"]
    current = store.credentials()
    assert current is not None
    store._begin_refresh(current, cast(int, refreshed["generation"]))
    claimed = store._snapshot()
    assert store._remove_attempts(
        ("b",),
        expected_generation=cast(int, claimed["generation"]),
        expected_auth_generation=cast(int, claimed["auth_generation"]),
    )
    pruned = store._snapshot()
    assert pruned["auth_generation"] == claimed["auth_generation"]
    assert pruned["refresh_unknown"] == claimed["refresh_unknown"]
    assert bool(pruned["session"] == claimed["session"])
    assert store._attempt("b") is None
    switched = replace(
        authenticated, user_id="another-user", session_id="another-session"
    )
    assert store._save_attempt("same", attempt(), expected_generation=store._generation)
    assert store._save_attempt(
        "other",
        {**attempt(), "email": "other@example.invalid"},
        expected_generation=store._generation,
    )
    assert store._transition(
        switched,
        user_id=switched.user_id,
        expected_generation=store._generation,
        expected_auth_generation=store._auth_generation,
        screens=("same",),
    )
    assert store._attempt("same") is None and store._attempt("other") is not None
    switched_state = store._snapshot()
    assert cast(int, switched_state["auth_generation"]) > cast(
        int, installed["auth_generation"]
    )
    assert store._transition(
        switched,
        user_id=switched.user_id,
        expected_generation=cast(int, switched_state["generation"]),
        screens=None,
    )
    scoped = store._snapshot()
    assert cast(int, scoped["auth_generation"]) > cast(
        int, switched_state["auth_generation"]
    )
    current = store.credentials()
    assert current is not None
    store.clear(current)
    logged_out = store._snapshot()
    assert cast(int, logged_out["auth_generation"]) > cast(
        int, installed["auth_generation"]
    )
    assert not store._transition(
        authenticated,
        user_id=authenticated.user_id,
        expected_generation=cast(int, logged_out["generation"]),
        expected_auth_generation=cast(int, installed["auth_generation"]),
        screens=(),
    )
    assert store.credentials() is None


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_relative_directory_is_bound_at_construction(
    mode: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    initial, later = tmp_path / "initial", tmp_path / "later"
    initial.mkdir()
    later.mkdir()
    monkeypatch.chdir(initial)
    owner = (
        HttpTransport("https://example.com", persist={"dir": "state"})
        if mode == "sync"
        else AsyncHttpTransport("https://example.com", persist={"dir": "state"})
    )
    assert not (initial / "state").exists()
    monkeypatch.chdir(later)
    store = owner._device_store(app="app", project="project", environment="test")
    store.replace(credentials())
    assert isinstance(store, _DeviceStore) and store._directory == initial / "state"
    assert not (later / "state").exists()
    if isinstance(owner, HttpTransport):
        owner.close()
    else:
        await owner.aclose()


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_empty_directory_is_rejected(mode: str) -> None:
    constructor = HttpTransport if mode == "sync" else AsyncHttpTransport
    with pytest.raises(
        ClientError, check=lambda error: error.code == "failed_precondition"
    ):
        constructor("https://example.com", persist={"dir": ""})


def test_explicit_replace_recovers_a_run_local_overlay(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    store = store_at(tmp_path / "state")
    assert store.credentials() is None
    original_write = store._write

    def fail(*args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(store, "_write", fail)
    first = credentials()
    assert store._accept_login(first, user_id=first.user_id, expected_generation=0)
    old = store.credentials()
    monkeypatch.setattr(store, "_write", original_write)
    replacement = replace(
        credentials(), user_id="another-user", session_id="another-session"
    )
    store.replace(replacement)
    assert bool(store.credentials() == replacement)
    assert not store._volatile
    assert old is not None
    store.clear(old)
    assert bool(store.credentials() == replacement)


@pytest.mark.skipif(sys.platform != "darwin", reason="Native macOS ACL check.")
@pytest.mark.parametrize("inherited", [False, True])
def test_read_acl_is_refused_before_session_use(
    inherited: bool, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    root.mkdir(mode=0o755)
    store = store_at(root)
    if inherited:
        target, entry = root, "everyone allow read,file_inherit,directory_inherit"
    else:
        store.replace(credentials())
        target, entry = bundle(store), "everyone allow read"
    result = subprocess.run(
        ["/bin/chmod", "+a", entry, str(target)],
        env={"PATH": "/usr/bin:/bin"},
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    with pytest.raises(ClientError, check=lambda e: e.code == "failed_precondition"):
        if inherited:
            store.replace(credentials())
        else:
            store_at(root).credentials()


@pytest.mark.parametrize("reread", [False, True])
@pytest.mark.parametrize("new_login", ["none", "switch", "same"])
def test_clear_after_attempt_write_respects_auth_boundary(
    new_login: str, reread: bool, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    store = store_at(root)
    store.replace(credentials())
    old = store.credentials()
    assert old is not None
    other = store_at(root)
    other.credentials()
    assert other._save_attempt(
        "other", attempt(), expected_generation=other._generation
    )
    replacement = replace(credentials(), user_id="new-user", session_id="new-session")
    if new_login == "same":
        current = other.credentials()
        assert current is not None
        other.clear(current)
        replacement = old
        other.replace(replacement)
    elif new_login == "switch":
        other.replace(replacement)
    if reread:
        store.credentials()
    store.clear(old)
    restored = store_at(root)
    matches = restored.credentials() == (replacement if new_login != "none" else None)
    assert matches
    assert (restored._attempt("other") is not None) == (new_login == "switch")


@pytest.mark.parametrize("boundary", ["logout", "switch", "unreadable"])
def test_memory_overlay_rechecks_persisted_auth_boundary(
    boundary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    store = store_at(root)
    store.replace(credentials())
    old = store.credentials()
    assert old is not None
    store._begin_refresh(old, store._generation)
    rotated = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    original = store._write

    def fail(*args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(store, "_write", fail)
    store._apply_refresh(old, store._generation, rotated, None)
    monkeypatch.setattr(store, "_write", original)
    matches = store.credentials() == rotated
    assert matches
    other = store_at(root)
    current = other.credentials()
    assert current is not None
    if boundary == "unreadable":
        read = store._read
        monkeypatch.setattr(store, "_read", fail)
        issued, generation = store._register()
        matches = issued == rotated
        assert matches
        store._release(generation)
        monkeypatch.setattr(store, "_read", read)
        matches = store.credentials() == rotated
        assert matches
    else:
        if boundary == "logout":
            other.clear(current)
        else:
            other.replace(
                replace(credentials(), user_id="new-user", session_id="new-session")
            )
        with pytest.raises(ClientError, check=lambda e: e.code == "unauthenticated"):
            store._register()
        assert store._credentials is None
        assert not store._volatile
        matches = store.credentials() == other.credentials()
        assert matches


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX path races.")
@pytest.mark.parametrize("attack", ["writable-parent", "swap"])
def test_writable_parent_or_swapped_directory_cannot_redirect_store(
    attack: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    parent = tmp_path / "parent"
    parent.mkdir(mode=0o700)
    root = parent / "state"
    target = tmp_path / "redirect"
    target.mkdir(mode=0o700)
    root.mkdir(mode=0o700)
    store = store_at(root)
    if attack == "writable-parent":
        parent.chmod(0o777)
        with pytest.raises(
            ClientError, check=lambda e: e.code == "failed_precondition"
        ):
            store.replace(credentials())
    else:
        original = device._open_private
        swapped = False

        def open_private(path: Path, **kwargs: Any) -> int:
            nonlocal swapped
            if path.suffix == ".lock" and not swapped:
                swapped = True
                root.rename(parent / "moved")
                root.symlink_to(target, target_is_directory=True)
            return original(path, **kwargs)

        monkeypatch.setattr(device, "_open_private", open_private)
        try:
            store.replace(credentials())
        except ClientError as error:
            assert error.code == "failed_precondition"
        assert swapped
        assert not list(target.glob("*.json"))


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("persist", [True, False])
@pytest.mark.parametrize(
    ("race", "outcome"),
    [
        (race, "success")
        for race in ("attempt", "remove", "exhausted", "logout", "switch")
    ]
    + [
        (race, outcome)
        for race in ("attempt", "remove")
        for outcome in ("rejected", "lost")
    ],
)
async def test_automatic_refresh_preserves_credentials_after_attempt_write(
    mode: str,
    persist: bool,
    race: str,
    outcome: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    old = credentials()
    rotated = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    refreshes, writes = 0, 0
    root = tmp_path / "state"
    store: _DeviceStore

    def other_store() -> _DeviceStore:
        other = store_at(root, origin=store._origin) if persist else store
        other.credentials()
        return other

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            other = other_store()
            current = other.credentials()
            assert current is not None
            if race == "logout":
                other.clear(current)
            elif race == "switch":
                other.replace(
                    replace(credentials(), user_id="new-user", session_id="new-session")
                )
            elif race == "remove":
                assert other._remove_attempts(
                    ("other",),
                    expected_generation=other._generation,
                    expected_auth_generation=other._auth_generation,
                )
            else:
                assert other._save_attempt(
                    "other", attempt(), expected_generation=other._generation
                )
            if outcome == "lost":
                writer.close()
                await writer.wait_closed()
            elif outcome == "rejected":
                await respond(
                    writer, json_bytes({"error": "invalid_token"}), status=401
                )
            else:
                await respond(writer, json_bytes(asdict(rotated)))
        elif request.headers.get("authorization") == "Bearer " + rotated.access_token:
            await respond(writer, json_bytes({"ok": True}))
        else:
            await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as peer:
        store = _device_store(
            peer.origin,
            app="app",
            project="project",
            environment="test",
            persist={"dir": root} if persist else False,
        )
        store.replace(old)
        assert store._save_attempt(
            "other", attempt(), expected_generation=store._generation
        )
        original = store._accept_login

        def accept(value: Any, **kwargs: Any) -> bool:
            nonlocal writes
            writes += 1
            if race == "exhausted":
                other = other_store()
                assert other._save_attempt(
                    "other", attempt(), expected_generation=other._generation
                )
            return original(value, **kwargs)

        monkeypatch.setattr(store, "_accept_login", accept)

        async def call() -> object:
            if mode == "async":
                async with AsyncHttpTransport(peer.origin) as transport:
                    return await transport.with_session(store).invoke("probe.echo", {})

            def sync() -> object:
                with HttpTransport(peer.origin) as transport:
                    return transport.with_session(store).invoke("probe.echo", {})

            return await asyncio.to_thread(sync)

        if race in {"logout", "switch"}:
            with pytest.raises(ClientError):
                await call()
            current = store.credentials()
            assert current is None or current.user_id == "new-user"
        elif outcome == "success":
            assert await call() == {"ok": True}
            matches = store.credentials() == rotated
            assert matches
            assert writes == (3 if race == "exhausted" else 1)
            assert (store._attempt("other") is None) == (race == "remove")
            assert await call() == {"ok": True}
        else:
            with pytest.raises(ClientError):
                await call()
            if outcome == "rejected":
                assert store.credentials() is None
                assert store._attempt("other") is None
                assert store._snapshot()["refresh_unknown"] is False
            else:
                matches = store.credentials() == old
                assert matches
                assert store._snapshot()["refresh_unknown"] is True
                other = other_store()
                assert other._save_attempt(
                    "after", attempt(), expected_generation=other._generation
                )
                assert other._remove_attempts(
                    ("after",),
                    expected_generation=other._generation,
                    expected_auth_generation=other._auth_generation,
                )
                assert store._snapshot()["refresh_unknown"] is True
            with pytest.raises(ClientError):
                await call()
        assert refreshes == 1


@pytest.mark.parametrize("persist", [True, False])
def test_auth_marker_write_failure_sends_no_rpc(
    persist: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _device_store(
        "https://example.com",
        app="app",
        project="project",
        environment="test",
        persist={"dir": tmp_path / "state"} if persist else False,
    )
    store.replace(credentials())
    current = store.credentials()
    state = store._snapshot()
    sends = 0

    def fail(*args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(store, "_write", fail)

    def login() -> None:
        nonlocal sends
        assert store._transition(
            current,
            user_id=current.user_id if current else None,
            expected_generation=cast(int, state["generation"]),
            expected_auth_generation=cast(int, state["auth_generation"]),
            auth_unknown=True,
        )
        sends += 1

    with pytest.raises(ClientError, check=lambda e: e.code == "failed_precondition"):
        login()
    assert sends == 0


@pytest.mark.parametrize("persist", [True, False])
def test_definite_auth_failure_removes_marker_and_keeps_account(
    persist: bool, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    store = _device_store(
        "https://example.com",
        app="app",
        project="project",
        environment="test",
        persist={"dir": root} if persist else False,
    )
    store.replace(credentials())
    old = store.credentials()
    assert old is not None
    state = store._snapshot()
    assert store._transition(
        old,
        user_id=old.user_id,
        expected_generation=cast(int, state["generation"]),
        expected_auth_generation=cast(int, state["auth_generation"]),
        auth_unknown=True,
    )
    marked = store._snapshot()
    assert marked["auth_unknown"] is True
    assert marked["auth_generation"] == state["auth_generation"]
    assert store._save_attempt(
        "other", attempt(), expected_generation=store._generation
    )
    marked = store._snapshot()
    assert marked["auth_unknown"] is True
    assert store._transition(
        old,
        user_id=old.user_id,
        expected_generation=cast(int, marked["generation"]),
        expected_auth_generation=cast(int, state["auth_generation"]),
    )
    matches = (store_at(root) if persist else store).credentials() == old
    assert matches
    assert store._snapshot()["auth_unknown"] is False
    assert store._attempt("other") is not None


def test_auth_success_failed_commit_does_not_restore_previous_account(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path / "state"
    store = store_at(root)
    store.replace(credentials())
    old = store.credentials()
    assert old is not None
    before = store._snapshot()
    assert store._transition(
        old,
        user_id=old.user_id,
        expected_generation=cast(int, before["generation"]),
        expected_auth_generation=cast(int, before["auth_generation"]),
        auth_unknown=True,
    )
    marked = store._snapshot()

    def fail(*args: object) -> None:
        raise PermissionError

    monkeypatch.setattr(store, "_write", fail)
    new = replace(credentials(), user_id="new-user", session_id="new-session")
    assert store._accept_login(
        new,
        user_id=new.user_id,
        expected_generation=cast(int, marked["generation"]),
        expected_auth_generation=cast(int, marked["auth_generation"]),
    )
    matches = store.credentials() == new
    assert matches
    marker_present = json.loads(bundle(store).read_bytes())["auth_unknown"] is True
    assert marker_present
    logical_auth_generation = store._auth_generation
    blocked = store_at(root)
    monkeypatch.setattr(blocked, "_write", fail)
    assert blocked.credentials() is None
    marker_present = json.loads(bundle(store).read_bytes())["auth_unknown"] is True
    assert marker_present
    assert (
        child(
            root,
            "assert s._snapshot()['session'] is None\nassert s.credentials() is None\n",
        ).returncode
        == 0
    )
    matches_logical_generation = (
        json.loads(bundle(store).read_bytes())["auth_generation"]
        == logical_auth_generation
    )
    assert matches_logical_generation
    assert store.credentials() is None


@pytest.mark.parametrize("persist", [True, False])
def test_first_login_does_not_write_auth_marker(
    persist: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _device_store(
        "https://example.com",
        app="app",
        project="project",
        environment="test",
        persist={"dir": tmp_path / "state"} if persist else False,
    )
    state = store._snapshot()
    writes: list[bool] = []
    original = store._write

    def write(record: _Record, value: dict[str, object]) -> None:
        writes.append(value["auth_unknown"] is True)
        original(record, value)

    monkeypatch.setattr(store, "_write", write)
    assert store._transition(
        None,
        expected_generation=cast(int, state["generation"]),
        expected_auth_generation=cast(int, state["auth_generation"]),
        auth_unknown=True,
    )
    assert writes == []
    new = credentials()
    assert store._accept_login(new, user_id=new.user_id, expected_generation=0)
    assert writes == [False]
    matches = (store_at(tmp_path / "state") if persist else store).credentials() == new
    assert matches


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("stage", ["original", "refresh"])
@pytest.mark.parametrize("persist", [True, False])
async def test_call_never_replays_under_switched_account(
    mode: str, stage: str, persist: bool, tmp_path: Path
) -> None:
    expected_code = "unauthenticated" if stage == "original" else "failed_precondition"
    old = credentials()
    rotated = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    other_account = replace(credentials(), user_id="new-user", session_id="new-session")
    root = tmp_path / "state"
    other_sends = 0
    refreshes = 0
    store: _DeviceStore

    def switch_account() -> None:
        target = store_at(root, origin=store._origin) if persist else store
        target.replace(other_account)

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal other_sends, refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            if stage == "refresh":
                switch_account()
            await respond(writer, json_bytes(asdict(rotated)))
        elif (
            request.headers.get("authorization")
            == "Bearer " + other_account.access_token
        ):
            other_sends += 1
            await respond(writer, json_bytes({"ok": True}))
        elif request.headers.get("authorization") == "Bearer " + old.access_token:
            if stage == "original":
                switch_account()
            await respond(writer, json_bytes({"error": "invalid_token"}), status=401)
        else:
            await respond(writer, json_bytes({"ok": True}))

    async with Peer(handler) as peer:
        store = _device_store(
            peer.origin,
            app="app",
            project="project",
            environment="test",
            persist={"dir": root} if persist else False,
        )
        store.replace(old)

        async def run() -> None:
            async with AsyncHttpTransport(peer.origin) as transport:
                client = transport.with_session(store)
                with pytest.raises(
                    ClientError, check=lambda e: e.code == expected_code
                ) as caught:
                    await client.invoke("probe.echo", {"value": "original"})
                assert caught.value.status is None
                assert other_sends == 0
                assert await client.invoke("probe.echo", {"value": "next"}) == {
                    "ok": True
                }

        def sync() -> None:
            with HttpTransport(peer.origin) as transport:
                client = transport.with_session(store)
                with pytest.raises(
                    ClientError, check=lambda e: e.code == expected_code
                ) as caught:
                    client.invoke("probe.echo", {"value": "original"})
                assert caught.value.status is None
                assert other_sends == 0
                assert client.invoke("probe.echo", {"value": "next"}) == {"ok": True}

        if mode == "async":
            await run()
        else:
            await asyncio.to_thread(sync)
    assert other_sends == 1
    assert refreshes == (1 if stage == "refresh" else 0)


@pytest.mark.parametrize("mode", ["sync", "async"])
async def test_refresh_rejection_clears_after_attempt_reread(
    mode: str, tmp_path: Path
) -> None:
    root = tmp_path / "state"
    store: _DeviceStore
    requests = 0

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal requests
        requests += 1
        if request.path == "/auth.refresh":
            previous = store.credentials()
            other = store_at(root, origin=store._origin)
            other.credentials()
            assert other._save_attempt(
                "other", attempt(), expected_generation=other._generation
            )
            matches = store.credentials() == previous
            assert matches
        await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as peer:
        store = store_at(root, origin=peer.origin)
        store.replace(credentials())

        async def run() -> None:
            async with AsyncHttpTransport(peer.origin) as transport:
                with pytest.raises(ClientError):
                    await transport.with_session(store).invoke("probe.echo", {})

        def sync() -> None:
            with HttpTransport(peer.origin) as transport:
                with pytest.raises(ClientError):
                    transport.with_session(store).invoke("probe.echo", {})

        if mode == "async":
            await run()
        else:
            await asyncio.to_thread(sync)
    assert requests == 2
    restored = store_at(root, origin=store._origin)
    assert restored.credentials() is None
    assert restored._attempt("other") is None
    assert not restored._snapshot()["refresh_unknown"]


@pytest.mark.parametrize("mode", ["sync", "async"])
@pytest.mark.parametrize("stage", ["first", "exhausted"])
async def test_refresh_success_survives_commit_reread_failure(
    mode: str, stage: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = credentials()
    rotated = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    root = tmp_path / "state"
    store: _DeviceStore
    refreshes = 0
    snapshots = 0
    unreadable = False

    async def handler(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal refreshes
        if request.path == "/auth.refresh":
            refreshes += 1
            monkeypatch.setattr(store, "_snapshot", snapshot)
            await respond(writer, json_bytes(asdict(rotated)))
        elif request.headers.get("authorization") == "Bearer " + rotated.access_token:
            await respond(writer, json_bytes({"ok": True}))
        else:
            await respond(writer, json_bytes({"error": "invalid_token"}), status=401)

    async with Peer(handler) as peer:
        store = store_at(root, origin=peer.origin)
        store.replace(old)
        read = store._read
        take_snapshot = store._snapshot
        accept = store._accept_login

        def read_or_fail(record: _Record) -> dict[str, object]:
            if unreadable:
                raise PermissionError
            return read(record)

        def snapshot() -> dict[str, object]:
            nonlocal snapshots, unreadable
            snapshots += 1
            unreadable = snapshots == (1 if stage == "first" else 4)
            return take_snapshot()

        def conflict(value: Any, **kwargs: Any) -> bool:
            if stage == "exhausted":
                other = store_at(root, origin=peer.origin)
                other.credentials()
                assert other._save_attempt(
                    "other", attempt(), expected_generation=other._generation
                )
            return accept(value, **kwargs)

        monkeypatch.setattr(store, "_read", read_or_fail)
        monkeypatch.setattr(store, "_accept_login", conflict)
        if mode == "async":
            async with AsyncHttpTransport(peer.origin) as transport:
                assert await transport.with_session(store).invoke("probe.echo", {}) == {
                    "ok": True
                }
        else:

            def sync() -> object:
                with HttpTransport(peer.origin) as transport:
                    return transport.with_session(store).invoke("probe.echo", {})

            assert await asyncio.to_thread(sync) == {"ok": True}
        matches = store.credentials() == rotated
        assert matches
        monkeypatch.setattr(store, "_read", read)
        persisted = store_at(root, origin=peer.origin)._snapshot()
        assert persisted["refresh_unknown"] is True
        assert persisted["auth_generation"] == store._persisted_auth_generation
        matches = persisted["session"] == asdict(old)
        assert matches
    assert refreshes == 1


@pytest.mark.parametrize("reparse", [False, True])
def test_windows_directory_handles_with_native_fake(
    reparse: bool, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """UNVERIFIED on Windows: fakes check pin lifetime and native open flags."""
    from chickinfry import _device_windows as windows

    root = tmp_path / "state"
    root.mkdir(mode=0o700)
    active: dict[int, Path] = {}
    opened: list[Path] = []

    def create(
        path: str,
        access: int,
        share: int,
        attributes: Any,
        disposition: int,
        flags: int,
        template: Any,
    ) -> int:
        assert access == 0x80 and share == 3
        assert disposition == 3 and flags == 0x02200000
        folder = Path(path)
        opened.append(folder)
        active[len(opened)] = folder
        return len(opened)

    def information(handle: int, kind: int, pointer: Any, size: int) -> bool:
        assert kind == 9
        pointer._obj.attributes = 0x410 if reparse and active[handle] == root else 0x10
        return True

    def close(handle: int) -> bool:
        del active[handle]
        return True

    kernel = SimpleNamespace(
        CreateFileW=create, GetFileInformationByHandleEx=information, CloseHandle=close
    )
    monkeypatch.setattr(windows, "_api", lambda name: kernel)
    monkeypatch.setattr(windows, "_check_acl", lambda path: None)
    monkeypatch.setattr(windows, "_mkdir", lambda path: path.mkdir(mode=0o700))
    monkeypatch.setattr(
        windows,
        "_create",
        lambda path: os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)),
    )

    @contextmanager
    def lock(descriptor: int) -> Iterator[None]:
        yield

    monkeypatch.setattr(device, "_HOST", "win32")
    monkeypatch.setattr(device, "_process_lock", lock)
    original_open = device._open_private

    def while_pinned(path: Path, **kwargs: Any) -> int:
        assert root in active.values()
        assert set(root.parents).issubset(active.values())
        return original_open(path, **kwargs)

    monkeypatch.setattr(device, "_open_private", while_pinned)
    store = store_at(root)
    if reparse:
        with pytest.raises(
            ClientError, check=lambda e: e.code == "failed_precondition"
        ):
            store.replace(credentials())
        assert not list(root.glob("*.json"))
    else:
        store.replace(credentials())
    assert root in opened
    assert not active


@pytest.mark.parametrize("boundary", ["corrupt", "version", "known-switch"])
def test_refresh_io_fallback_does_not_override_confirmed_boundary(
    boundary: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = store_at(tmp_path / "state")
    old = credentials()
    store.replace(old)
    previous = store.credentials()
    assert previous is not None
    generation = store._generation
    store._begin_refresh(previous, generation)
    rotated = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    reason = {
        "corrupt": "data_loss",
        "version": "unimplemented",
        "known-switch": "failed_precondition",
    }[boundary]
    if boundary == "known-switch":
        store.replace(
            replace(credentials(), user_id="new-user", session_id="new-session")
        )

    def fail(record: _Record) -> dict[str, object]:
        raise ClientError(reason)

    monkeypatch.setattr(store, "_read", fail)
    expected = "failed_precondition" if boundary == "known-switch" else reason
    with pytest.raises(ClientError, check=lambda e: e.code == expected):
        store._apply_refresh(previous, generation, rotated, None)
    assert not store._volatile
    matches = store._credentials == rotated
    assert not matches


def test_refresh_precondition_does_not_become_storage_fallback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = store_at(tmp_path / "state")
    old = credentials()
    store.replace(old)
    previous = store.credentials()
    assert previous is not None
    generation = store._generation
    store._begin_refresh(previous, generation)
    read = store._snapshot
    before = bundle(store).read_bytes()

    def unknown_auth() -> dict[str, object]:
        return {**read(), "auth_unknown": True}

    monkeypatch.setattr(store, "_snapshot", unknown_auth)
    rotated = replace(credentials(), user_id=old.user_id, session_id=old.session_id)
    with pytest.raises(
        ClientError, check=lambda error: error.code == "failed_precondition"
    ):
        store._apply_refresh(previous, generation, rotated, None)
    assert not store._volatile and store._credentials == previous
    assert bundle(store).read_bytes() == before


@pytest.mark.parametrize(
    "code,message",
    [
        (
            "failed_precondition",
            "Could not use device storage for the session. Check that the storage location is writable, or set persist to another directory or turn it off.",
        ),
        (
            "data_loss",
            "Stored session data could not be read. Sign out to clear it, then sign in again.",
        ),
        (
            "resource_exhausted",
            "Device storage for sign-in is full. Finish or cancel pending sign-ups, then try again.",
        ),
        (
            "unimplemented",
            "Stored session data was written by a newer SDK. Update the SDK, or sign out and sign in again.",
        ),
    ],
)
def test_device_reason_and_exact_message(code: str, message: str) -> None:
    error = _storage_error(code)
    assert error.code == code and error.status is None
    assert str(error) == message
