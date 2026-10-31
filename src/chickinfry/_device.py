"""Private device bridge; generated wiring supplies trusted ownership context."""

import json
import os
import stat
import sys
import threading
from collections.abc import Iterator, Mapping
from contextlib import ExitStack, contextmanager
from copy import deepcopy
from dataclasses import asdict, dataclass, field, replace
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast
from uuid import uuid4

from .errors import ClientError, _local_error, _storage_error
from .session import (
    MemoryStore,
    SessionCredentials,
    _commit_device_refresh,
    _Failure,
    _read_credentials,
    _validate,
)


def _object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


class _Attempt(dict[str, object]):
    """Validated auth-owned payload; no request bodies or passwords are accepted."""

    def __repr__(self) -> str:
        return "<signup attempt>"


_HOST = sys.platform
_VERSION = 1
_MAX_BYTES = 8 * 1024
_MAX_ATTEMPTS = 3
_MAX_ID = 36
_MAX_EMAIL = 320
_MAX_SCREEN = 64
_MAX_INT = 2**63 - 1


def _time(value: str) -> int:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        raise ValueError
    delta = parsed - datetime(1970, 1, 1, tzinfo=timezone.utc)
    micros = (delta.days * 86400 + delta.seconds) * 1_000_000 + delta.microseconds
    if not -_MAX_INT - 1 <= micros <= _MAX_INT:
        raise ValueError
    return micros


def _native(credentials: SessionCredentials) -> None:
    _validate(credentials)
    try:
        if max(len(credentials.user_id), len(credentials.session_id)) > _MAX_ID:
            raise ValueError
        _time(credentials.expires_at)
        _time(credentials.refresh_expires_at)
    except (ValueError, OverflowError):
        raise ClientError("failed_precondition") from None


def _next_auth_generation(
    state: dict[str, object],
    credentials: SessionCredentials | None,
    *,
    scoped_delete: bool = False,
    floor: int = 0,
) -> int:
    generation = cast(int, state["auth_generation"])
    previous = state["session"]
    if not scoped_delete and credentials is not None and isinstance(previous, dict):
        if (previous.get("user_id"), previous.get("session_id")) == (
            credentials.user_id,
            credentials.session_id,
        ):
            return generation
    return max(generation, floor) + 1


def _location(app: str) -> Path:
    if _HOST == "win32":
        base = os.environ.get("LOCALAPPDATA")
        if not base or not Path(base).is_absolute():
            raise _storage_error("failed_precondition")
        root = Path(base)
    else:
        home = os.environ.get("HOME")
        state = os.environ.get("XDG_STATE_HOME")
        if _HOST != "darwin" and state and Path(state).is_absolute():
            root = Path(state)
        else:
            if not home or not Path(home).is_absolute():
                raise _storage_error("failed_precondition")
            root = (
                Path(home) / "Library" / "Application Support"
                if _HOST == "darwin"
                else Path(home) / ".local" / "state"
            )
    return root / "chickinfry" / sha256(app.encode()).hexdigest()


def _check_path(path: Path, *, directory: bool = False) -> None:
    info = path.lstat()
    if getattr(info, "st_file_attributes", 0) & 0x400:
        raise _storage_error("failed_precondition")
    if stat.S_ISLNK(info.st_mode) or not (
        stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
    ):
        raise _storage_error("failed_precondition")
    if _HOST == "win32":
        from ._device_windows import _check_acl

        _check_acl(path)
    elif info.st_uid != os.getuid() or (
        bool(info.st_mode & 0o022) if directory else stat.S_IMODE(info.st_mode) != 0o600
    ):
        raise _storage_error("failed_precondition")
    if not directory and info.st_nlink != 1:
        raise _storage_error("failed_precondition")


def _check_acl(descriptor: int) -> None:
    if _HOST != "darwin":
        return
    import ctypes
    import errno

    libc = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    libc.acl_get_fd.argtypes = [ctypes.c_int]
    libc.acl_get_fd.restype = ctypes.c_void_p
    libc.acl_get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p]
    libc.acl_get_tag_type.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    libc.acl_free.argtypes = [ctypes.c_void_p]
    acl = libc.acl_get_fd(descriptor)
    if not acl:
        if ctypes.get_errno() == errno.ENOENT:
            return
        raise _storage_error("failed_precondition")
    try:
        entry, tag = ctypes.c_void_p(), ctypes.c_int()
        index = 0  # ACL_FIRST_ENTRY; Darwin's ACL_NEXT_ENTRY is -1.
        while libc.acl_get_entry(acl, index, ctypes.byref(entry)) == 0:
            if libc.acl_get_tag_type(entry, ctypes.byref(tag)) != 0 or tag.value == 1:
                raise _storage_error("failed_precondition")
            index = -1
        if ctypes.get_errno() != errno.EINVAL:
            raise _storage_error("failed_precondition")
    finally:
        libc.acl_free(acl)


def _check_directory(descriptor: int, *, ancestor: bool) -> None:
    info = os.fstat(descriptor)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid not in (
        (0, os.getuid()) if ancestor else (os.getuid(),)
    ):
        raise _storage_error("failed_precondition")
    if info.st_mode & 0o022 and not (ancestor and info.st_mode & stat.S_ISVTX):
        raise _storage_error("failed_precondition")
    _check_acl(descriptor)


def _directory(path: Path) -> int | None:
    if not path.is_absolute() or ".." in path.parts:
        raise _storage_error("failed_precondition")
    if _HOST != "win32":
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(path.anchor, flags)
        try:
            _check_directory(descriptor, ancestor=True)
            for index, part in enumerate(path.parts[1:]):
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                child = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
                _check_directory(descriptor, ancestor=index < len(path.parts) - 2)
            return descriptor
        except BaseException:
            os.close(descriptor)
            raise
    for parent in path.parents:
        if parent.is_symlink() or (
            parent.exists() and getattr(parent.lstat(), "st_file_attributes", 0) & 0x400
        ):
            raise _storage_error("failed_precondition")
    missing: list[Path] = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for folder in reversed(missing):
        try:
            if _HOST == "win32":
                from ._device_windows import _mkdir

                _mkdir(folder)
            else:
                folder.mkdir(mode=0o700)
        except FileExistsError:
            pass
        _check_path(folder, directory=True)
    _check_path(path, directory=True)
    return None


def _open_private(
    path: Path,
    *,
    create: bool = False,
    exclusive: bool = False,
    directory: int | None = None,
) -> int:
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    if create:
        if _HOST == "win32":
            from ._device_windows import _create

            try:
                _create(path)
            except FileExistsError:
                if exclusive:
                    raise
        else:
            flags |= os.O_CREAT | (os.O_EXCL if exclusive else 0)
    target = path if directory is None else Path(path.name)
    descriptor = os.open(target, flags, 0o600, dir_fd=directory)
    try:
        if directory is None:
            _check_path(path)
            if _HOST == "win32":
                for parent in path.parents:
                    info = parent.lstat()
                    if (
                        not stat.S_ISDIR(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & 0x400
                    ):
                        raise _storage_error("failed_precondition")
        opened = os.fstat(descriptor)
        if directory is not None and (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != os.getuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
        ):
            raise _storage_error("failed_precondition")
        _check_acl(descriptor)
        current = os.stat(target, dir_fd=directory, follow_symlinks=False)
        if (opened.st_dev, opened.st_ino) != (current.st_dev, current.st_ino):
            raise _storage_error("failed_precondition")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


@contextmanager
def _process_lock(descriptor: int) -> Iterator[None]:
    if _HOST == "win32":
        import msvcrt

        os.lseek(descriptor, 0, os.SEEK_SET)
        getattr(msvcrt, "locking")(descriptor, getattr(msvcrt, "LK_LOCK"), 1)
        try:
            yield
        finally:
            os.lseek(descriptor, 0, os.SEEK_SET)
            getattr(msvcrt, "locking")(descriptor, getattr(msvcrt, "LK_UNLCK"), 1)
    else:
        import fcntl

        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)


def _atomic_write(path: Path, data: bytes, *, directory: int | None = None) -> None:
    temporary = path.with_name("." + path.name + "." + uuid4().hex + ".tmp")
    try:
        descriptor = _open_private(
            temporary, create=True, exclusive=True, directory=directory
        )
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            descriptor = _open_private(path, directory=directory)
        except FileNotFoundError:
            pass
        else:
            os.close(descriptor)
        if directory is None:
            os.replace(temporary, path)
        else:
            os.replace(
                temporary.name, path.name, src_dir_fd=directory, dst_dir_fd=directory
            )
            os.fsync(directory)
        os.close(_open_private(path, directory=directory))
    finally:
        try:
            os.unlink(
                temporary if directory is None else temporary.name, dir_fd=directory
            )
        except FileNotFoundError:
            pass


@dataclass(repr=False)
class _Record:
    raw: bytes | None
    directory: int | None = None
    lock: threading.RLock = field(default_factory=threading.RLock, repr=False)


class _DeviceSessionStore(MemoryStore):
    def __init__(self, origin: str) -> None:
        super().__init__(origin)
        self._auth_generation = 0
        self._peer_blocked = False
        self._call_auth_generations: dict[int, int] = {}

    def _register(
        self, deadline: float | None = None
    ) -> tuple[SessionCredentials, int]:
        with self._locked(deadline):
            previous_auth = self._auth_generation
            had_credentials = self._credentials is not None
            self.credentials()
            if had_credentials and previous_auth != self._auth_generation:
                self._credentials = None
                raise _local_error("unauthenticated", "invalid_session")
            if self._peer_blocked:
                raise _local_error("unauthenticated", "invalid_session")
            snapshot, generation = super()._register(deadline)
            self._call_auth_generations[generation] = self._auth_generation
            return snapshot, generation

    def _release(self, generation: int) -> None:
        with self._locked():
            super()._release(generation)
            if generation not in self._active:
                self._call_auth_generations.pop(generation, None)

    def _current(self, snapshot: SessionCredentials, generation: int) -> bool:
        self.credentials()
        return super()._current(snapshot, generation)

    def _new_credentials(self, generation: int) -> SessionCredentials | None:
        self.credentials()
        if (
            self._credentials is None
            or self._call_auth_generations.get(generation) != self._auth_generation
        ):
            raise _local_error("unauthenticated", "invalid_session")
        return super()._new_credentials(generation)


class _DeviceStore(_DeviceSessionStore):
    def __init__(
        self,
        origin: str,
        *,
        app: str,
        project: str,
        environment: str,
        path: Path | None = None,
        persist: bool = True,
    ) -> None:
        super().__init__(origin)
        if any(
            not isinstance(value, str) or not value
            for value in (app, project, environment)
        ):
            raise ClientError("invalid_argument")
        self._scope = json.dumps(
            [app, self._origin, project, environment], separators=(",", ":")
        )
        self._memory_record = None if persist else _Record(None)
        self._directory = path
        self._path: Path | None = None
        self._app = app
        self._storage_blocked = False
        self._location_ready = False
        self._volatile = False
        self._persisted_auth_generation = 0
        self._persisted_session: object = None
        self._refresh_auth_generations: dict[int, int] = {}
        self._auth_in_progress: tuple[int, object] | None = None
        self._retired_screens: set[str] = set()
        self._baseline: dict[str, object] | None = None
        self._pending: dict[str, object] | None = None
        self._candidate: dict[str, object] | None = None
        self._pending_view: dict[str, object] | None = None
        self._discarded = False
        self._peer_blocked = False
        self._auth_request: str | None = None
        self._refresh_request: str | None = None
        self._memory_success = False
        self._auth_high_water = 0

    @contextmanager
    def _transaction(self, *, block_on_failure: bool = False) -> Iterator[_Record]:
        if self._storage_blocked:
            raise _storage_error("failed_precondition")
        failure: ClientError | None = None
        descriptor = None
        directory = None
        pins = ExitStack()
        try:
            if self._memory_record is not None:
                self._location_ready = True
                with self._memory_record.lock:
                    yield self._memory_record
                return
            self._directory = self._directory or _location(self._app)
            if _HOST == "win32":
                from ._device_windows import _pin_directory

                pins.enter_context(_pin_directory(self._directory))
            directory = _directory(self._directory)
            self._path = self._directory / (
                sha256(self._scope.encode()).hexdigest() + ".json"
            )
            descriptor = _open_private(
                self._path.with_suffix(".lock"), create=True, directory=directory
            )
            self._location_ready = True
            with _process_lock(descriptor):
                raw = None
                try:
                    opened = _open_private(self._path, directory=directory)
                except FileNotFoundError:
                    pass
                else:
                    with os.fdopen(opened, "rb") as stream:
                        raw = stream.read(_MAX_BYTES + 1)
                yield _Record(raw, directory)
        except ClientError as error:
            failure = error
        except Exception as error:
            reason = (
                "resource_exhausted"
                if isinstance(error, OSError) and error.errno in (28, 122)
                else "failed_precondition"
            )
            failure = _storage_error(reason)
        finally:
            if descriptor is not None:
                os.close(descriptor)
            if directory is not None:
                os.close(directory)
            pins.close()
        if failure is not None:
            if block_on_failure:
                self._storage_blocked = True
            raise failure from None

    def _read(self, record: _Record) -> dict[str, object]:
        if record.raw is None:
            return {
                "version": 1,
                "scope": self._scope,
                "generation": 0,
                "auth_generation": 0,
                "session": None,
                "attempts": {},
                "refresh_unknown": False,
                "auth_unknown": False,
                "refresh_request": None,
                "auth_request": None,
            }
        try:
            if len(record.raw) > _MAX_BYTES:
                raise ValueError
            value: object = json.loads(
                record.raw.decode("utf-8"), object_pairs_hook=_object
            )
            if not isinstance(value, dict):
                raise ValueError
            state = cast(dict[str, object], value)
            if type(state.get("version")) is not int:
                raise ValueError
            if state["version"] != _VERSION:
                raise _storage_error("unimplemented")
            state.setdefault("auth_unknown", False)
            state.setdefault("refresh_request", None)
            state.setdefault("auth_request", None)
            if (
                set(state)
                != {
                    "version",
                    "scope",
                    "generation",
                    "auth_generation",
                    "session",
                    "attempts",
                    "refresh_unknown",
                    "auth_unknown",
                    "refresh_request",
                    "auth_request",
                }
                or state["scope"] != self._scope
                or type(state["generation"]) is not int
                or not 0 <= state["generation"] <= _MAX_INT
                or type(state["auth_generation"]) is not int
                or not 0 <= state["auth_generation"] <= _MAX_INT
                or type(state["refresh_unknown"]) is not bool
                or type(state["auth_unknown"]) is not bool
                or not isinstance(state["attempts"], dict)
            ):
                raise ValueError
            for kind in ("refresh", "auth"):
                request = state[kind + "_request"]
                if request is not None and (
                    not isinstance(request, str)
                    or not 0 < len(request) <= _MAX_SCREEN
                    or not request.isascii()
                    or not state[kind + "_unknown"]
                ):
                    raise ValueError
            if (state["refresh_unknown"] or state["auth_unknown"]) and state[
                "session"
            ] is None:
                raise ValueError
            if state["session"] is not None:
                if not isinstance(state["session"], dict) or set(state["session"]) != {
                    "access_token",
                    "refresh_token",
                    "expires_at",
                    "refresh_expires_at",
                    "user_id",
                    "session_id",
                }:
                    raise ValueError
                _native(_read_credentials(state["session"]))
            if len(cast(dict[str, object], state["attempts"])) > _MAX_ATTEMPTS:
                raise ValueError
            for screen, attempt in cast(dict[str, object], state["attempts"]).items():
                self._validate_attempt(screen, attempt)
            return state
        except ClientError as error:
            if error.code == "unimplemented":
                raise
        except (ValueError, TypeError, KeyError, RecursionError):
            pass
        raise _storage_error("data_loss")

    def _write(self, record: _Record, state: dict[str, object]) -> None:
        raw = json.dumps(
            state, ensure_ascii=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        if len(raw) > _MAX_BYTES or any(
            not 0 <= cast(int, state[key]) <= _MAX_INT
            for key in ("generation", "auth_generation")
        ):
            raise _storage_error("resource_exhausted")
        if self._memory_record is None:
            assert self._path is not None
            _atomic_write(self._path, raw, directory=record.directory)
        record.raw = raw

    def _load(self, state: dict[str, object]) -> None:
        generation = cast(int, state["generation"])
        unknown_auth = state["auth_unknown"] and self._auth_in_progress != (
            state["auth_generation"],
            state["session"],
        )
        credentials = (
            _read_credentials(state["session"])
            if state["session"] is not None and not unknown_auth
            else None
        )
        # Attempt-only changes must preserve a pending delete's expected session.
        if (
            state["auth_generation"] != self._auth_generation
            or credentials != self._credentials
        ):
            self._credentials = credentials
        self._generation = generation
        self._auth_generation = cast(int, state["auth_generation"])
        self._auth_high_water = max(self._auth_high_water, self._auth_generation)
        self._blocked_generation = (
            generation if state["refresh_unknown"] or state["auth_unknown"] else None
        )
        if not state["refresh_unknown"] and not state["auth_unknown"]:
            self._peer_blocked = False
        if not self._volatile:
            self._baseline = deepcopy(state)

    def _commit(self, record: _Record, state: dict[str, object]) -> None:
        self._candidate = deepcopy(state)
        self._write(record, state)
        self._candidate = None

    def _hold(self, state: dict[str, object]) -> None:
        self._pending = deepcopy(state)
        self._pending_view = None
        self._volatile = True
        if self._baseline is not None:
            self._persisted_auth_generation = cast(
                int, self._baseline["auth_generation"]
            )
            self._persisted_session = deepcopy(self._baseline["session"])
        self._load(state)

    @staticmethod
    def _recoverable(error: ClientError) -> bool:
        return error._storage_failure and error.code in {
            "failed_precondition",
            "resource_exhausted",
        }

    @staticmethod
    def _auth_state(state: dict[str, object]) -> tuple[object, ...]:
        return tuple(
            state[key]
            for key in (
                "scope",
                "auth_generation",
                "session",
                "refresh_unknown",
                "refresh_request",
                "auth_unknown",
                "auth_request",
            )
        )

    def _merge_attempts(
        self,
        base: dict[str, object],
        memory: dict[str, object],
        latest: dict[str, object],
    ) -> dict[str, object]:
        before = cast(dict[str, dict[str, object]], base["attempts"])
        local = cast(dict[str, dict[str, object]], memory["attempts"])
        remote = cast(dict[str, dict[str, object]], latest["attempts"])
        merged = deepcopy(remote)
        for screen, old in before.items():
            own = local.get(screen)
            current = merged.get(screen)
            if (own is None or own["attempt"] != old["attempt"]) and (
                current is not None and current["attempt"] == old["attempt"]
            ):
                merged.pop(screen)
        for screen, own in local.items():
            original = before.get(screen)
            current = remote.get(screen)
            if original is not None and own["attempt"] == original["attempt"]:
                if current is None or current["attempt"] != original["attempt"]:
                    continue
                if own == original:
                    continue
            if (
                current is not None
                and current != original
                and (cast(int, own["sequence"]) <= cast(int, current["sequence"]))
            ):
                continue
            merged[screen] = deepcopy(own)
        now = _time(datetime.now(timezone.utc).isoformat())
        return {
            screen: value
            for screen, value in merged.items()
            if now - _time(cast(str, value["started_at"])) < 86_400_000_000
        }

    def _swap(
        self, record: _Record, expected: bytes | None, state: dict[str, object]
    ) -> bool:
        if record.raw != expected:
            return False
        self._commit(record, state)
        return True

    def _rejoin(self, record: _Record, latest: dict[str, object]) -> dict[str, object]:
        base, memory = self._baseline, self._pending
        assert memory is not None
        for _ in range(3):
            raw = record.raw
            applied = self._candidate is not None and (
                latest == self._candidate
                or (
                    self._auth_state(latest) == self._auth_state(self._candidate)
                    and cast(int, latest["generation"])
                    >= cast(int, self._candidate["generation"])
                    and base is not None
                    and self._auth_state(self._candidate) != self._auth_state(base)
                )
            )
            if (
                base is None
                or (
                    latest["auth_generation"] != base["auth_generation"] and not applied
                )
                or (cast(int, latest["generation"]) < cast(int, base["generation"]))
            ):
                self._volatile = False
                self._pending = self._candidate = self._pending_view = None
                self._credentials = None
                self._generation = cast(int, latest["generation"])
                self._auth_generation = cast(int, latest["auth_generation"])
                self._auth_high_water = max(
                    self._auth_high_water, self._auth_generation
                )
                self._baseline = deepcopy(latest)
                self._retired_screens.clear()
                self._memory_success = False
                self._auth_request = self._refresh_request = None
                self._auth_in_progress = None
                self._peer_blocked = bool(
                    latest["refresh_unknown"] or latest["auth_unknown"]
                )
                self._discarded = True
                return latest
            merged = deepcopy(latest)
            own_markers = {
                "refresh": self._refresh_request,
                "auth": self._auth_request,
            }
            install = latest["session"] == base["session"] and all(
                not base[kind + "_unknown"]
                or (
                    request is not None
                    and base[kind + "_request"] == request
                    and latest[kind + "_request"] == request
                    and latest[kind + "_unknown"] is True
                )
                for kind, request in own_markers.items()
                if base[kind + "_unknown"] and not memory[kind + "_unknown"]
            )
            if install:
                merged["session"] = deepcopy(memory["session"])
                merged["auth_generation"] = memory["auth_generation"]
                for kind, request in own_markers.items():
                    if (
                        base[kind + "_unknown"]
                        and not memory[kind + "_unknown"]
                        and request is not None
                        and latest[kind + "_request"] == request
                    ):
                        merged[kind + "_unknown"] = False
                        merged[kind + "_request"] = None
            merged["attempts"] = self._merge_attempts(base, memory, latest)
            if merged != latest:
                merged["generation"] = cast(int, latest["generation"]) + 1
            self._pending_view = deepcopy(merged)
            self._peer_blocked = bool(
                merged["refresh_unknown"] or merged["auth_unknown"]
            )
            self._load(merged)
            if len(cast(dict[str, object], merged["attempts"])) > _MAX_ATTEMPTS:
                raise _storage_error("resource_exhausted")
            if merged != latest:
                if not self._swap(record, raw, merged):
                    latest = self._read(record)
                    continue
            self._volatile = False
            self._pending = self._candidate = self._pending_view = None
            self._retired_screens.clear()
            if not merged["refresh_unknown"]:
                self._refresh_request = None
            if not merged["auth_unknown"]:
                self._auth_request = None
                self._auth_in_progress = None
            return merged
        raise _storage_error("failed_precondition")

    def _restore(self, record: _Record) -> dict[str, object]:
        state = self._read(record)
        if self._volatile:
            return self._rejoin(record, state)
        if self._baseline is not None and any(
            state[kind + "_unknown"]
            and (
                not self._baseline[kind + "_unknown"]
                or state[kind + "_request"] != self._baseline[kind + "_request"]
            )
            for kind in ("refresh", "auth")
        ):
            self._peer_blocked = True
        if (
            self._baseline is None
            and state["auth_unknown"]
            and self._auth_in_progress
            != (
                state["auth_generation"],
                state["session"],
            )
        ):
            cleaned = {
                **state,
                "session": None,
                "auth_unknown": False,
                "refresh_unknown": False,
                "auth_request": None,
                "refresh_request": None,
                "generation": cast(int, state["generation"]) + 1,
                "auth_generation": cast(int, state["auth_generation"]) + 1,
            }
            try:
                self._write(record, cleaned)
            except (ClientError, OSError):
                pass
            else:
                state = cleaned
        self._baseline = deepcopy(state)
        return state

    def _snapshot(self) -> dict[str, object]:
        return self._view()

    def _view(self) -> dict[str, object]:
        with self._locked():
            self._check_loop()
            self._discarded = False
            try:
                with self._transaction() as record:
                    state = self._restore(record)
            except ClientError as error:
                if (
                    self._memory_success
                    and self._baseline is not None
                    and self._credentials is not None
                    and not self._volatile
                    and self._recoverable(error)
                ):
                    self._hold(self._baseline)
                if not self._volatile or not self._recoverable(error):
                    raise
                overlay = self._pending_view or self._pending
                assert overlay is not None
                state = deepcopy(overlay)
            if not self._discarded:
                self._load(state)
            return state

    def credentials(self) -> SessionCredentials | None:
        with self._locked():
            self._check_loop()
            if self._storage_blocked:
                raise _storage_error("failed_precondition")
            self._view()
            return self._credentials

    def _attach(self, mode: Literal["sync", "async"], origin: str) -> None:
        with self._locked():
            if origin != self._origin:
                raise _local_error("failed_precondition", "origin_mismatch")
            if self._mode is not None and self._mode != mode:
                raise ClientError("failed_precondition")
            if self._mode is None and mode == "sync":
                self._loop = None
            self.credentials()
            super()._attach(mode, origin)

    def replace(self, credentials: SessionCredentials) -> None:
        _native(credentials)
        with self._locked():
            self._check_loop()
            with self._transaction() as record:
                state = self._read(record)
                state.update(
                    auth_generation=_next_auth_generation(
                        state, credentials, floor=self._auth_high_water
                    ),
                    session=asdict(credentials),
                    generation=cast(int, state["generation"]) + 1,
                    refresh_unknown=False,
                    auth_unknown=False,
                    refresh_request=None,
                    auth_request=None,
                )
                self._write(record, state)
                # A run-local overlay can share the committed generation.
                self._credentials = None
                self._load(state)
            self._volatile = False
            self._pending = self._candidate = self._pending_view = None
            self._retired_screens.clear()
            self._memory_success = False
            self._auth_request = self._refresh_request = None
            self._auth_in_progress = None
            self._condition.notify_all()

    def clear(self, expected: SessionCredentials) -> None:
        with self._locked():
            self._check_loop()
            if expected is not self._credentials:
                return
            auth_generation = (
                self._persisted_auth_generation
                if self._volatile
                else self._auth_generation
            )
            session = self._persisted_session if self._volatile else asdict(expected)
            with self._transaction(block_on_failure=True) as record:
                state = self._read(record)
                if (
                    state["auth_generation"] == auth_generation
                    and state["session"] == session
                ):
                    state.update(
                        session=None,
                        attempts={},
                        refresh_unknown=False,
                        auth_unknown=False,
                        refresh_request=None,
                        auth_request=None,
                        generation=cast(int, state["generation"]) + 1,
                        auth_generation=max(auth_generation, self._auth_high_water) + 1,
                    )
                    self._write(record, state)
                self._volatile = False
                self._pending = self._candidate = self._pending_view = None
                self._credentials = None
                self._auth_request = self._refresh_request = None
                self._auth_in_progress = None
                self._load(state)
                self._condition.notify_all()
                self._memory_success = False

    @staticmethod
    def _validate_attempt(screen_id: str, value: object) -> _Attempt:
        if (
            not isinstance(screen_id, str)
            or not screen_id
            or not isinstance(value, dict)
            or set(value) != {"attempt", "email", "started_at", "sequence"}
        ):
            raise ClientError("invalid_argument")
        record = cast(dict[str, object], value)
        if (
            any(
                not isinstance(record[key], str) or not record[key]
                for key in ("attempt", "email", "started_at")
            )
            or type(record["sequence"]) is not int
            or record["sequence"] < 0
        ):
            raise ClientError("invalid_argument")
        if (
            len(screen_id) > _MAX_SCREEN
            or not screen_id.isascii()
            or len(cast(str, record["attempt"])) > _MAX_ID
            or len(cast(str, record["email"])) > _MAX_EMAIL
            or record["sequence"] > _MAX_INT
        ):
            raise ClientError("invalid_argument")
        try:
            _time(cast(str, record["started_at"]))
        except (ValueError, OverflowError):
            raise ClientError("invalid_argument") from None
        return _Attempt(record)

    def _attempt(self, screen_id: str) -> _Attempt | None:
        with self._locked():
            state = self._snapshot()
            attempts = cast(dict[str, object], state["attempts"])
            value = attempts.get(screen_id)
            return None if value is None else self._validate_attempt(screen_id, value)

    def _save_attempt(
        self,
        screen_id: str,
        value: Mapping[str, object],
        *,
        expected_generation: int,
        remove_screens: tuple[str, ...] = (),
        expected_auth_generation: int | None = None,
    ) -> bool:
        attempt = self._validate_attempt(screen_id, dict(value))
        with self._locked():
            auth_generation = (
                self._auth_generation
                if expected_auth_generation is None
                else expected_auth_generation
            )
            candidate = None
            try:
                with self._transaction() as record:
                    self._discarded = False
                    state = self._restore(record)
                    if (
                        self._discarded
                        or state["generation"] != expected_generation
                        or state["auth_generation"] != auth_generation
                    ):
                        if not self._discarded:
                            self._load(state)
                        return False
                    attempts = cast(dict[str, object], state["attempts"])
                    for screen in remove_screens:
                        attempts.pop(screen, None)
                    if screen_id not in attempts and len(attempts) >= _MAX_ATTEMPTS:
                        raise _storage_error("resource_exhausted")
                    attempts[screen_id] = attempt
                    state["generation"] = expected_generation + 1
                    candidate = state
                    self._commit(record, state)
                    self._load(state)
                    return True
            except ClientError as error:
                if candidate is not None and self._recoverable(error):
                    self._hold(candidate)
                elif (
                    self._location_ready
                    and self._recoverable(error)
                    and candidate is None
                ):
                    # No verified baseline remains distinct from an empty store.
                    fallback = self._pending or self._baseline
                    if fallback is None:
                        state = {
                            "version": 1,
                            "scope": self._scope,
                            "generation": expected_generation,
                            "auth_generation": auth_generation,
                            "session": None,
                            "attempts": {},
                            "refresh_unknown": False,
                            "auth_unknown": False,
                            "refresh_request": None,
                            "auth_request": None,
                        }
                    else:
                        state = deepcopy(fallback)
                    if (
                        state["generation"] == expected_generation
                        and state["auth_generation"] == auth_generation
                    ):
                        attempts = cast(dict[str, object], state["attempts"])
                        for screen in remove_screens:
                            attempts.pop(screen, None)
                        if screen_id in attempts or len(attempts) < _MAX_ATTEMPTS:
                            attempts[screen_id] = attempt
                            state["generation"] = expected_generation + 1
                            self._hold(state)
                raise

    def _remove_attempts(
        self,
        screens: tuple[str, ...],
        *,
        expected_generation: int,
        expected_auth_generation: int,
    ) -> bool:
        with self._locked(), self._transaction() as record:
            state = self._restore(record)
            if (
                state["generation"] != expected_generation
                or state["auth_generation"] != expected_auth_generation
            ):
                self._load(state)
                return False
            for screen in screens:
                cast(dict[str, object], state["attempts"]).pop(screen, None)
            state["generation"] = expected_generation + 1
            try:
                self._commit(record, state)
            except (ClientError, OSError):
                self._hold(state)
                raise
            self._load(state)
            return True

    def _transition(
        self,
        credentials: SessionCredentials | None,
        *,
        expected_generation: int,
        screens: tuple[str, ...] | None = (),
        user_id: str | None = None,
        expected_auth_generation: int | None = None,
        auth_unknown: bool = False,
    ) -> bool:
        if credentials is not None:
            _native(credentials)
            if user_id != credentials.user_id:
                raise ClientError("invalid_argument")
        with self._locked(), self._transaction(block_on_failure=True) as record:
            self._discarded = False
            latest = self._read(record) if auth_unknown and self._peer_blocked else None
            if latest is not None and any(
                latest[kind + "_unknown"]
                and (
                    latest[kind + "_request"] is None
                    or latest[kind + "_request"] != owned_request
                )
                for kind, owned_request in (
                    ("refresh", self._refresh_request),
                    ("auth", self._auth_request),
                )
            ):
                state = latest
                persisted_auth = (
                    self._baseline["auth_generation"]
                    if self._volatile and self._baseline is not None
                    else self._auth_generation
                )
                if (
                    expected_generation != self._generation
                    or state["auth_generation"] != persisted_auth
                    or (
                        expected_auth_generation is not None
                        and expected_auth_generation != self._auth_generation
                    )
                ):
                    return False
                if screens is None:
                    raise ClientError("invalid_argument")
                state["attempts"] = self._merge_attempts(state, state, state)
                state.update(
                    session=None,
                    refresh_unknown=False,
                    auth_unknown=False,
                    refresh_request=None,
                    auth_request=None,
                    generation=max(
                        cast(int, state["generation"]),
                        self._generation,
                        cast(int, (self._pending or state)["generation"]),
                    )
                    + 1,
                    auth_generation=max(
                        cast(int, state["auth_generation"]), self._auth_high_water
                    )
                    + 1,
                )
                if not self._swap(record, record.raw, state):
                    return False
                self._volatile = False
                self._pending = self._candidate = self._pending_view = None
                self._retired_screens.clear()
                self._memory_success = False
                self._auth_request = self._refresh_request = None
                self._auth_in_progress = None
                self._load(state)
                self._condition.notify_all()
                return True
            state = self._restore(record)
            if (
                state["generation"] != expected_generation
                or (
                    expected_auth_generation is not None
                    and state["auth_generation"] != expected_auth_generation
                )
                or self._discarded
            ):
                self._load(state)
                return False
            if auth_unknown:
                if state["session"] is None:
                    self._load(state)
                    return True
                if (
                    credentials is None
                    or state["session"] != asdict(credentials)
                    or screens != ()
                ):
                    raise ClientError("invalid_argument")
                if state["auth_unknown"] or state["refresh_unknown"]:
                    raise ClientError("failed_precondition")
                request = str(uuid4())
                state.update(
                    auth_unknown=True,
                    auth_request=request,
                    generation=expected_generation + 1,
                )
                try:
                    self._write(record, state)
                except (ClientError, OSError):
                    raise _storage_error("failed_precondition") from None
                self._auth_in_progress = (
                    cast(int, state["auth_generation"]),
                    state["session"],
                )
                self._auth_request = request
                self._load(state)
                return True
            if credentials is not None:
                for kind, owned_request in (
                    ("refresh", self._refresh_request),
                    ("auth", self._auth_request),
                ):
                    if (owned_request is not None or state[kind + "_unknown"]) and (
                        owned_request is None
                        or not state[kind + "_unknown"]
                        or state[kind + "_request"] != owned_request
                    ):
                        raise ClientError("failed_precondition")
            attempts = cast(dict[str, object], state["attempts"])
            if screens is None:
                attempts.clear()
            else:
                for screen in screens:
                    attempts.pop(screen, None)
            state.update(
                auth_generation=_next_auth_generation(
                    state,
                    credentials,
                    scoped_delete=screens is None,
                    floor=self._auth_high_water,
                ),
                session=asdict(credentials) if credentials else None,
                generation=expected_generation + 1,
                refresh_unknown=False,
                auth_unknown=False,
                refresh_request=None,
                auth_request=None,
            )
            self._commit(record, state)
            self._auth_in_progress = None
            self._auth_request = self._refresh_request = None
            self._load(state)
            self._condition.notify_all()
            return True

    def _accept_login(
        self,
        credentials: SessionCredentials,
        *,
        expected_generation: int,
        user_id: str,
        screens: tuple[str, ...] = (),
        expected_auth_generation: int | None = None,
    ) -> bool:
        with self._locked():
            if self._generation != expected_generation:
                return False
            persisted_auth_generation = self._auth_generation
            persisted_session = asdict(self._credentials) if self._credentials else None
        _native(credentials)
        if user_id != credentials.user_id:
            raise ClientError("invalid_argument")
        try:
            return self._transition(
                credentials,
                expected_generation=expected_generation,
                user_id=user_id,
                screens=screens,
                expected_auth_generation=expected_auth_generation,
            )
        except ClientError as error:
            if (
                not self._location_ready
                or not error._storage_failure
                or error.code
                not in {
                    "failed_precondition",
                    "resource_exhausted",
                }
            ):
                raise
        with self._locked():
            if (
                self._generation != expected_generation
                or self._auth_generation != persisted_auth_generation
            ):
                return False
            self._keep_memory(
                credentials,
                persisted_auth_generation=persisted_auth_generation,
                persisted_session=persisted_session,
                screens=screens,
            )
        return True

    def _keep_memory(
        self,
        credentials: SessionCredentials,
        *,
        persisted_auth_generation: int,
        persisted_session: object,
        screens: tuple[str, ...] = (),
    ) -> None:
        # STORE-ERRORS E1: only verified server credentials can enter this overlay.
        with self._locked():
            state = deepcopy(self._pending or self._baseline)
            if state is None:
                state = {
                    "version": 1,
                    "scope": self._scope,
                    "generation": self._generation,
                    "auth_generation": persisted_auth_generation,
                    "session": persisted_session,
                    "attempts": {},
                    "refresh_unknown": False,
                    "auth_unknown": False,
                    "refresh_request": None,
                    "auth_request": None,
                }
            state.update(
                auth_generation=_next_auth_generation(
                    state, credentials, floor=self._auth_high_water
                ),
                session=asdict(credentials),
                generation=self._generation + 1,
                refresh_unknown=False,
                auth_unknown=False,
                refresh_request=None,
                auth_request=None,
            )
            for screen in screens:
                cast(dict[str, object], state["attempts"]).pop(screen, None)
            self._hold(state)
            self._memory_success = True
            self._credentials = replace(credentials)
            self._storage_blocked = False
            self._retired_screens.update(screens)
            self._condition.notify_all()

    def _begin_refresh(self, snapshot: SessionCredentials, generation: int) -> None:
        with self._locked(), self._transaction() as record:
            state = self._restore(record)
            if (
                state["generation"] != generation
                or state["refresh_unknown"]
                or state["auth_unknown"]
            ):
                self._load(state)
                raise ClientError("failed_precondition")
            state["refresh_unknown"] = True
            request = str(uuid4())
            state["refresh_request"] = request
            self._write(record, state)
            self._load(state)
            self._refresh_request = request
            self._refresh_auth_generations[generation] = self._auth_generation

    def _apply_refresh(
        self,
        snapshot: SessionCredentials,
        generation: int,
        credentials: SessionCredentials | None,
        failure: _Failure | None,
    ) -> None:
        auth_generation = self._refresh_auth_generations.pop(generation, None)
        if failure is None and credentials is not None:
            _commit_device_refresh(self, snapshot, auth_generation, credentials)
        elif (
            failure is not None
            and failure.valid_error_envelope
            and failure.status == 401
        ):
            self.clear(snapshot)
        # All other outcomes retain the durable consumption-unknown marker.


def _persist_settings(persist: bool | Mapping[str, object]) -> bool | dict[str, Path]:
    if persist is True or persist is False:
        return persist
    if (
        isinstance(persist, Mapping)
        and set(persist) == {"dir"}
        and isinstance(persist["dir"], (str, os.PathLike))
    ):
        try:
            raw = os.fspath(persist["dir"])
            if not isinstance(raw, str) or not raw or "\0" in raw:
                raise ValueError
            return {"dir": Path(os.path.abspath(raw))}
        except (OSError, ValueError, TypeError):
            raise _storage_error("failed_precondition") from None
    raise ClientError("invalid_argument")


def _device_store(
    origin: str,
    *,
    app: str,
    project: str,
    environment: str,
    persist: bool | Mapping[str, object] = True,
) -> _DeviceStore:
    settings = _persist_settings(persist)
    path = settings["dir"] if isinstance(settings, dict) else None
    return _DeviceStore(
        origin,
        app=app,
        project=project,
        environment=environment,
        path=path,
        persist=settings is not False,
    )
