import asyncio
import json
import unittest
from datetime import date, datetime, timezone
from importlib.metadata import requires
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import UUID

from packaging.requirements import Requirement

from chickinfry._workerd import (
    _bind_log,
    _fetch,
    _HostPort,
    _HostRequest,
    _LogStream,
    _request,
    _wait_until,
)
from chickinfry.orm import DatabasePort
from chickinfry.postgres import CommitOutcomeUnknown


class Bridge:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.error: dict[str, str] | None = None
        self.finished: list[tuple[int, bool]] = []
        self.logs: list[dict[str, object]] = []

    def log(self, rid: int, frame: bytes) -> None:
        record = json.loads(frame)
        assert record["rid"] == rid
        self.logs.append(record)

    def background(self, rid: int) -> int:
        assert rid == 4
        return 5

    async def db(self, frame: bytes) -> bytes:
        call = json.loads(frame)
        self.calls.append(call)
        if self.error:
            return json.dumps(self.error).encode()
        return json.dumps(
            {"lease": 7}
            if call["op"] == "begin"
            else {"rows": []}
            if call["op"] in ("query", "exec")
            else {}
        ).encode()

    async def finish(self, rid: int, cancel: bool) -> None:
        self.finished.append((rid, cancel))


class WorkerdPortTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.bridge = Bridge()
        self.finishing: list[asyncio.Future[None]] = []
        self.state = _HostRequest(self.bridge, 4, self.schedule)
        self.token = _request.set(self.state)
        self.port = _HostPort()

    def schedule(self, work: Any) -> None:
        self.finishing.append(asyncio.ensure_future(work))

    async def asyncTearDown(self) -> None:
        _request.reset(self.token)

    async def test_saved_logger_is_request_bound_and_stdout_is_buffered(self) -> None:
        saved_log = _bind_log()
        print("first", end="", file=_LogStream("info"))
        print("\nsecond", file=_LogStream("info"))
        token = _request.set(_HostRequest(self.bridge, 5, self.schedule))
        try:
            saved_log("info", "wrong request", None)
        finally:
            _request.reset(token)
        self.state.finish()
        saved_log("info", "closed request", None)
        await asyncio.gather(*self.finishing)
        self.assertEqual(
            self.bridge.logs, [{"rid": 4, "level": "info", "message": "first\nsecond"}]
        )

    async def test_auth_background_owns_a_separate_host_request(self) -> None:
        async def cleanup() -> None:
            await _HostPort().query("select 1", [])

        _wait_until(cleanup())
        self.state.finish()
        await self.finishing[0]
        await asyncio.gather(*self.finishing[1:])
        self.assertEqual([frame["rid"] for frame in self.bridge.calls], [5])
        self.assertCountEqual(self.bridge.finished, [(4, False), (5, False)])

    async def test_frame_values_and_transaction_lifetime(self) -> None:
        stamp = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=timezone.utc)
        await self.port.query(
            "select $1, $2, $3", [date(2026, 1, 2), stamp, UUID(int=1)]
        )
        frame = self.bridge.calls[-1]
        self.assertEqual(frame["rid"], 4)
        self.assertEqual(frame["params"][1], "2026-01-02T03:04:05.123456Z")
        saved: list[DatabasePort] = []

        async def work(tx: DatabasePort) -> int:
            saved.append(tx)
            await tx.query("select 1", [])
            with self.assertRaises(RuntimeError):
                await tx.transaction(work)
            with self.assertRaises(RuntimeError):
                await self.port.query("select 2", [])
            return 9

        self.assertEqual(await self.port.transaction(work), 9)
        self.assertEqual(
            [x["op"] for x in self.bridge.calls], ["query", "begin", "exec", "commit"]
        )
        with self.assertRaises(RuntimeError):
            await saved[0].query("select 1", [])

    async def test_sqlstate_and_untrusted_error_never_expose_raw_text(self) -> None:
        for envelope, code in [
            ({"error": "23505"}, "23505"),
            ({"error": "password=private"}, None),
            ({"error": "23505", "message": "private"}, None),
        ]:
            self.bridge.error = envelope
            with self.assertRaises(Exception) as caught:
                await self.port.query("select 1", [])
            self.assertNotIn("private", str(caught.exception))
            self.assertEqual(getattr(caught.exception, "sqlstate", None), code)

        async def rejected(frame: bytes) -> bytes:
            raise RuntimeError("private diagnostic")

        with patch.object(self.bridge, "db", rejected):
            with self.assertRaises(Exception) as caught:
                await self.port.query("select 1", [])
            self.assertNotIn("private", str(caught.exception))

    async def test_rollback_and_commit_unknown_never_retry(self) -> None:
        async def fail(tx: DatabasePort) -> None:
            raise ValueError("business")

        with self.assertRaises(ValueError):
            await self.port.transaction(fail)
        self.assertEqual([x["op"] for x in self.bridge.calls], ["begin", "rollback"])
        self.bridge.calls.clear()

        async def ambiguous(tx: DatabasePort) -> None:
            self.bridge.error = {"error": "commit_unknown"}

        with self.assertRaises(CommitOutcomeUnknown):
            await self.port.transaction(ambiguous)
        self.assertEqual([x["op"] for x in self.bridge.calls], ["begin", "commit"])
        with self.assertRaises(RuntimeError):
            await self.port.query("select 1", [])

    async def test_cross_request_and_unsafe_number_rejected_before_host_call(
        self,
    ) -> None:
        for value in [2**53, float("nan"), float("inf")]:
            with self.assertRaises(ValueError):
                await self.port.query("select $1", [value])
        token = _request.set(_HostRequest(self.bridge, 5, self.schedule))
        try:
            with self.assertRaises(RuntimeError):
                await self.port.query("select 1", [])
        finally:
            _request.reset(token)
        self.assertEqual(self.bridge.calls, [])

    async def test_cancel_finishes_host_request(self) -> None:
        async def cancelled(frame: bytes) -> bytes:
            raise asyncio.CancelledError

        with patch.object(self.bridge, "db", cancelled):
            with self.assertRaises(asyncio.CancelledError):
                await self.port.query("select 1", [])
        await asyncio.gather(*self.finishing)
        self.assertEqual(self.bridge.finished, [(4, True)])

    async def test_callback_cancellation_closes_host_without_rollback(self) -> None:
        async def cancel(tx: DatabasePort) -> None:
            raise asyncio.CancelledError

        with self.assertRaises(asyncio.CancelledError):
            await self.port.transaction(cancel)
        await asyncio.gather(*self.finishing)
        self.assertEqual([x["op"] for x in self.bridge.calls], ["begin"])
        self.assertEqual(self.bridge.finished, [(4, True)])

    def test_server_extra_selects_native_driver_only(self) -> None:
        dependencies = requires("chickinfry")
        assert dependencies is not None
        driver = next(
            Requirement(value)
            for value in dependencies
            if Requirement(value).name == "asyncpg"
        )
        assert driver.marker is not None
        self.assertFalse(
            driver.marker.evaluate({"extra": "server", "sys_platform": "emscripten"})
        )
        self.assertTrue(
            driver.marker.evaluate({"extra": "server", "sys_platform": "darwin"})
        )
        self.assertTrue(
            driver.marker.evaluate({"extra": "server", "sys_platform": "linux"})
        )

    async def test_sdk_returns_before_host_cleanup_and_finishes_once(self) -> None:
        signal, headers, response = object(), object(), object()
        events: list[str] = []
        release = asyncio.Event()
        finished: list[asyncio.Task[None]] = []

        def start(value: object, incoming_headers: object) -> int:
            self.assertIs(value, signal)
            self.assertIs(incoming_headers, headers)
            events.append("start")
            return 11

        async def finish(rid: int, cancel: bool) -> None:
            self.assertEqual((rid, cancel), (11, False))
            events.append("finish")
            await release.wait()

        host = SimpleNamespace(
            verify=lambda python, pyodide: events.append("verify"),
            prepare=lambda environment, names, vault: events.append("prepare"),
            start=start,
            finish=finish,
            outputBlocked=lambda: None,
        )
        modules = {
            "workers": SimpleNamespace(import_from_javascript=lambda name: host),
            "pyodide.ffi": SimpleNamespace(to_js=lambda value: value),
            "js": SimpleNamespace(),
            "pyodide": SimpleNamespace(__version__="314.0.6"),
        }

        def wait_until(work: Any) -> None:
            finished.append(asyncio.create_task(work))

        worker = SimpleNamespace(
            env=object(), ctx=SimpleNamespace(waitUntil=wait_until)
        )
        request = SimpleNamespace(
            js_object=SimpleNamespace(signal=signal, headers=headers)
        )

        async def dispatch(instance: object, incoming: object) -> object:
            self.assertIs(instance, worker)
            self.assertIs(incoming, request)
            state = _request.get()
            assert state is not None
            self.assertEqual(state.rid, 11)
            events.append("dispatch")
            return response

        with (
            patch("chickinfry._workerd._output_blocked", None),
            patch("importlib.import_module", side_effect=modules.__getitem__),
        ):
            self.assertIs(
                await asyncio.wait_for(_fetch(dispatch, worker, request), 1), response
            )
        self.assertEqual(len(finished), 1)
        self.assertFalse(finished[0].done())
        release.set()
        await finished[0]
        self.assertEqual(events, ["verify", "prepare", "start", "dispatch", "finish"])
        self.assertIs(_request.get(), self.state)
