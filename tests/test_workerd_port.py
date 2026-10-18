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

from chickinfry._workerd import _fetch, _HostPort, _HostRequest, _request
from chickinfry.orm import DatabasePort
from chickinfry.postgres import CommitOutcomeUnknown


class Bridge:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.error: dict[str, str] | None = None
        self.finished: list[tuple[int, bool]] = []

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
        self.state = _HostRequest(self.bridge, 4)
        self.token = _request.set(self.state)
        self.port = _HostPort()

    async def asyncTearDown(self) -> None:
        _request.reset(self.token)

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
        token = _request.set(_HostRequest(self.bridge, 5))
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
        self.assertEqual(self.bridge.finished, [(4, True)])

    async def test_callback_cancellation_closes_host_without_rollback(self) -> None:
        async def cancel(tx: DatabasePort) -> None:
            raise asyncio.CancelledError

        with self.assertRaises(asyncio.CancelledError):
            await self.port.transaction(cancel)
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

    async def test_sdk_request_signal_bootstraps_before_dispatch(self) -> None:
        signal, response = object(), object()
        events: list[str] = []

        def start(value: object) -> int:
            self.assertIs(value, signal)
            events.append("start")
            return 11

        async def finish(rid: int, cancel: bool) -> None:
            self.assertEqual((rid, cancel), (11, False))
            events.append("finish")

        host = SimpleNamespace(
            verify=lambda python, pyodide: events.append("verify"),
            prepare=lambda environment: events.append("prepare"),
            start=start,
            finish=finish,
        )
        modules = {
            "workers": SimpleNamespace(import_from_javascript=lambda name: host),
            "pyodide.ffi": SimpleNamespace(),
            "js": SimpleNamespace(),
            "pyodide": SimpleNamespace(__version__="314.0.6"),
        }
        worker = SimpleNamespace(env=object())
        request = SimpleNamespace(js_object=SimpleNamespace(signal=signal))

        async def dispatch(instance: object, incoming: object) -> object:
            self.assertIs(instance, worker)
            self.assertIs(incoming, request)
            state = _request.get()
            assert state is not None
            self.assertEqual(state.rid, 11)
            events.append("dispatch")
            return response

        with patch("importlib.import_module", side_effect=modules.__getitem__):
            self.assertIs(await _fetch(dispatch, worker, request), response)
        self.assertEqual(events, ["verify", "prepare", "start", "dispatch", "finish"])
        self.assertIs(_request.get(), self.state)
