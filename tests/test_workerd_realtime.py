"""Server realtime publishing and the reserved realtime request paths."""

import json
import unittest
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch

from chickinfry._workerd import (
    Realtime,
    _HostRequest,
    _realtime_request,
    _request,
)
from chickinfry.server import OperationError, Session, User, create_worker_entrypoint


class RecordingBridge:
    def __init__(self, reply: bytes) -> None:
        self.reply = reply
        self.frames: list[dict[str, Any]] = []

    async def realtime(self, rid: int, frame: bytes) -> bytes:
        self.frames.append(json.loads(frame))
        return self.reply


class PublishTests(unittest.IsolatedAsyncioTestCase):
    async def test_publish_sends_one_host_frame_and_accepts_confirmation(self) -> None:
        bridge = RecordingBridge(b"{}")
        state = _HostRequest(bridge, 9, lambda work: None)
        marker = _request.set(state)
        try:
            await Realtime().publish("orders", {"id": 7})
        finally:
            _request.reset(marker)
        self.assertEqual(
            bridge.frames,
            [
                {
                    "rid": 9,
                    "op": "publish",
                    "input": {"channel": "orders", "payload": {"id": 7}},
                }
            ],
        )

    async def test_publish_maps_public_rejections(self) -> None:
        for reply, expected in [
            (b'{"error":"binding_unavailable"}', ("service_unavailable", 503)),
            (
                b'{"error":"unauthorized_project","status":403}',
                ("unauthorized_project", 403),
            ),
            (
                b'{"error":"realtime_publish_outcome_unknown","status":503}',
                ("realtime_publish_outcome_unknown", 503),
            ),
            (b'{"error":"invalid_host_call"}', ("operation_failed", 500)),
            (b'{"reply":"odd"}', ("operation_failed", 500)),
            (b"[]", ("operation_failed", 500)),
        ]:
            with self.subTest(reply=reply):
                bridge = RecordingBridge(reply)
                state = _HostRequest(bridge, 4, lambda work: None)
                marker = _request.set(state)
                try:
                    with self.assertRaises(OperationError) as raised:
                        await Realtime().publish("orders", None)
                finally:
                    _request.reset(marker)
                self.assertEqual(
                    (raised.exception.code, raised.exception.status), expected
                )

    async def test_publish_rejects_values_the_host_frame_cannot_carry(self) -> None:
        bridge = RecordingBridge(b"{}")
        state = _HostRequest(bridge, 4, lambda work: None)
        marker = _request.set(state)
        try:
            with self.assertRaises(OperationError) as raised:
                await Realtime().publish("orders", float("nan"))
        finally:
            _request.reset(marker)
        self.assertEqual(
            (raised.exception.code, raised.exception.status), ("operation_failed", 500)
        )
        self.assertEqual(bridge.frames, [])

    async def test_publish_outside_a_request_is_unavailable(self) -> None:
        with self.assertRaises(OperationError) as raised:
            await Realtime().publish("orders", None)
        self.assertEqual(
            (raised.exception.code, raised.exception.status),
            ("service_unavailable", 503),
        )


class FakeProxy:
    def __init__(self, value: Any) -> None:
        self.value = value
        self.destroyed = False

    def destroy(self) -> None:
        self.destroyed = True


class RealtimeRequestTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.state = _HostRequest(SimpleNamespace(), 12, lambda work: None)
        self.marker = _request.set(self.state)
        self.response = object()
        self.authorize_calls: list[tuple[Any, ...]] = []

    def tearDown(self) -> None:
        _request.reset(self.marker)

    def modules(
        self, props: object = None, config: str | None = None
    ) -> dict[str, Any]:
        async def realtime_ticket(rid: int, request: Any, auth_enabled: bool) -> object:
            return (rid, request, auth_enabled)

        async def realtime_authorize(
            rid: int, request: Any, context: Any, decide: Any, auth: str | None
        ) -> object:
            self.authorize_calls.append((rid, request, context, decide, auth))
            return self.response

        self.prepared: list[Any] = []
        host = SimpleNamespace(
            prepareRealtime=self.prepared.append,
            realtimeTicket=realtime_ticket,
            realtimeAuthorize=realtime_authorize,
        )
        return {
            "workers": SimpleNamespace(
                import_from_javascript=lambda name: host,
                Response=lambda body, status, headers: SimpleNamespace(
                    body=body, status=status, headers=headers
                ),
            ),
            "pyodide.ffi": SimpleNamespace(
                create_proxy=lambda value: FakeProxy(value), to_js=lambda value: value
            ),
        }

    async def run_gate(
        self,
        request: Any,
        context: Any,
        modules: dict[str, Any],
        options: object = None,
        config: str | None = None,
        decide: Any = None,
        environment: Any = None,
        origins: frozenset[str] = frozenset(),
    ) -> object | None:
        with patch("importlib.import_module", side_effect=modules.__getitem__):
            return await _realtime_request(
                request, context, environment, options, config, origins, decide
            )

    async def test_other_paths_reach_the_application(self) -> None:
        request = SimpleNamespace(
            url="https://app.invalid/orders.list", js_object=object()
        )
        self.assertIsNone(await self.run_gate(request, None, self.modules()))

    async def test_ticket_routes_to_the_host_with_the_authentication_state(
        self,
    ) -> None:
        request = SimpleNamespace(
            url="https://app.invalid/realtime.ticket", js_object=object()
        )
        result = await self.run_gate(request, None, self.modules(), config="{}")
        self.assertEqual(result, (12, request.js_object, True))

    async def test_declared_origins_reach_the_host_before_either_path(self) -> None:
        for path in ("realtime.ticket", "realtime.authorize"):
            with self.subTest(path=path):
                modules = self.modules()
                request = SimpleNamespace(
                    url=f"https://app.invalid/{path}", js_object=object()
                )
                await self.run_gate(
                    request,
                    None,
                    modules,
                    origins=frozenset(["https://b.example", "https://a.example"]),
                )
                self.assertEqual(
                    self.prepared, [["https://a.example", "https://b.example"]]
                )

    async def test_decision_may_use_the_request_database_after_host_verification(
        self,
    ) -> None:
        request = SimpleNamespace(
            url="https://app.invalid/realtime.authorize", js_object=object()
        )
        props = SimpleNamespace(realtime=object())
        self.state.business_ready = False
        seen: list[tuple[bool, object]] = []

        async def decide(*_: object) -> bool:
            seen.append((self.state.business_ready, _request.get()))
            return True

        await self.run_gate(
            request,
            SimpleNamespace(props=props),
            self.modules(props=props),
            config="{}",
            decide=decide,
        )
        proxy = self.authorize_calls[0][3]
        metadata = json.dumps(
            {
                "session": None,
                "origin": None,
                "appOrigin": "https://app.example",
                "channel": "orders",
            }
        )
        self.assertEqual(await proxy.value(metadata), "true")
        self.assertEqual(seen, [(True, self.state)])
        self.assertFalse(self.state.business_ready)

    async def test_authorize_without_engine_props_is_not_found(self) -> None:
        request = SimpleNamespace(
            url="https://app.invalid/realtime.authorize", js_object=object()
        )
        result: Any = await self.run_gate(request, None, self.modules())
        self.assertEqual((result.body, result.status), ('{"error":"not_found"}', 404))

    async def test_authorize_routes_the_decision_through_the_host(self) -> None:
        request = SimpleNamespace(
            url="https://app.invalid/realtime.authorize", js_object=object()
        )
        props = SimpleNamespace(realtime=object())
        modules = self.modules(props=props)
        decisions: list[
            tuple[object, object, Session | None, str | None, str, str]
        ] = []

        async def decide(
            options: object,
            environment: object,
            session: Session | None,
            origin: str | None,
            app_origin: str,
            channel: str,
        ) -> bool:
            decisions.append(
                (options, environment, session, origin, app_origin, channel)
            )
            return channel == "orders"

        result = await self.run_gate(
            request,
            SimpleNamespace(props=props),
            modules,
            options="options",
            config="{}",
            decide=decide,
            environment="environment",
        )
        self.assertIs(result, self.response)
        rid, passed_request, context, proxy, auth = self.authorize_calls[0]
        self.assertEqual((rid, passed_request, auth), (12, request.js_object, "{}"))
        metadata = json.dumps(
            {
                "session": {
                    "id": "s1",
                    "user": {"id": "u1", "email": "u1@example.invalid"},
                },
                "origin": None,
                "appOrigin": "https://app.example",
                "channel": "orders",
            }
        )
        self.assertEqual(await proxy.value(metadata), "true")
        self.assertEqual(
            decisions,
            [
                (
                    "options",
                    "environment",
                    Session("s1", User("u1", "u1@example.invalid")),
                    None,
                    "https://app.example",
                    "orders",
                )
            ],
        )
        self.assertEqual(
            await proxy.value(
                json.dumps(
                    {
                        "session": None,
                        "origin": None,
                        "appOrigin": "https://app.example",
                        "channel": "other",
                    }
                )
            ),
            "false",
        )
        self.assertTrue(proxy.destroyed)


class EntrypointOrderTests(unittest.IsolatedAsyncioTestCase):
    """The engine callback has no session, so it never reaches authentication."""

    def entrypoint(self) -> Any:
        host = SimpleNamespace(WorkerEntrypoint=type("Worker", (), {}), Response=None)

        async def setup() -> object:
            return "options"

        def factory(environment: object, context: object, options: object) -> Any:
            return None

        def hooks(options: object) -> Any:
            return None, []

        with patch("chickinfry.server.import_module", return_value=host):
            return create_worker_entrypoint(
                factory,
                setup=setup,
                _auth_config="{}",
                _auth_hooks=hooks,
                _realtime=True,
                _realtime_origins=frozenset(["https://app.example"]),
                _realtime_decide=None,
            )

    async def fetch(self, path: str) -> tuple[Any, AsyncMock, AsyncMock]:
        worker = self.entrypoint()()
        worker.env = SimpleNamespace()
        worker.ctx = SimpleNamespace()
        request = SimpleNamespace(url=f"https://app.invalid/{path}")
        authenticate = AsyncMock(return_value=(None, request))
        answer = AsyncMock(return_value="answered")
        with (
            patch("sys.platform", "emscripten"),
            patch("chickinfry._workerd._authenticate", authenticate),
            patch("chickinfry._workerd._realtime_request", answer),
        ):
            result = await worker.fetch(request)
        return result, authenticate, answer

    async def test_authorize_skips_session_authentication(self) -> None:
        result, authenticate, answer = await self.fetch("realtime.authorize")
        self.assertEqual(result, "answered")
        authenticate.assert_not_awaited()
        answer.assert_awaited_once()
        assert answer.await_args is not None
        self.assertEqual(answer.await_args.args[5], frozenset(["https://app.example"]))

    async def test_ticket_is_answered_after_session_authentication(self) -> None:
        result, authenticate, answer = await self.fetch("realtime.ticket")
        self.assertEqual(result, "answered")
        authenticate.assert_awaited_once()
        answer.assert_awaited_once()


if __name__ == "__main__":
    unittest.main()
