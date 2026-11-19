import asyncio

import pytest

from chickinfry import ClientError
from chickinfry.realtime import RealtimeClient, _endpoint


def test_realtime_only_accepts_canonical_project_address() -> None:
    address = "wss://10000000-0000-4000-8000-000000000001.chickinfry.app/realtime"
    assert _endpoint(address) == address
    for bad in (
        address + "?ticket=other",
        address.replace("wss:", "ws:"),
        "ws://127.0.0.1/realtime",
    ):
        with pytest.raises(ClientError, match="server response"):
            _endpoint(bad)


async def test_realtime_rejects_invalid_channel_before_transport() -> None:
    class Transport:
        async def invoke(self, operation: str, payload: object) -> object:
            raise AssertionError("invalid input must not acquire a ticket")

    for name in ("", "bad\nchannel", "\ud800", "é" * 65):
        with pytest.raises(ClientError) as failure:
            await RealtimeClient(Transport()).subscribe(name)
        assert failure.value.code == "invalid_argument"


async def test_realtime_does_not_refresh_a_blocked_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from chickinfry import AsyncHttpTransport, MemoryStore, SessionCredentials

    origin = "http://127.0.0.1:1"
    credentials = SessionCredentials(
        access_token="a" * 43,
        refresh_token="b" * 43,
        expires_at="2020-01-01T00:00:00Z",
        refresh_expires_at="2020-01-02T00:00:00Z",
        user_id="user",
        session_id="session",
    )
    store = MemoryStore(origin, credentials)
    store._blocked_generation = store._generation
    rotations = 0

    async def rotate(*args: object, **kwargs: object) -> None:
        nonlocal rotations
        rotations += 1

    async def attempt(*args: object, **kwargs: object) -> object:
        await asyncio.Future[None]()
        raise AssertionError("the pending ticket request should have been canceled")

    owner = AsyncHttpTransport(origin)
    monkeypatch.setattr(owner, "_rotate", rotate)
    monkeypatch.setattr(owner, "_attempt", attempt)
    async with owner:
        with pytest.raises(ClientError) as failure:
            await asyncio.wait_for(
                RealtimeClient(owner.with_session(store)).subscribe("orders"), 2
            )
        assert failure.value.code == "unauthenticated"
        assert rotations == 0
