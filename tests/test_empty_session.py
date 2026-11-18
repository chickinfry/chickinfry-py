import asyncio
from contextlib import AsyncExitStack
from dataclasses import asdict

import pytest

from chickinfry import (
    AsyncHttpTransport,
    ClientError,
    HttpTransport,
    MemoryStore,
)

from .peer import Peer, Received, json_bytes, respond
from .test_session import credentials


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("starts_empty", [False, True])
async def test_same_client_can_sign_in_again_after_logout(
    asynchronous: bool, starts_empty: bool
) -> None:
    first, second = credentials(), credentials()
    active = first if not starts_empty else None
    signin_count = 0

    async def handle(request: Received, writer: asyncio.StreamWriter) -> None:
        nonlocal active, signin_count
        authorization = request.headers.get("authorization")
        if request.path == "/auth.signin" and authorization is None:
            active = (first, second)[signin_count]
            signin_count += 1
            await respond(writer, json_bytes(asdict(active)))
        elif request.path == "/auth.signup" and authorization is None:
            await respond(writer, b'{"accepted":true,"attempt":"signup"}')
        elif request.path == "/probe.list" and active is None and authorization is None:
            await respond(writer)
        elif active is not None and authorization == "Bearer " + active.access_token:
            if request.path == "/auth.logout":
                active = None
                await respond(writer, b'{"status":"ok"}')
            else:
                await respond(writer)
        else:
            await respond(writer, b'{"error":"invalid_token"}', status=401)

    async with Peer(handle) as peer, AsyncExitStack() as stack:
        store = MemoryStore(peer.origin, active)
        if not starts_empty:
            signin_count = 1
        if asynchronous:
            owner = await stack.enter_async_context(AsyncHttpTransport(peer.origin))
            async_transport = owner.with_session(store)

            async def invoke(operation: str, *, public: bool = False) -> object:
                call = (
                    getattr(async_transport, "invoke_public", async_transport.invoke)
                    if public
                    else async_transport.invoke
                )
                return await call(operation, {})
        else:
            sync_owner = stack.enter_context(HttpTransport(peer.origin))
            sync_transport = sync_owner.with_session(store)

            async def invoke(operation: str, *, public: bool = False) -> object:
                sync_call = (
                    getattr(sync_transport, "invoke_public", sync_transport.invoke)
                    if public
                    else sync_transport.invoke
                )
                return await asyncio.to_thread(sync_call, operation, {})

        if starts_empty:
            await invoke("auth.signin", public=True)
        await invoke("probe.echo")
        await invoke("auth.logout")
        assert store.credentials() is None
        await invoke("auth.signup", public=True)
        await invoke("probe.list", public=True)
        with pytest.raises(ClientError) as rejected:
            await invoke("probe.echo")
        assert rejected.value.code == "unauthenticated"
        assert rejected.value.status is None
        assert "again" not in str(rejected.value)
        with pytest.raises(
            ClientError, check=lambda error: error.code == "unauthenticated"
        ):
            await invoke("auth.signin")

        await invoke("auth.signin", public=True)
        assert store.credentials() == second
        await invoke("probe.echo")
        await invoke("probe.list", public=True)
        paths = [request.path for request in peer.received]
        assert paths == (["/auth.signin"] if starts_empty else []) + [
            "/probe.echo",
            "/auth.logout",
            "/auth.signup",
            "/probe.list",
            "/auth.signin",
            "/probe.echo",
            "/probe.list",
        ]
        assert bool(
            all(
                request.headers.get("authorization") == "Bearer " + second.access_token
                for request in peer.received[-2:]
            )
        )
