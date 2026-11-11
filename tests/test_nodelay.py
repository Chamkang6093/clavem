from __future__ import annotations

import asyncio
import socket

from clavem.channel import Channel
from clavem.transport import connect, serve


async def test_tcp_nodelay_is_enabled_on_both_peers(key: bytes) -> None:
    server_option: asyncio.Future[int] = asyncio.get_running_loop().create_future()

    async def inspect(channel: Channel) -> None:
        connection = channel._writer.get_extra_info("socket")
        server_option.set_result(connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY))
        # Keep the channel open until the server context cancels this handler.
        # Avoid an unrelated EOF masking a failed socket-option assertion.
        await asyncio.Event().wait()

    async with asyncio.timeout(5):
        async with serve(inspect, "127.0.0.1", 0, keys={"home": key}) as server:
            port = server.sockets[0].getsockname()[1]
            async with await connect("127.0.0.1", port, identity="home", key=key) as channel:
                connection = channel._writer.get_extra_info("socket")
                # Enabled is nonzero; Darwin exposes the flag bit rather than 1.
                assert connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0
                assert await server_option != 0
