from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager

from clavem.channel import MAX_MESSAGE, Channel
from clavem.tls import client_context, server_context

Handler = Callable[[Channel], Awaitable[None]]


async def connect(
    host: str,
    port: int,
    *,
    identity: str,
    key: bytes,
    timeout: float = 5,  # noqa: ASYNC109 - also bounds the TLS handshake.
) -> Channel:
    """Establish a TLS 1.3 external-PSK channel within timeout seconds."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    context = client_context(identity, key)
    async with asyncio.timeout(timeout):
        reader, writer = await asyncio.open_connection(
            host,
            port,
            ssl=context,
            server_hostname="",
            ssl_handshake_timeout=timeout,
            ssl_shutdown_timeout=2,
            limit=MAX_MESSAGE + 4,
        )
    channel = Channel(reader, writer)
    if not writer.get_extra_info("ssl_object").session_reused:
        await channel.close()
        raise ssl.SSLError("peer did not authenticate with an external PSK")
    return channel


@asynccontextmanager
async def serve(
    handler: Handler,
    host: str,
    port: int,
    *,
    keys: Mapping[str, bytes],
    handshake_timeout: float = 5,
) -> AsyncIterator[asyncio.Server]:
    """Own a listener and its handlers; cancel handlers when leaving the context.

    A handler owns one authenticated channel for its lifetime. Unexpected
    handler errors propagate through the task group and stop the listener.
    Applications should handle expected disconnects in their handler.
    """
    if handshake_timeout <= 0:
        raise ValueError("handshake_timeout must be positive")
    context = server_context(keys)
    tasks: set[asyncio.Task[None]] = set()

    async def run(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        async with Channel(reader, writer) as channel:
            if not writer.get_extra_info("ssl_object").session_reused:
                raise ssl.SSLError("peer did not authenticate with an external PSK")
            # Accepted sockets do not consistently inherit asyncio's TCP_NODELAY default.
            writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            await handler(channel)

    async with asyncio.TaskGroup() as group:

        def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            task = group.create_task(run(reader, writer))
            tasks.add(task)
            task.add_done_callback(tasks.discard)

        server = await asyncio.start_server(
            accept,
            host,
            port,
            ssl=context,
            ssl_handshake_timeout=handshake_timeout,
            ssl_shutdown_timeout=2,
            limit=MAX_MESSAGE + 4,
        )
        try:
            yield server
        finally:
            server.close()
            for task in tasks:
                task.cancel()
            await server.wait_closed()
