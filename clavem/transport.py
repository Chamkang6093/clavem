from __future__ import annotations

import asyncio
import socket
import ssl
from collections.abc import AsyncIterator, Awaitable, Callable, Mapping
from contextlib import asynccontextmanager

from clavem.channel import MAX_MESSAGE, Channel, MessageTooLarge, _validate_timeout
from clavem.tls import client_context, server_context

Handler = Callable[[Channel], Awaitable[None]]


async def connect(
    host: str,
    port: int,
    *,
    identity: str,
    key: bytes,
    timeout: float = 5,  # noqa: ASYNC109 - also bounds the TLS handshake.
    io_timeout: float = 30,
) -> Channel:
    """Establish a TLS 1.3 external-PSK channel within timeout seconds."""
    _validate_timeout(timeout, "timeout")
    _validate_timeout(io_timeout, "io_timeout")
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
    channel = Channel(reader, writer, io_timeout=io_timeout)
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
    io_timeout: float = 30,
    max_connections: int = 64,
) -> AsyncIterator[asyncio.Server]:
    """Own a listener and its handlers; cancel handlers when leaving the context.

    A handler owns one authenticated channel for its lifetime. Unexpected
    handler errors propagate through the task group and stop the listener.
    Expected transport errors close only the affected connection.
    """
    _validate_timeout(handshake_timeout, "handshake_timeout")
    _validate_timeout(io_timeout, "io_timeout")
    if (
        isinstance(max_connections, bool)
        or not isinstance(max_connections, int)
        or max_connections < 1
    ):
        raise ValueError("max_connections must be a positive integer")
    context = server_context(keys)
    tasks: set[asyncio.Task[None]] = set()

    async def run(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await writer.start_tls(
                context, ssl_handshake_timeout=handshake_timeout, ssl_shutdown_timeout=2
            )
            if not writer.get_extra_info("ssl_object").session_reused:
                return
            # Accepted sockets do not consistently inherit asyncio's TCP_NODELAY default.
            writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            async with Channel(reader, writer, io_timeout=io_timeout) as channel:
                await handler(channel)
        except (
            asyncio.IncompleteReadError,
            ConnectionError,
            ssl.SSLError,
            MessageTooLarge,
            TimeoutError,
        ):
            pass
        finally:
            # Failed/cancelled upgrades still own a raw transport, with no TLS stream to await.
            writer.close()

    def accept(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        if not server.is_serving() or len(tasks) >= max_connections:
            writer.transport.abort()
            return
        # Do not let ClientHello enter StreamReader before start_tls takes over.
        writer.transport.pause_reading()
        task = group.create_task(run(reader, writer))
        tasks.add(task)
        task.add_done_callback(tasks.discard)

    server = await asyncio.start_server(
        accept,
        host,
        port,
        limit=MAX_MESSAGE + 4,
        start_serving=False,
    )
    async with asyncio.TaskGroup() as group:
        try:
            await server.start_serving()
            yield server
        finally:
            server.close()
            for task in tasks:
                task.cancel()
            # Include sockets that have not completed TLS and have no handler yet.
            server.close_clients()
            await server.wait_closed()
