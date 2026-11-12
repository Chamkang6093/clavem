from __future__ import annotations

import asyncio
import struct
from unittest.mock import MagicMock

import pytest

from clavem.channel import Channel
from clavem.transport import connect, serve


@pytest.mark.parametrize("drip", [False, True], ids=["idle", "drip"])
async def test_receive_deadline_survives_partial_progress(key: bytes, drip: bool) -> None:
    disconnected = asyncio.Event()
    fragments = 0

    async def stall(channel: Channel) -> None:
        nonlocal fragments
        try:
            if drip:
                # The header consumes part of the same deadline as the body.
                for byte in struct.pack("!I", 65_536) + b"x" * 8:
                    channel._writer.write(bytes([byte]))
                    await channel._writer.drain()
                    fragments += 1
                    await asyncio.sleep(0.06)
            else:
                assert await channel._reader.read() == b""
        finally:
            disconnected.set()

    async with asyncio.timeout(3), serve(stall, "127.0.0.1", 0, keys={"peer": key}) as server:
        async with await connect(
            "127.0.0.1",
            server.sockets[0].getsockname()[1],
            identity="peer",
            key=key,
            io_timeout=0.25,
        ) as channel:
            # A new deadline after the header, or after each byte, must fail here.
            async with asyncio.timeout(0.375):
                with pytest.raises(TimeoutError):
                    await channel.receive()
            if drip:
                assert fragments >= 2
            with pytest.raises(ConnectionError, match="closed"):
                await channel.receive()
            with pytest.raises(ConnectionError, match="closed"):
                await channel.send(b"cannot reuse")
            await disconnected.wait()


async def test_send_deadline_aborts_backpressured_channel() -> None:
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False
    writer.transport = MagicMock(spec=asyncio.Transport)
    writer.drain.side_effect = asyncio.Event().wait
    channel = Channel(asyncio.StreamReader(), writer, io_timeout=0.02)
    async with asyncio.timeout(2):
        with pytest.raises(TimeoutError):
            await channel.send(b"blocked")
    writer.transport.abort.assert_called_once()
    with pytest.raises(ConnectionError, match="closed"):
        await channel.receive()


async def test_server_timeout_preserves_listener(key: bytes) -> None:
    async def echo(channel: Channel) -> None:
        await channel.send(await channel.receive())

    async with (
        asyncio.timeout(3),
        serve(echo, "127.0.0.1", 0, keys={"peer": key}, io_timeout=0.05) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            assert await channel._reader.read() == b""
        assert server.is_serving()
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            await channel.send(b"healthy")
            assert await channel.receive() == b"healthy"


async def test_connect_deadline_closes_a_stalled_handshake(key: bytes) -> None:
    accepted = asyncio.get_running_loop().create_future()

    def stall(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.set_result((reader, writer))

    listener = await asyncio.start_server(stall, "127.0.0.1", 0)
    async with asyncio.timeout(3), listener:
        try:
            with pytest.raises((TimeoutError, ConnectionAbortedError)):
                await connect(
                    "127.0.0.1",
                    listener.sockets[0].getsockname()[1],
                    identity="peer",
                    key=key,
                    timeout=0.1,
                )
            reader, _writer = await accepted
            # Discard ClientHello; EOF establishes that connect released its socket.
            await reader.read()
        finally:
            listener.close()
            listener.close_clients()
