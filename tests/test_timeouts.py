from __future__ import annotations

import asyncio
import math
import struct
from unittest.mock import MagicMock

import pytest

from clavem.channel import Channel
from clavem.transport import connect, serve


@pytest.mark.parametrize("invalid", [0, -1, math.nan, math.inf, -math.inf])
async def test_io_deadlines_are_validated_before_connecting(key: bytes, invalid: float) -> None:
    with pytest.raises(ValueError, match="io_timeout"):
        await connect("127.0.0.1", 0, identity="peer", key=key, io_timeout=invalid)
    with pytest.raises(ValueError, match="io_timeout"):
        async with serve(
            lambda _channel: asyncio.sleep(0),
            "127.0.0.1",
            0,
            keys={"peer": key},
            io_timeout=invalid,
        ):
            pytest.fail("invalid deadline accepted")


@pytest.mark.parametrize("frame", [b"", b"\x00\x00", struct.pack("!I", 8) + b"abc"])
async def test_receive_deadline_aborts_partial_frames(key: bytes, frame: bytes) -> None:
    disconnected = asyncio.Event()

    async def stall(channel: Channel) -> None:
        channel._writer.write(frame)
        await channel._writer.drain()
        assert await channel._reader.read() == b""
        disconnected.set()

    async with asyncio.timeout(3), serve(stall, "127.0.0.1", 0, keys={"peer": key}) as server:
        async with await connect(
            "127.0.0.1",
            server.sockets[0].getsockname()[1],
            identity="peer",
            key=key,
            io_timeout=0.05,
        ) as channel:
            with pytest.raises(TimeoutError):
                await channel.receive()
            with pytest.raises(ConnectionError, match="closed"):
                await channel.receive()
            with pytest.raises(ConnectionError, match="closed"):
                await channel.send(b"cannot reuse")
            await disconnected.wait()


async def test_cancelled_receive_aborts_channel(key: bytes) -> None:
    ready = asyncio.Event()
    disconnected = asyncio.Event()

    async def stall(channel: Channel) -> None:
        ready.set()
        assert await channel._reader.read() == b""
        disconnected.set()

    async with asyncio.timeout(3), serve(stall, "127.0.0.1", 0, keys={"peer": key}) as server:
        async with await connect(
            "127.0.0.1", server.sockets[0].getsockname()[1], identity="peer", key=key
        ) as channel:
            task = asyncio.create_task(channel.receive())
            await ready.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            with pytest.raises(ConnectionError, match="closed"):
                await channel.send(b"cannot reuse")
            await disconnected.wait()


@pytest.mark.parametrize("waiting_for_lock", [False, True])
async def test_send_deadline_includes_backpressure_and_lock(waiting_for_lock: bool) -> None:
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False
    writer.transport = MagicMock(spec=asyncio.Transport)
    writer.drain.side_effect = asyncio.Event().wait
    channel = Channel(asyncio.StreamReader(), writer, io_timeout=0.02)
    if waiting_for_lock:
        await channel._send_lock.acquire()
    try:
        async with asyncio.timeout(2):
            with pytest.raises(TimeoutError):
                await channel.send(b"blocked")
        writer.transport.abort.assert_called_once()
        if waiting_for_lock:
            writer.write.assert_not_called()
    finally:
        if channel._send_lock.locked():
            channel._send_lock.release()


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


async def test_cancelled_send_aborts_channel() -> None:
    writer = MagicMock(spec=asyncio.StreamWriter)
    writer.is_closing.return_value = False
    writer.transport = MagicMock(spec=asyncio.Transport)
    entered = asyncio.Event()

    async def blocked() -> None:
        entered.set()
        await asyncio.Event().wait()

    writer.drain.side_effect = blocked
    channel = Channel(asyncio.StreamReader(), writer)
    async with asyncio.timeout(2):
        task = asyncio.create_task(channel.send(b"pending"))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    writer.transport.abort.assert_called_once()
    with pytest.raises(ConnectionError, match="closed"):
        await channel.receive()
