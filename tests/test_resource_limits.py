from __future__ import annotations

import asyncio
import math
import ssl
import struct

import pytest

from clavem.channel import Channel
from clavem.tls import client_context
from clavem.transport import connect, serve


@pytest.mark.parametrize("invalid", [0, -1, True, 1.5, math.inf, "2"])
async def test_connection_cap_must_be_a_positive_integer(key: bytes, invalid: object) -> None:
    with pytest.raises(ValueError, match="max_connections"):
        async with serve(
            lambda _channel: asyncio.sleep(0),
            "127.0.0.1",
            0,
            keys={"peer": key},
            max_connections=invalid,
        ):
            pytest.fail("invalid connection cap accepted")


async def test_cap_includes_handshakes_and_releases_failed_slots(key: bytes) -> None:
    calls = []

    async def echo(channel: Channel) -> None:
        calls.append(True)
        await channel.send(await channel.receive())

    async with (
        asyncio.timeout(5),
        serve(
            echo, "127.0.0.1", 0, keys={"peer": key}, handshake_timeout=0.15, max_connections=1
        ) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            peer = client_context("peer", key).wrap_bio(incoming, outgoing)
            with pytest.raises(ssl.SSLWantReadError):
                peer.do_handshake()
            writer.write(outgoing.read())
            await writer.drain()
            # ServerHello proves that the first handshake owns the only slot.
            assert await reader.read(1)
            for _ in range(3):
                extra_reader, extra_writer = await asyncio.open_connection("127.0.0.1", port)
                try:
                    assert await extra_reader.read() == b""
                finally:
                    extra_writer.close()
                    await extra_writer.wait_closed()
            assert calls == []
            await reader.read()  # The unfinished handshake expires, releasing the slot.
            assert reader.at_eof()
        finally:
            writer.close()
            await writer.wait_closed()
        for _ in range(3):
            with pytest.raises((ssl.SSLError, ConnectionError)):
                await connect("127.0.0.1", port, identity="unknown", key=key)
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            await channel.send(b"healthy")
            assert await channel.receive() == b"healthy"
        assert calls == [True]


async def test_authenticated_channels_keep_their_slots(key: bytes) -> None:
    entered = asyncio.Event()

    async def echo(channel: Channel) -> None:
        entered.set()
        await channel.send(await channel.receive())

    async with (
        asyncio.timeout(3),
        serve(echo, "127.0.0.1", 0, keys={"peer": key}, max_connections=1) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        async with await connect("127.0.0.1", port, identity="peer", key=key) as first:
            await entered.wait()
            with pytest.raises((ssl.SSLError, ConnectionError)):
                await connect("127.0.0.1", port, identity="peer", key=key)
            await first.send(b"first is healthy")
            assert await first.receive() == b"first is healthy"
        async with await connect("127.0.0.1", port, identity="peer", key=key) as second:
            await second.send(b"slot reused")
            assert await second.receive() == b"slot reused"


async def test_cancelling_server_cleans_up_pending_handshakes(key: bytes) -> None:
    ready = asyncio.get_running_loop().create_future()

    async def run() -> None:
        async with serve(
            lambda _channel: asyncio.sleep(0),
            "127.0.0.1",
            0,
            keys={"peer": key},
            handshake_timeout=30,
            max_connections=1,
        ) as server:
            ready.set_result(server.sockets[0].getsockname()[1])
            await asyncio.Event().wait()

    async with asyncio.timeout(2):
        task = asyncio.create_task(run())
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", await ready)
            incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
            peer = client_context("peer", key).wrap_bio(incoming, outgoing)
            with pytest.raises(ssl.SSLWantReadError):
                peer.do_handshake()
            writer.write(outgoing.read())
            await writer.drain()
            assert await reader.read(1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await reader.read()
            assert reader.at_eof()
        finally:
            if writer is not None:
                writer.close()
                await writer.wait_closed()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_malformed_message_is_isolated_without_handler_catch(key: bytes) -> None:
    async def echo(channel: Channel) -> None:
        await channel.send(await channel.receive())

    async with (
        asyncio.timeout(3),
        serve(echo, "127.0.0.1", 0, keys={"peer": key}, max_connections=1) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            channel._writer.write(struct.pack("!I", 2**32 - 1))
            await channel._writer.drain()
            assert await channel._reader.read() == b""
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            await channel.send(b"healthy")
            assert await channel.receive() == b"healthy"


async def test_plaintext_is_rejected_before_application_handler(key: bytes) -> None:
    called = asyncio.Event()

    async def echo(channel: Channel) -> None:
        called.set()
        await channel.send(await channel.receive())

    async with (
        asyncio.timeout(3),
        serve(echo, "127.0.0.1", 0, keys={"peer": key}, max_connections=1) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            writer.write(struct.pack("!I", 5) + b"hello")
            await writer.drain()
            assert await reader.read() == b""
            assert not called.is_set()
        finally:
            writer.close()
            await writer.wait_closed()
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            await channel.send(b"authenticated")
            assert await channel.receive() == b"authenticated"


async def test_concurrent_admission_never_exceeds_cap(key: bytes) -> None:
    async def echo(channel: Channel) -> None:
        while True:
            await channel.send(await channel.receive())

    async with (
        asyncio.timeout(5),
        serve(echo, "127.0.0.1", 0, keys={"peer": key}, max_connections=2) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        outcomes = await asyncio.gather(
            *(connect("127.0.0.1", port, identity="peer", key=key) for _ in range(10)),
            return_exceptions=True,
        )
        channels = [result for result in outcomes if isinstance(result, Channel)]
        try:
            assert len(channels) == 2
            assert all(
                isinstance(result, (Channel, ConnectionError, ssl.SSLError)) for result in outcomes
            )
            for channel in channels:
                await channel.send(b"healthy")
                assert await channel.receive() == b"healthy"
        finally:
            await asyncio.gather(*(channel.close() for channel in channels))
