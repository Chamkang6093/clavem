from __future__ import annotations

import asyncio
import ssl
import struct

import pytest

from clavem.channel import Channel
from clavem.tls import client_context
from clavem.transport import connect, serve


def _client_hello(key: bytes) -> bytes:
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    peer = client_context("peer", key).wrap_bio(incoming, outgoing)
    with pytest.raises(ssl.SSLWantReadError):
        peer.do_handshake()
    return outgoing.read()


@pytest.mark.parametrize("peer_state", ["silent", "partial", "abort"])
async def test_cap_includes_handshakes_and_releases_failed_slots(
    key: bytes, peer_state: str
) -> None:
    calls = []

    async def echo(channel: Channel) -> None:
        calls.append(True)
        await channel.send(await channel.receive())

    async with (
        asyncio.timeout(5),
        serve(
            echo, "127.0.0.1", 0, keys={"peer": key}, handshake_timeout=0.4, max_connections=1
        ) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        reader, writer = await asyncio.open_connection("127.0.0.1", port)
        try:
            if peer_state != "silent":
                writer.write(_client_hello(key))
                await writer.drain()
                assert await reader.read(1)
            extra_reader, extra_writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                # Overflow must close before a separate handshake could expire.
                async with asyncio.timeout(0.2):
                    assert await extra_reader.read() == b""
            finally:
                extra_writer.close()
                await extra_writer.wait_closed()
            assert calls == []
            if peer_state == "abort":
                writer.transport.abort()
            else:
                await reader.read()
                assert reader.at_eof()
        finally:
            writer.close()
            await writer.wait_closed()
        for _ in range(2):
            with pytest.raises((ssl.SSLError, ConnectionError)):
                await connect("127.0.0.1", port, identity="unknown", key=key)
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            await channel.send(b"healthy")
            assert await channel.receive() == b"healthy"
        assert calls == [True]


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
            writer.write(_client_hello(key))
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


@pytest.mark.parametrize("message", ["oversized", "truncated"])
async def test_malformed_message_releases_slot_and_preserves_listener(
    key: bytes, message: str
) -> None:
    cleaned_up = asyncio.Event()

    async def echo(channel: Channel) -> None:
        task = asyncio.current_task()
        assert task is not None
        task.add_done_callback(lambda _task: cleaned_up.set())
        await channel.send(b"ready")
        await channel.send(await channel.receive())

    async with (
        asyncio.timeout(3),
        serve(echo, "127.0.0.1", 0, keys={"peer": key}, max_connections=1) as server,
    ):
        port = server.sockets[0].getsockname()[1]
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            assert await channel.receive() == b"ready"
            frame = (
                struct.pack("!I", 2**32 - 1)
                if message == "oversized"
                else (struct.pack("!I", 100) + b"partial")
            )
            channel._writer.write(frame)
            await channel._writer.drain()
            if message == "truncated":
                # Drop TLS without close_notify, leaving an incomplete message.
                channel._writer.transport.abort()
            else:
                assert await channel._reader.read() == b""
        # Local abort completion does not imply the server has released its slot.
        await cleaned_up.wait()
        async with await connect("127.0.0.1", port, identity="peer", key=key) as channel:
            assert await channel.receive() == b"ready"
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
            # Reuse one released slot while another authenticated peer remains.
            await channels.pop().close()
            async with await connect("127.0.0.1", port, identity="peer", key=key) as replacement:
                await replacement.send(b"slot reused")
                assert await replacement.receive() == b"slot reused"
        finally:
            await asyncio.gather(*(channel.close() for channel in channels))
