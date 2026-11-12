from __future__ import annotations

import asyncio
import logging
import ssl
from pathlib import Path

import pytest

from clavem import transport
from clavem.channel import Channel
from clavem.tls import client_context


async def test_rejects_untrusted_certificate_fallback(
    certificate_server: tuple[int, list[bool]], key: bytes
) -> None:
    port, _accepted = certificate_server
    async with asyncio.timeout(5):
        with pytest.raises(ssl.SSLCertVerificationError):
            async with await transport.connect("127.0.0.1", port, identity="home", key=key):
                pytest.fail("untrusted certificate fallback was accepted")


async def test_rejects_trusted_certificate_fallback(
    certificate_server: tuple[int, list[bool]],
    certificate: Path,
    key: bytes,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port, accepted = certificate_server

    def trusted_context(identity: str, secret: bytes) -> ssl.SSLContext:
        context = client_context(identity, secret)
        context.load_verify_locations(certificate)
        return context

    # First establish that the real certificate fallback succeeds when trusted.
    # This rules out an unrelated TLS/certificate failure as the test's cause.
    async with asyncio.timeout(5):
        reader, writer = await asyncio.open_connection(
            "127.0.0.1",
            port,
            ssl=trusted_context("home", key),
            server_hostname="",
            ssl_shutdown_timeout=1,
        )
        try:
            assert not writer.get_extra_info("ssl_object").session_reused
            assert await reader.read() == b""
        finally:
            writer.close()
            await writer.wait_closed()
        assert accepted == [False]

        monkeypatch.setattr(transport, "client_context", trusted_context)
        with pytest.raises(ssl.SSLError, match="external PSK"):
            async with await transport.connect("127.0.0.1", port, identity="home", key=key):
                pytest.fail("certificate-only authentication was accepted")


@pytest.mark.parametrize("identity,wrong_key", [("home", True), ("unknown", False)])
async def test_rejects_invalid_credentials_without_stopping_listener(
    key: bytes,
    identity: str,
    wrong_key: bool,
    caplog: pytest.LogCaptureFixture,
    capfd: pytest.CaptureFixture[str],
) -> None:
    caplog.set_level(logging.DEBUG)
    called = asyncio.Event()

    async def echo(channel: Channel) -> None:
        called.set()
        await channel.send(await channel.receive())

    async with asyncio.timeout(5):
        async with transport.serve(echo, "127.0.0.1", 0, keys={"home": key}) as server:
            port = server.sockets[0].getsockname()[1]
            invalid_key = bytes(value ^ 255 for value in key) if wrong_key else key
            with pytest.raises((ssl.SSLError, ConnectionError)) as error:
                await transport.connect("127.0.0.1", port, identity=identity, key=invalid_key)
            assert not called.is_set()
            async with await transport.connect(
                "127.0.0.1", port, identity="home", key=key
            ) as channel:
                await channel.send(b"still listening")
                assert await channel.receive() == b"still listening"
                assert called.is_set()
    captured = capfd.readouterr()
    output = str(error.value) + caplog.text + captured.out + captured.err
    for secret in {key, invalid_key}:
        assert secret.hex() not in output
        assert repr(secret) not in output
