from __future__ import annotations

import asyncio
import secrets
import ssl
from collections.abc import AsyncIterator
from pathlib import Path

import pytest
import pytest_asyncio


@pytest.fixture(scope="session", autouse=True)
def require_psk() -> None:
    assert ssl.HAS_PSK, "transport regressions require a Python/OpenSSL build with PSK"


@pytest.fixture
def key() -> bytes:
    return secrets.token_bytes(32)


@pytest.fixture
def certificate() -> Path:
    return Path(__file__).parent / "data" / "server-cert.pem"


@pytest_asyncio.fixture
async def certificate_server(certificate: Path) -> AsyncIterator[tuple[int, list[bool]]]:
    """A real TLS server that declines PSK and offers a test-only certificate."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.load_cert_chain(certificate, certificate.with_name("server-key.pem"))
    context.set_psk_server_callback(lambda _identity: b"")
    context.num_tickets = 0
    accepted: list[bool] = []

    def accept(_reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        accepted.append(writer.get_extra_info("ssl_object").session_reused)
        writer.close()

    server = await asyncio.start_server(
        accept,
        "127.0.0.1",
        0,
        ssl=context,
        ssl_handshake_timeout=2,
        ssl_shutdown_timeout=1,
    )
    try:
        yield server.sockets[0].getsockname()[1], accepted
    finally:
        server.close()
        server.close_clients()
        await server.wait_closed()
