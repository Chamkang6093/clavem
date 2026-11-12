from __future__ import annotations

import asyncio
import math
import ssl
import struct
from types import TracebackType

MAX_MESSAGE = 65_536
_HEADER = struct.Struct("!I")


def _validate_timeout(value: float, name: str) -> None:
    if not math.isfinite(value) or value <= 0:
        raise ValueError(f"{name} must be finite and positive")


class MessageTooLarge(ValueError):
    """A message exceeds the channel's 64 KiB limit."""


class Channel:
    """One reader and serialized writers on a length-prefixed byte stream."""

    def __init__(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, *, io_timeout: float = 30
    ) -> None:
        _validate_timeout(io_timeout, "io_timeout")
        self._reader: asyncio.StreamReader = reader
        self._writer: asyncio.StreamWriter = writer
        self._send_lock: asyncio.Lock = asyncio.Lock()
        self._io_timeout = io_timeout
        self._closed = False

    def _abort(self) -> None:
        self._closed = True
        self._writer.transport.abort()

    async def send(self, message: bytes) -> None:
        """Send one message; concurrent senders cannot interleave frames."""
        if len(message) > MAX_MESSAGE:
            raise MessageTooLarge("message exceeds 64 KiB")
        try:
            async with asyncio.timeout(self._io_timeout), self._send_lock:
                if self._closed or self._writer.is_closing():
                    raise ConnectionError("channel is closed")
                self._writer.write(_HEADER.pack(len(message)) + message)
                await self._writer.drain()
        except (TimeoutError, asyncio.CancelledError):
            self._abort()
            raise

    async def receive(self) -> bytes:
        """Read one message. Only one task may receive at a time."""
        if self._closed:
            raise ConnectionError("channel is closed")
        try:
            async with asyncio.timeout(self._io_timeout):
                header = await self._reader.readexactly(_HEADER.size)
                (length,) = _HEADER.unpack(header)
                if length > MAX_MESSAGE:
                    self._abort()
                    raise MessageTooLarge("peer message exceeds 64 KiB; channel closed")
                return await self._reader.readexactly(length)
        except (TimeoutError, asyncio.CancelledError):
            self._abort()
            raise

    async def close(self) -> None:
        """Close the stream, bounded by its configured TLS shutdown timeout."""
        self._closed = True
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except (ConnectionError, ssl.SSLError, TimeoutError):
            # A disconnected peer cannot acknowledge TLS shutdown.
            pass
        except asyncio.CancelledError:
            self._abort()
            raise

    async def __aenter__(self) -> Channel:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()
