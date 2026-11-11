from __future__ import annotations

import asyncio
import struct
from types import TracebackType

MAX_MESSAGE = 65_536
_HEADER = struct.Struct("!I")


class MessageTooLarge(ValueError):
    """A message exceeds the channel's 64 KiB limit."""


class Channel:
    """One reader and serialized writers on a length-prefixed byte stream."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self._reader = reader
        self._writer = writer
        self._send_lock = asyncio.Lock()

    async def send(self, message: bytes) -> None:
        """Send one message; concurrent senders cannot interleave frames."""
        if len(message) > MAX_MESSAGE:
            raise MessageTooLarge("message exceeds 64 KiB")
        async with self._send_lock:
            self._writer.write(_HEADER.pack(len(message)) + message)
            await self._writer.drain()

    async def receive(self) -> bytes:
        """Read one message. Only one task may receive at a time."""
        header = await self._reader.readexactly(_HEADER.size)
        (length,) = _HEADER.unpack(header)
        if length > MAX_MESSAGE:
            self._writer.close()
            raise MessageTooLarge("peer message exceeds 64 KiB; channel closed")
        return await self._reader.readexactly(length)

    async def close(self) -> None:
        """Close the stream, bounded by its configured TLS shutdown timeout."""
        self._writer.close()
        try:
            await self._writer.wait_closed()
        except (ConnectionError, TimeoutError):
            # A disconnected peer cannot acknowledge TLS shutdown.
            pass

    async def __aenter__(self) -> Channel:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        await self.close()
