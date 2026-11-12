# clavem

Small async TLS-PSK message channels. Python 3.13+, no third-party runtime dependencies.

Clavem authenticates peers with a shared random key and carries length-prefixed byte
messages over one TLS 1.3 connection. It does not reconnect, schedule heartbeats,
serialize application data, or configure logging.

## Install

```bash
pip install clavem
```

For an unpublished checkout, use `uv sync` and `uv run` instead. Both endpoints
need a Python/OpenSSL build with PSK support:

```bash
python -c "import ssl; print(ssl.OPENSSL_VERSION, ssl.HAS_PSK)"
```

`HAS_PSK` must be `True`. Check this on the exact interpreter used for deployment
and on the interpreter bundled into a desktop executable.

## Connect and exchange messages

Create one 32-byte random key and securely provision the same bytes on both peers.
Use a different key for unrelated services. The identity is public, not a password.

```python
import asyncio
from pathlib import Path

from clavem.transport import connect


async def main() -> None:
    key = Path("psk.bin").read_bytes()
    async with await connect("127.0.0.1", 9443, identity="home", key=key) as channel:
        await channel.send(b"hello")
        reply = await channel.receive()
        print(reply)


asyncio.run(main())
```

One task receives messages; multiple tasks may send, with complete frames serialized
by the channel. TCP_NODELAY is enabled on both peers: the client uses asyncio's
default, and the server explicitly enables it on accepted TLS sockets. Messages
can be empty and are limited to 65,536 bytes. The wire format is a four-byte
unsigned network-order length followed by that many bytes.

## Serve

```python
import asyncio
from pathlib import Path

from clavem.channel import Channel
from clavem.transport import serve


async def echo(channel: Channel) -> None:
    while True:
        await channel.send(await channel.receive())


async def main() -> None:
    key = Path("psk.bin").read_bytes()
    async with serve(echo, "127.0.0.1", 9443, keys={"home": key}):
        await asyncio.Event().wait()


asyncio.run(main())
```

`serve()` owns accepted channels and handler tasks. Returning from a handler closes
its channel. Leaving the server context closes the listener and cancels and awaits
remaining handlers, including pending TLS handshakes. Peer disconnects, TLS errors,
I/O timeouts, and oversized frames close only the affected connection. Unexpected
handler exceptions stop the server and propagate through its task group.
To run until cancelled, wait for an application stop signal inside this context,
as above. Avoid awaiting the raw server's `serve_forever()`: its cancellation waits
for active connections before Clavem can clean up the handlers.

## Contract

| API | Behavior |
| --- | --- |
| `connect(..., timeout=5, io_timeout=30)` | Bounds TCP connection and TLS authentication together; sets per-operation I/O deadlines. Returns a `Channel`. |
| `serve(..., handshake_timeout=5, io_timeout=30, max_connections=64)` | Bounds handshakes and channel I/O; caps admitted connections. Yields an `asyncio.Server`. |
| `Channel.send(bytes)` | Checks the size before writing; the I/O deadline includes waiting for other senders and stream backpressure. |
| `Channel.receive()` | Reads a complete frame within one I/O deadline; EOF raises `asyncio.IncompleteReadError`. |
| `Channel.close()` | Closes the stream; supported by `async with channel`. |
| `client_context()` / `server_context()` | TLS contexts for applications that need lower-level asyncio integration. |

An oversized incoming frame raises `clavem.channel.MessageTooLarge` and closes
the stream. An oversized outgoing message raises the same error before writing.
Network, TLS, and timeout exceptions retain their standard-library types at the
channel API. A timed-out operation raises `TimeoutError`; cancelling or timing out
a send or receive aborts the channel immediately, so a partial exchange cannot be
reused. The `serve()` connection task handles expected peer errors as described
above; unexpected handler exceptions propagate in an exception group.

TLS contexts require external PSK authentication. The client loads no trusted CAs,
the server loads no certificate and issues no session tickets, and the transport
checks that PSK authentication was negotiated. There is no plaintext fallback.
Connection, handshake, and I/O timeouts must be finite and positive. `io_timeout`
defaults to 30 seconds for each `send()` or `receive()` call, including an idle
receive and the entire header/body exchange. Receiving a fragment does not restart
the deadline. Configure it on `connect()`, `serve()`, or a directly constructed
`Channel`; applications may use an outer `asyncio.timeout()` for a shorter deadline
covering a complete request/reply exchange.

`max_connections` is a positive integer, defaulting to 64. It counts admitted
connections from before TLS negotiation until their handshake/handler cleanup
finishes. Excess connections are closed immediately before starting TLS, without
adding a waiting queue or a handler task. TLS starts immediately after admission;
application handlers only receive authenticated channels. A disconnect, failed
handshake, timeout, or handler completion releases its slot. The operating system's
TCP listen backlog is separate from this application connection limit.
