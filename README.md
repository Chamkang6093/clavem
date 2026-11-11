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
from pathlib import Path
import asyncio

from clavem.transport import connect


async def main() -> None:
    key = Path("psk.bin").read_bytes()
    async with await connect("127.0.0.1", 9443, identity="home", key=key) as channel:
        await channel.send(b"hello")
        async with asyncio.timeout(5):
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
from pathlib import Path
import asyncio

from clavem.channel import Channel
from clavem.transport import serve


async def echo(channel: Channel) -> None:
    try:
        while True:
            async with asyncio.timeout(30):
                message = await channel.receive()
                await channel.send(message)
    except (asyncio.IncompleteReadError, ConnectionError, TimeoutError):
        return


async def main() -> None:
    key = Path("psk.bin").read_bytes()
    async with serve(echo, "127.0.0.1", 9443, keys={"home": key}) as server:
        await server.serve_forever()


asyncio.run(main())
```

`serve()` owns accepted channels and handler tasks. Returning from a handler closes
its channel. Leaving the server context closes the listener and cancels and awaits
remaining handlers. Handle expected peer disconnects in your handler; unexpected
handler exceptions stop the server and propagate through its task group.

## Contract

| API | Behavior |
| --- | --- |
| `connect(..., timeout=5)` | Bounds TCP connection and TLS authentication together. Returns a `Channel`. |
| `serve(..., handshake_timeout=5)` | Async context manager yielding an `asyncio.Server`. |
| `Channel.send(bytes)` | Checks the size before writing and applies stream backpressure. |
| `Channel.receive()` | Reads a complete frame; EOF raises `asyncio.IncompleteReadError`. |
| `Channel.close()` | Closes the stream; supported by `async with channel`. |
| `client_context()` / `server_context()` | TLS contexts for applications that need lower-level asyncio integration. |

An oversized incoming frame raises `clavem.channel.MessageTooLarge` and closes
the stream. An oversized outgoing message raises the same error before writing.
Network, TLS, and timeout exceptions retain their standard-library types. After
cancelling or timing out an in-progress receive or send, close the channel rather
than trying to reuse a potentially partial exchange.

TLS contexts require external PSK authentication. The client loads no trusted CAs,
the server loads no certificate and issues no session tickets, and the transport
checks that PSK authentication was negotiated. There is no plaintext fallback.
Clavem sets neither application idle timeouts nor connection-count limits; the
hosting application owns those policies.
