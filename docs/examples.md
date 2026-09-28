# Examples

## JSON API

```python
import asyncio
from redc import Client

async def main():
    async with Client(
        base_url="https://jsonplaceholder.typicode.com",
        timeout=(10.0, 3.0),
        raise_for_status=True,
    ) as client:
        posts = await client.get("/posts", params={"userId": 1})
        for post in posts.json()[:3]:
            print(post["id"], post["title"])

asyncio.run(main())
```

## Pin TLS 1.2 and a source address

```python
async with Client(
    tls_version="1.2",
    tls_version_max="1.2",
    ip_version="4",
    interface="192.0.2.10",
) as client:
    page = await client.get("https://example.com")
    print(page.primary_ip, page.http_version, page.first_byte_time)
```

## Talk to a local socket

The URL is still HTTP. The connection is the socket file.

```python
async with Client(unix_socket="/var/run/docker.sock", http_version="1.1") as client:
    info = await client.get("http://localhost/v1.41/info")
    info.raise_for_status()
```

## Read a local file

```python
async with Client() as client:
    notes = await client.get("file:///tmp/notes.txt")
    print(notes.content)
```

A redirect cannot do this. Only the URL you pass may be `file://`.

## Stream a large body

```python
from redc import StreamCallback

chunks = []

def collect(data: bytes, size: int) -> None:
    chunks.append(data)

async with Client() as client:
    await client.get(
        "https://example.com/large.bin",
        stream_callback=StreamCallback(collect),
    )

body = b"".join(chunks)
```

Without the callback, a body over 16 MiB aborts the transfer.
