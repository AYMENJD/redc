---
hide:
  - navigation
  - toc
---

<div class="hero" markdown>

# ![RedC](assets/redc-logo.svg){ .wordmark }

<p class="lede">Async HTTP for Python. Connections stay open. Your event loop stays free.</p>

```bash
pip install redc
```

[Quick start](getting-started/quickstart.md){ .md-button .md-button--primary }
[Client](guides/client.md){ .md-button }

</div>

<div class="home-first" markdown>

## One client, many requests

Keep one `Client` for the work you are doing. The next request to the same server reuses the connection, so it does not pay for a new handshake.

```python
import asyncio
from redc import Client

async def main():
    async with Client(base_url="https://example.com") as client:
        response = await client.get("/get")
        response.raise_for_status()
        print(response.status_code, response.first_byte_time)

asyncio.run(main())
```

HTTP/3 is the default. If the server does not offer it, the request uses HTTP/2 or HTTP/1.1. Certificates are checked with [trustifi](https://github.com/AYMENJD/trustifi).

</div>

<div class="home-map" markdown>

<div markdown>

## Start

Install the wheel, then make one request.

[Install](getting-started/installation.md)  
[Quick start](getting-started/quickstart.md)

</div>

<div markdown>

## Use it

The client, the request, the response.

[Client](guides/client.md)  
[Requests](guides/requests.md)  
[Response](guides/response.md)  
[URL](guides/url.md)  
[Streaming](guides/streaming.md)

</div>

<div markdown>

## Control the connection

TLS, the local address, proxies, sockets.

[TLS](guides/tls.md)  
[Connections](guides/connections.md)  
[Errors](guides/errors.md)

</div>

</div>
