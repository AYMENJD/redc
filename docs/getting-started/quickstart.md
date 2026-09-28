# Quick start

Open one client and keep it. Creating a `Client` per request throws away the connection cache.

```python
import asyncio
from redc import Client

async def main():
    async with Client(base_url="https://jsonplaceholder.typicode.com") as client:
        post = await client.get("/posts/1")
        post.raise_for_status()
        print(post.json()["title"])

        created = await client.post(
            "/posts",
            json={"title": "foo", "body": "bar", "userId": 1},
        )
        created.raise_for_status()
        print(created.status_code)

asyncio.run(main())
```

`base_url` is joined in front of a relative path. A full URL ignores it.

`raise_for_status()` raises `HTTPError` for status 400–599. If the connection failed, `status_code` is `-1` and the same call raises a `CurlError`.

A `Response` is true when the status is 2xx:

```python
if response:
    data = response.json()
```

The client closes when the `async with` block ends.

Next: [Client](../guides/client.md).
