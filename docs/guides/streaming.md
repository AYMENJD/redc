# Streaming

A body kept on the response is limited to 16 MiB. For anything larger, pass a `StreamCallback`. The function must be a normal function, not `async`. It is called as each piece arrives.

```python
from redc import Client, StreamCallback

def on_chunk(data: bytes, size: int) -> None:
    out.write(data)

async with Client() as client:
    await client.get(
        "https://example.com/large.bin",
        stream_callback=StreamCallback(on_chunk),
    )
```

The callback takes `(data, size)`. It cannot be a coroutine. While it runs, the body is not stored. `response.content` is empty. Raising from the callback aborts the transfer.

`ProgressCallback` reports byte counts. It is also synchronous, and it takes four integers: download total, download so far, upload total, upload so far.

```python
from redc import ProgressCallback

def on_progress(dltotal: int, dlnow: int, ultotal: int, ulnow: int) -> None:
    if dltotal:
        print(dlnow, dltotal)

await client.get(url, progress_callback=ProgressCallback(on_progress))
```

`dltotal` and `ultotal` stay `0` until the size is known.

`verbose=True` stores the debug log on `response.verbose`. It is not a second copy of the body.
