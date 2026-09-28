# Errors

Two failures look different.

An HTTP status is still a `Response`. `raise_for_status()` raises `HTTPError` when the status is 400–599. The response is false outside 2xx, and also when the connection failed.

```python
response = await client.get("/missing")
if not response.ok:
    print(response.status_code, response.reason)
```

A connection failure sets `status_code` to `-1`. `raise_for_status()` then raises a specific error: `CouldntConnectError`, `CouldntResolveHostError`, `OperationTimedoutError`, `InterfaceFailedError`, `SslConnectErrorError`, or `UnsupportedProtocolError`. `curl_code` is the numeric code. `curl_error_message` is the message.

```python
from redc.exceptions import CouldntConnectError, OperationTimedoutError

try:
    await client.get("https://example.com", timeout=(5.0, 2.0))
except OperationTimedoutError as exc:
    print(exc)
except CouldntConnectError as exc:
    print(exc)
```

`UnsupportedProtocolError` is what you get for a scheme other than `http`, `https`, or `file`, and for a redirect that leaves HTTP.

`timeout=(total, connect)` is in seconds. The connect value is the cap for the dial. The total covers the whole transfer, including the body.
