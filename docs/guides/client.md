# Client

A `Client` is what you keep open. Requests made with it share connections. Turn on `persist_cookies` and they share cookies too.

```python
async with Client(
    base_url="https://api.example.com",
    headers={"Accept": "application/json"},
    timeout=(10.0, 3.0),
) as client:
    await client.get("/v1/items")
```

## Defaults

| Argument | Default | What it does |
| --- | --- | --- |
| `http_version` | `"3"` | Try HTTP/3, then fall back to what the server supports. |
| `tls_version` | `"default"` | TLS 1.2 or newer. |
| `keep_alive` | `True` | Reuse the connection. `False` closes it when the response arrives. |
| `timeout` | `(30.0, 0.0)` | Seconds for the whole request, then a separate limit for connecting. `0` means no extra connect limit. |
| `persist_cookies` | `False` | Remember cookies for later requests on this client. |
| `ip_version` | `"any"` | `"4"` or `"6"` limits which addresses a hostname may use. |
| `backend` | `"asyncio"` | `"threaded"` runs the network work on a background thread. |
| `raise_for_status` | `False` | When `True`, a bad status raises before you see the response. |

Connection limits, if you need them: 1024 connections in total, 64 to one host, 2048 kept idle. The pool of workers starts at 16 and grows to 512. Leave these alone unless you have a reason.

`read_buffer_size` is how much of a response is read at once. The default is 16 KiB. It must be greater than 1024.

## Per request

The same names work on `get`, `post`, and the other methods. `None` uses the client value. That covers `http_version`, `tls_version`, `tls_version_max`, `interface`, `unix_socket`, `ip_version`, `no_proxy`, `keep_alive`, and `timeout`.

An empty string is a real override. `interface=""` does not pick a local address. `unix_socket=""` uses a normal connection. `no_proxy=""` sends every host through the proxy.

## asyncio or threaded

`"asyncio"` is the default. `"threaded"` moves the network work onto a background thread. Use it when your event loop cannot watch RedC’s sockets. The methods you call are the same.
