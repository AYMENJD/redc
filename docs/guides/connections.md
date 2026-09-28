# Connections

These arguments choose the socket. They are client defaults, and a request can override them.

## Local address

`interface` is the local side of the connection. Pass a network interface (`eth0`), an IP address, or a more specific form: `if!eth0` for the interface, `host!192.0.2.10` for the address, `ifhost!eth0!192.0.2.10` for both. A hostname here waits on DNS, so pass a name or an address. On Windows, use an IP address. Interface names are ignored there.

`ip_version` is `"any"`, `"4"`, or `"6"`. It limits which addresses of a hostname may be used, including when a pooled connection is reused. A URL that is already a numeric address is used as written.

```python
async with Client(interface="eth0", ip_version="4") as client:
    await client.get("https://example.com", interface="")  # this call does not bind
```

Binding to an address the machine does not have raises `InterfaceFailedError`.

## Proxy

`proxy_url` is per request. `http://user:pass@proxy:8080` is enough for proxy authentication.

`no_proxy` is the list of hosts that skip the proxy. Separate them with commas. `example.com` also matches `www.example.com`, and it does not match `example.com.org`. A network such as `192.168.0.0/16` matches every address in it. `*` skips the proxy for every host.

```python
async with Client(no_proxy="localhost,127.0.0.1") as client:
    await client.get("https://example.com", proxy_url="http://proxy:8080")
    await client.get("http://127.0.0.1:8080", proxy_url="http://proxy:8080")  # direct
```

Leave `no_proxy` as `None` and RedC honors the `no_proxy` or `NO_PROXY` environment variable, when one is set. `""` ignores that variable and sends every host through the proxy.

## Unix sockets

`unix_socket` connects to a filesystem socket instead of the host in the URL. The URL still supplies the request path and the `Host` header. A proxy is not used for that transfer.

```python
async with Client(unix_socket="/var/run/docker.sock") as client:
    info = await client.get("http://localhost/v1.41/info")
```

`unix_socket=""` on a request goes back to TCP. The path limit is 107 bytes on Linux.

## What may be requested

A request can use `http`, `https`, or `file`. A redirect can use `http` or `https` only. Anything else is rejected.
