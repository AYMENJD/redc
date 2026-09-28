# TLS

Verification is on unless you turn it off.

```python
await client.get("https://example.com", verify=True)
```

`verify=False` skips both the certificate check and the hostname check. Use it against a machine you trust, not against the public internet.

`cert` is a CA bundle, a PEM file, used to check the server. It is not a client certificate. `None` uses the trustifi bundle that ships with the package.

## Version

`tls_version` is the minimum: this version or anything newer. `tls_version_max` is the cap.

```python
async with Client(tls_version="1.2") as client:
    await client.get("https://example.com")                          # 1.2 or later
    await client.get("https://example.com", tls_version="1.3")       # 1.3 or later
    await client.get(
        "https://example.com",
        tls_version="1.2",
        tls_version_max="1.2",
    )                                                                 # 1.2 only
```

The values are `"default"`, `"1.0"`, `"1.1"`, `"1.2"`, and `"1.3"`. `"default"` means TLS 1.2 or newer.

A minimum newer than the maximum raises `ValueError` before the request is sent.

There is no SSL 2 or SSL 3. Those protocols are retired.
