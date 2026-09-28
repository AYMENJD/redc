# Response

A finished transfer is a `Response`. The body is `content` (`bytes`), `text` (decoded), or `json()`.

```python
response = await client.get("/get")
if response:
    payload = response.json()
```

`status_code` is `-1` when the request never got an HTTP response. `curl_code` and `curl_error_message` say why. `reason` is the usual phrase for the status (`"OK"`, `"Not Found"`).

`url` is the final URL after redirects. `http_version` is the version that was used (`"1.1"`, `"2"`, `"3"`), which can be lower than the one you asked for. `history` is the redirect chain. `redirect_count` is its length. `cookies` is the `Set-Cookie` values from that chain. The last write wins for a repeated name.

## Where it connected

| Field | Meaning |
| --- | --- |
| `primary_ip`, `primary_port` | The address the request connected to. |
| `local_ip`, `local_port` | The local side of that socket. |

On a failed transfer these are empty strings and `0`.

## Time

Each time starts when the request starts, except `tls_time`, which is only the handshake.

| Field | What it counts |
| --- | --- |
| `dns_time` | Through name lookup. |
| `connect_time` | Through the TCP connect. |
| `tls_time` | The TLS handshake alone. |
| `first_byte_time` | Until the first response byte. Includes DNS, connect, and TLS. |
| `redirect_time` | Redirects before the final transfer. `0` when there were none. |
| `elapsed` | The whole transfer. |

Each has a `_us` form in microseconds (`first_byte_time_us`, `elapsed_us`). The name without `_us` is seconds.

`download_size` and `upload_size` are bytes. `download_speed` and `upload_speed` are bytes per second.

A body kept in memory is capped at 16 MiB. Past that, use a [stream callback](streaming.md). The callback receives the bytes. `content` is then empty.
