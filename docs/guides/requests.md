# Requests

`get`, `head`, `post`, `put`, `patch`, `delete`, and `options` all call `request`. The method is the only difference.

```python
await client.get("/search", params={"q": "redc"})
await client.post("/items", json={"name": "widget"})
await client.post("/upload", files={"file": ("notes.txt", data, "text/plain")})
```

## Body

`json` encodes the value and sets `Content-Type: application/json`. `data` is a raw `bytes` or `str` body. `files` is a multipart upload. A file value is bytes, or a tuple `(filename, file, content_type)`. The file object can be a `BytesIO`.

Do not pass `json` and `data` on the same call.

## Headers, query, cookies

`headers` merges over the client headers. `params` is the query string. `cookies` is a dict sent as `Cookie`.

With `persist_cookies=True`, `Set-Cookie` from one response is stored on the client and sent on the next request to that host.

## Auth

A tuple is username and password. The default scheme is Basic. Pass the scheme as the third item: `"digest"`, `"digest_ie"`, `"ntlm"`, or `"any"`.

A string is a bearer token:

```python
await client.get("/me", auth="secret-token")
await client.get("/me", auth=("user", "pass", "digest"))
```

## Redirects

`allow_redirects=True` follows up to 30 redirects. A number sets that limit. `False` returns the redirect itself.

The method you set is sent again after a redirect, including on 301, 302, and 303. On 307 and 308 the body is sent again too. A redirect can only go to `http` or `https`. A redirect to a file raises `UnsupportedProtocolError`.

## The URL you pass

The request itself may be `http`, `https`, or `file`:

```python
await client.get("file:///tmp/notes.txt")
```

`file://` reads the local file. It is not an HTTP response from a server, and a redirect cannot turn into one.
