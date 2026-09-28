# URL

`CurlURL` reads and edits a URL. It does not send a request.

```python
from redc import CurlURL

u = CurlURL("https://user:pass@example.com:8080/path?q=1#frag")
u.query = None
u.port = 443
print(str(u))
# https://user:pass@example.com:443/path#frag
```

The parts are `scheme`, `user`, `password`, `options`, `host`, `zoneid`, `port`, `path`, `query`, and `fragment`. A missing part is `None`. `port` is an `int`.

```python
u["host"] = "example.org"
host = u.get("host", punycode=True)
print(u.parts())
```

`CurlURL.is_valid_url` only checks the string. It returns false when the URL is not valid.

```python
CurlURL.is_valid_url("https://example.com")  # True
CurlURL.is_valid_url("::::invalid::::")      # False
```
