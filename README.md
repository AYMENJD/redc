<p align="center">
  <img src="https://raw.githubusercontent.com/AYMENJD/redc/refs/heads/main/assets/images/redc-logo.svg" width="500" alt="RedC logo" />
  <br/><br/>
  Async HTTP client for Python with <strong>native libcurl</strong> performance.
  <br/><br/>

  <a href="https://pypi.org/project/RedC">
    <img src="https://img.shields.io/pypi/v/redc?style=flat&logo=curl&logoColor=red&color=red" alt="PyPI version">
  </a>
  <a href="https://curl.se/ch/8.19.0.html">
    <img src="https://img.shields.io/badge/Curl-v8.19.0-red?logo=curl" alt="Curl version">
  </a>
  <a href="https://github.com/AYMENJD/redc/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/AYMENJD/redc/build_wheels.yml?label=CI+wheels&logo=github" alt="Build status">
  </a>
  <a href="https://www.python.org">
    <img src="https://img.shields.io/pypi/pyversions/redc?style=flat&logo=python" alt="Python versions" />
  </a>
  <a href="https://pypi.org/project/RedC">
    <img src="https://img.shields.io/pypi/dm/RedC?style=flat&logo=pypi" alt="Downloads"/>
  </a>
</p>

### Features

- **Protocols**: Supports **HTTP/1.1**, **HTTP/2**, and **HTTP/3**
- **curl-powered**: Built on top of **libcurl** for **performance and reliability**
- **Streaming**: Efficient handling of large responses
- **Proxying**: Simple and flexible proxy configuration
- **Google CA Trust**: Uses [**trustifi**](https://github.com/AYMENJD/trustifi) as the default TLS trust store

## Installation

You can install RedC via pip:

```bash
pip install redc
```

## Quick Start

```python
import asyncio
from redc import Client

async def main():
    async with Client(base_url="https://jsonplaceholder.typicode.com") as client:
        # Make a GET request
        response = await client.get("/posts/1")
        response.raise_for_status()
        print(response.status_code)  # 200
        print(response.json())  # {'userId': 1, 'id': 1, 'title': '...', 'body': '...'}

        # Make a POST request with JSON data
        response = await client.post(
            "/posts",
            json={"title": "foo", "body": "bar", "userId": 1},
        )
        response.raise_for_status()
        print(response.status_code)  # 201
        print(response.json())  # {'id': 101, ...}

asyncio.run(main())
```

## URL Utilities

RedC includes a high-performance URL parser powered by libcurl.

```python
from redc import CurlURL

u = CurlURL("https://user:pass@example.com:8080/path?q=1#frag")

print(u.host)   # example.com
print(u.port)   # 8080
print(u.path)   # /path

u.query = None
u["port"] = 443

print(str(u))
# https://user:pass@example.com:443/path#frag
```

Validate URLs:

```python
from redc import CurlURL

print(CurlURL.is_valid_url("https://example.com"))  # True
print(CurlURL.is_valid_url("::::invalid::::"))      # False
```

## License

MIT [LICENSE](https://github.com/AYMENJD/redc/blob/main/LICENSE)
