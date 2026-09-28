<div align="center">

<img src="https://raw.githubusercontent.com/AYMENJD/redc/refs/heads/main/assets/images/redc-logo.svg" alt="RedC" width="500">

Async HTTP client for Python with **native libcurl** performance.

[![PyPI version](https://img.shields.io/pypi/v/redc?style=flat&logo=curl&logoColor=red&color=red)](https://pypi.org/project/RedC)
[![Curl version](https://img.shields.io/badge/Curl-v8.21.0-red?logo=curl)](https://curl.se/ch/8.21.0.html)
[![Build status](https://img.shields.io/github/actions/workflow/status/AYMENJD/redc/build_wheels.yml?label=CI+wheels&logo=github)](https://github.com/AYMENJD/redc/actions)
[![Python versions](https://img.shields.io/pypi/pyversions/redc?style=flat&logo=python)](https://www.python.org)
[![Docs](https://img.shields.io/badge/Documentation-229ED9?style=flat)](https://red-c.pages.dev)
[![Downloads](https://img.shields.io/pepy/dt/RedC?style=flat&logo=pypi)](https://pypi.org/project/RedC)
[![Support with TON](https://img.shields.io/badge/Support%20with-TON-0098EA?style=for-the-badge&logo=ton)](https://cupofton.pages.dev/donate?a=UQCeySURtYxvqF2jNXlsFrXuTEqPjJhGx8uoev6tUbD_HELL&n=AYMEN&t=5&c=You+deserve+a+Cup+of+TON+for+RedC%2521)

</div>

#

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
