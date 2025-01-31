<div align="center">
  <img src="/assets/images/redc-logo.png">
</div>

[![Version](https://img.shields.io/pypi/v/redc?style=flat&logo=curl&logoColor=red&color=red)](https://pypi.org/project/RedC) [![Downloads](https://static.pepy.tech/personalized-badge/redc?period=month&units=none&left_color=grey&right_color=brightgreen&left_text=Downloads)](https://pepy.tech/project/redc)

**RedC** is a **high-performance**, asynchronous **HTTP** client library for **Python**, built on top of the powerful **curl** library. It provides a simple and intuitive interface for making HTTP requests and handling responses

## Features

- **Asynchronous by Design**: Built with `asyncio` for non-blocking HTTP requests
- **curl Backend**: Leverages the speed and reliability of libcurl for HTTP operations
- **Streaming Support**: Stream large responses with ease using callback functions
- **Proxy Support**: Easily configure proxies for your requests

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
        print(response.status_code)  # 200
        print(response.json())  # {'userId': 1, 'id': 1, 'title': '...', 'body': '...'}

        # Make a POST request with JSON data
        response = await client.post(
            "/posts",
            json={"title": "foo", "body": "bar", "userId": 1},
        )
        print(response.status_code)  # 201
        print(response.json())  # {'id': 101, ...}

asyncio.run(main())
```

## License

MIT [LICENSE](LICENSE)
