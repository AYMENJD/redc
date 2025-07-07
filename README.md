<div align="center">
  <img src="https://raw.githubusercontent.com/AYMENJD/redc/refs/heads/main/assets/images/redc-logo.png">
</div>

[![Version](https://img.shields.io/pypi/v/redc?style=flat&logo=curl&logoColor=red&color=red)](https://pypi.org/project/RedC) [![CURL version](https://img.shields.io/badge/Curl-v8.14.1-red?logo=curl)](https://curl.se/ch/8.14.1.html) [![Downloads](https://static.pepy.tech/personalized-badge/redc?period=month&units=none&left_color=grey&right_color=brightgreen&left_text=Downloads)](https://pepy.tech/project/redc)

**RedC** is a **high-performance**, asynchronous **HTTP** client library for **Python**, built on top of the powerful **curl** library. It provides a simple and intuitive interface for making HTTP requests and handling responses

## Features

-   **Asynchronous by Design**: Built with `asyncio` for non-blocking HTTP requests
-   **HTTP/2 Support**: Fully compatible with `HTTP/2` for faster and more efficient communication
-   **curl Backend**: Leverages the speed and reliability of curl for HTTP operations
-   **Streaming Support**: Stream large responses with ease using callback functions
-   **Proxy Support**: Easily configure proxies for your requests

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

## License

MIT [LICENSE](https://github.com/AYMENJD/redc/blob/main/LICENSE)
