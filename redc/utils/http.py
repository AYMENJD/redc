from urllib.parse import urlparse


def parse_base_url(url: str) -> str:
    res = urlparse(url)

    if not res.scheme:
        raise ValueError("URL is missing a scheme (e.g., 'http://' or 'https://')")
    if not res.netloc:
        raise ValueError("URL is missing a network location (e.g., 'example.com')")

    return f"{url.rstrip('/')}/"
