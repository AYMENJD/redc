from ..redc_ext_url import CurlURL


def parse_base_url(url: str) -> str:
    u = CurlURL(url)

    if not u.scheme:
        raise ValueError("URL is missing a scheme (e.g., 'http://' or 'https://')")
    if not u.host:
        raise ValueError("URL is missing a network location (e.g., 'example.com')")

    return f"{url.rstrip('/')}/"
