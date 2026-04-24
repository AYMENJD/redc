import pytest
from redc import CurlURL

URL = "https://user:pass@example.com:8080/path/to/resource?q=hello%20world&x=1#fragment"


def test_parse_basic():
    u = CurlURL(URL)

    assert u.scheme == "https"
    assert u.user == "user"
    assert u.password == "pass"
    assert u.host == "example.com"
    assert u.port == 8080
    assert u.path == "/path/to/resource"
    assert u.query == "q=hello%20world&x=1"
    assert u.fragment == "fragment"


def test_str_and_repr():
    u = CurlURL(URL)

    assert str(u).startswith("https://user:pass@example.com")
    assert "<CurlURL '" in repr(u)


def test_set_properties():
    u = CurlURL(URL)

    u.scheme = "http"
    u.host = "test.com"
    u.port = 443
    u.path = "/new"
    u.query = "a=1"
    u.fragment = "frag"

    assert u.scheme == "http"
    assert u.host == "test.com"
    assert u.port == 443
    assert u.path == "/new"
    assert u.query == "a=1"
    assert u.fragment == "frag"


def test_remove_properties():
    u = CurlURL(URL)

    u.query = None
    u.fragment = None
    u.user = None
    u.password = None

    assert u.query is None
    assert u.fragment is None
    assert u.user is None
    assert u.password is None


def test_getitem():
    u = CurlURL(URL)

    assert u["host"] == "example.com"
    assert u["port"] == 8080


def test_setitem():
    u = CurlURL(URL)

    u["host"] = "abc.com"
    u["port"] = 1234

    assert u.host == "abc.com"
    assert u.port == 1234


def test_is_valid_url():
    assert CurlURL.is_valid_url("https://example.com")
    assert CurlURL.is_valid_url("http://user:pass@host:8080/path?q=1#frag")
    assert CurlURL.is_valid_url("http:///missing-host")

    assert not CurlURL.is_valid_url("https://example.com/path with space")
    assert not CurlURL.is_valid_url("::::invalid::::")
    assert not CurlURL.is_valid_url("")


def test_setitem_none():
    u = CurlURL(URL)

    u["query"] = None
    assert u.query is None


def test_invalid_key():
    u = CurlURL(URL)

    with pytest.raises(KeyError):
        _ = u["invalid"]

    with pytest.raises(KeyError):
        u["invalid"] = "x"


def test_get_basic():
    u = CurlURL(URL)

    assert u.get("host") == "example.com"
    assert u.get("port") == 8080


def test_get_decode():
    u = CurlURL(URL)

    decoded = u.get("query", decode=True)
    assert "hello world" in decoded


def test_get_encode():
    u = CurlURL("https://example.com/path%20with%20space")

    encoded = u.get("path", encode=True)
    assert "%20" in encoded


def test_get_empty_flag():
    u = CurlURL("https://example.com")

    val = u.get("query", empty=True)
    assert val in (None, "")


def test_parts():
    u = CurlURL(URL)

    parts = u.parts()

    assert parts["scheme"] == "https"
    assert parts["host"] == "example.com"
    assert parts["port"] == 8080
    assert "query" in parts


def test_reset():
    u = CurlURL(URL)

    u.reset("http://test.com")

    assert u.scheme == "http"
    assert u.host == "test.com"
    assert u.port is None


def test_missing_parts():
    u = CurlURL("https://example.com")

    assert u.user is None
    assert u.password is None
    assert u.query is None
    assert u.fragment is None
    assert u.port is None


def test_empty_constructor():
    u = CurlURL()

    assert u.scheme is None
    assert u.host is None


def test_invalid_url():
    with pytest.raises(Exception):
        CurlURL("::::invalid::::")


def test_port_set_and_remove():
    u = CurlURL(URL)

    u.port = 123
    assert u.port == 123

    u.port = None
    assert u.port is None


def test_unicode_host():
    u = CurlURL("https://example.com")

    u.host = "tést.com"
    assert u.host is not None


def test_repeated_usage():
    for _ in range(1000):
        u = CurlURL(URL)
        assert u.host == "example.com"
