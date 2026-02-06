import pytest
from redc.exceptions import (
    CouldntConnectError,
    HTTPError,
    UnsupportedProtocolError,
    UrlMalformatError,
)


async def test_empty_url(client_with_no_base):
    with pytest.raises(ValueError):
        await client_with_no_base.get("")


async def test_url_malformed(client_with_no_base):
    with pytest.raises(UrlMalformatError):
        await client_with_no_base.get("!!515!!")


async def test_unsupported_protocol(client_with_no_base):
    with pytest.raises(UnsupportedProtocolError):
        await client_with_no_base.get("ksa://515")


async def test_couldnt_connect(client_with_no_base):
    with pytest.raises(CouldntConnectError):
        await client_with_no_base.get("localhost:1")


async def test_404_status(client):
    with pytest.raises(HTTPError) as exc:
        await client.get("/status/404")

    assert exc.value.status_code == 404


async def test_500_status(client):
    with pytest.raises(HTTPError) as exc:
        await client.get("/status/500")

    assert exc.value.status_code == 500
