import pytest
from redc.exceptions import HTTPError


async def test_raise_for_status_ok(client):
    await client.get("/status/200")


async def test_raise_for_status_404(client):
    with pytest.raises(HTTPError):
        await client.get("/status/404")


async def test_raise_for_status_500(client):
    with pytest.raises(HTTPError):
        await client.get("/status/500")
