import pytest

from redc import Client
from redc.exceptions import InterfaceFailedError


def test_ip_version_rejects_unknown():
    with pytest.raises(AssertionError):
        Client(ip_version="nope")


def test_interface_rejects_non_string():
    with pytest.raises(AssertionError):
        Client(interface=1)


async def test_ip_version_v4(client):
    response = await client.get("/get", ip_version="4")
    assert response.status_code == 200


async def test_interface_loopback(client):
    response = await client.get("/get", interface="127.0.0.1")
    assert response.status_code == 200


async def test_interface_missing_address(client):
    with pytest.raises(InterfaceFailedError):
        await client.get("/get", interface="192.0.2.1")


async def test_client_defaults(server_url, backend):
    kwargs = {"backend": "threaded"} if backend == "threaded" else {}
    async with Client(
        base_url=server_url,
        interface="127.0.0.1",
        ip_version="4",
        raise_for_status=True,
        **kwargs,
    ) as c:
        response = await c.get("/get")
        assert response.status_code == 200
        response = await c.get("/get", interface="", ip_version="any")
        assert response.status_code == 200
