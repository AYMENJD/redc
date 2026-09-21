import pytest

from redc import Client


def test_tls_version_rejects_unknown():
    with pytest.raises(AssertionError):
        Client(tls_version="nope")


def test_tls_version_min_above_max():
    with pytest.raises(ValueError):
        Client(tls_version="1.3", tls_version_max="1.2")


async def test_tls_version_request_min_above_max(client):
    with pytest.raises(ValueError):
        await client.get("/get", tls_version="1.3", tls_version_max="1.2")


async def test_tls_version_on_http(client):
    response = await client.get("/get", tls_version="1.2", tls_version_max="1.3")
    assert response.status_code == 200


async def test_tls_version_client_default(server_url, backend):
    kwargs = {"backend": "threaded"} if backend == "threaded" else {}
    async with Client(
        base_url=server_url,
        tls_version="1.2",
        raise_for_status=True,
        **kwargs,
    ) as c:
        response = await c.get("/get")
        assert response.status_code == 200
