import pytest

from redc import Client
from redc.exceptions import CouldntConnectError

_DEAD_PROXY = "http://127.0.0.1:1"


def test_no_proxy_rejects_non_string():
    with pytest.raises(AssertionError):
        Client(no_proxy=1)


async def test_no_proxy_bypasses_dead_proxy(client):
    response = await client.get(
        "/get",
        proxy_url=_DEAD_PROXY,
        no_proxy="127.0.0.1",
        timeout=(2.0, 1.0),
    )
    assert response.status_code == 200


async def test_empty_no_proxy_uses_dead_proxy(client):
    with pytest.raises(CouldntConnectError):
        await client.get(
            "/get",
            proxy_url=_DEAD_PROXY,
            no_proxy="",
            timeout=(2.0, 1.0),
        )


async def test_no_proxy_client_default(server_url, backend):
    kwargs = {"backend": "threaded"} if backend == "threaded" else {}
    async with Client(
        base_url=server_url,
        no_proxy="127.0.0.1",
        raise_for_status=True,
        timeout=(2.0, 1.0),
        **kwargs,
    ) as c:
        response = await c.get("/get", proxy_url=_DEAD_PROXY)
        assert response.status_code == 200
        with pytest.raises(CouldntConnectError):
            await c.get("/get", proxy_url=_DEAD_PROXY, no_proxy="")
