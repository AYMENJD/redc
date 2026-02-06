import pytest
from redc import Client


async def test_manual_close(server_url):
    client = Client(base_url=server_url)
    r = await client.get("/get")
    assert r.status_code == 200
    await client.close()

    with pytest.raises(RuntimeError):
        await client.get("/get")
