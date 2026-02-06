async def test_generic_request_get(client):
    r = await client.request("GET", "/get")

    assert r.status_code == 200


async def test_generic_request_post(client):
    r = await client.request("POST", "/post", json={"a": 1})

    assert r.status_code == 200
    assert r.json()["json"]["a"] == 1
