async def test_put_request(client):
    r = await client.put("/put", json={"data": "put"})

    assert r.status_code == 200
    assert r.json()["json"] == {"data": "put"}


async def test_patch_request(client):
    r = await client.patch("/patch", json={"data": "patch"})

    assert r.status_code == 200
    assert r.json()["json"] == {"data": "patch"}


async def test_delete_request(client):
    r = await client.delete("/delete")

    assert r.status_code == 200


async def test_head_request(client):
    r = await client.head("/get")

    assert r.status_code == 200
    assert r.text() == ""


async def test_options_request(client):
    r = await client.options("/get")

    assert r.status_code == 200
