async def test_gzip(client):
    r = await client.get("/gzip")

    assert r.status_code == 200
    assert r.json()["gzipped"] is True


async def test_deflate(client):
    r = await client.get("/deflate")

    assert r.status_code == 200
    assert r.json()["deflated"] is True


async def test_brotli(client):
    r = await client.get("/brotli")

    assert r.status_code == 200
    assert r.json()["brotli"] is True
