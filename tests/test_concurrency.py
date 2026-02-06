import asyncio


async def test_concurrent_requests(client):
    async def req():
        r = await client.get("/get")
        return r.status_code

    results = await asyncio.gather(*(req() for _ in range(100)))
    assert all(code == 200 for code in results)
