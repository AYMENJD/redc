from redc import Client


def _connection_closed(verbose: str) -> bool:
    return "shutting down connection" in verbose or "Closing connection" in verbose


async def test_keep_alive_true(client):
    r = await client.get("/get", verbose=True)
    assert r.status_code == 200
    assert "left intact" in r.verbose


async def test_keep_alive_false(server_url):
    async with Client(base_url=server_url) as c:
        r = await c.get("/get", verbose=True, keep_alive=False)
        assert r.status_code == 200
        assert _connection_closed(r.verbose)


async def test_keep_alive_client_default_true(server_url):
    async with Client(base_url=server_url, keep_alive=True) as c:
        r = await c.get("/get", verbose=True)
        assert r.status_code == 200
        assert "left intact" in r.verbose


async def test_keep_alive_client_default_false(server_url):
    async with Client(base_url=server_url, keep_alive=False) as c:
        r = await c.get("/get", verbose=True)
        assert r.status_code == 200
        assert _connection_closed(r.verbose)


async def test_keep_alive_per_request_override(server_url):
    async with Client(base_url=server_url, keep_alive=True) as c:
        r = await c.get("/get", verbose=True, keep_alive=False)
        assert r.status_code == 200
        assert _connection_closed(r.verbose)


async def test_keep_alive_default_no_verbose(client):
    r = await client.get("/get")
    assert r.status_code == 200
    assert r.verbose == ""


async def test_keep_alive_post(server_url):
    async with Client(base_url=server_url) as c:
        r = await c.post("/post", json={"a": 1}, verbose=True, keep_alive=False)
        assert r.status_code == 200
        assert _connection_closed(r.verbose)


async def test_keep_alive_multiple_requests_reuse(server_url):
    async with Client(base_url=server_url) as c:
        r1 = await c.get("/get", verbose=True, keep_alive=True)
        r2 = await c.get("/get", verbose=True, keep_alive=True)
        assert r1.status_code == 200
        assert r2.status_code == 200
        assert "left intact" in r1.verbose
        assert "left intact" in r2.verbose
