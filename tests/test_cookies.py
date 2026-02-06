async def test_cookie_persist_between_requests(client_with_cookies):
    await client_with_cookies.get("/cookies/set?city=Jeddah")

    r = await client_with_cookies.get("/cookies")

    assert r.json()["cookies"]["city"] == "Jeddah"
    assert client_with_cookies.get_cookies()[0]["value"] == "Jeddah"


async def test_cookie_not_persist_between_requests(client):
    await client.get("/cookies/set?city=Jeddah")

    r = await client.get("/cookies")

    assert len(r.json()["cookies"]) == 0
    assert len(client.get_cookies()) == 0


async def test_cookie_dict(client):
    r = await client.get("/cookies", cookies={"city": "Jeddah"})

    assert r.json()["cookies"]["city"] == "Jeddah"
    assert len(client.get_cookies()) == 0
