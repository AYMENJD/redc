async def test_headers(client):
    r = await client.get(
        "/response-headers?city=Jeddah",
    )

    assert r.headers["city"] == "Jeddah"


async def test_custom_headers(client):
    headers = {"X-My-Header": "test-value"}
    r = await client.get("/headers", headers=headers)

    assert r.json()["headers"]["X-My-Header"] == "test-value"


async def test_none_headers(client):
    r = await client.get("/headers", headers={"X-RedC": None})
    assert r.json()["headers"]["X-Redc"] == ""


async def headers_case_insensitive(client):
    r = await client.get("/headers", headers={"X-RedC": "515"})

    assert "x-ReDc" in r.headers
    assert "X-redC" in r.headers

    assert r.headers["x-redc"] == "515"


async def test_empty_headers(client):
    r = await client.get("/get", headers={"X-Redc-Test": "", "X-Via": "redc"})

    data = r.json()

    assert data["headers"]["X-Redc-Test"] == ""
    assert data["headers"]["X-Via"] == "redc"


async def test_empty_headers_response(client):
    r = await client.get(
        "/response-headers?city=&country=",
    )

    assert r.headers["city"] == ""
    assert r.headers["country"] == ""


async def test_user_agent_override(client):
    headers = {"User-Agent": "test-redc/0.0.0"}
    r = await client.get("/user-agent", headers=headers)

    assert r.json()["user-agent"] == "test-redc/0.0.0"


async def test_links_parsing_edge_cases(client):
    complex_link_header = (
        '<https://example.com/style1.css>; rel="stylesheet", '
        '<https://example.com/style2.css>; rel="stylesheet", '
        '<https://example.com/chapter2>; rel="prev"; title="Previous; Chapter"'
    )

    r = await client.get("/response-headers", params={"Link": complex_link_header})

    links = r.links

    assert isinstance(links, list)
    assert len(links) == 3

    stylesheets = [x for x in links if x.get("rel") == "stylesheet"]
    assert len(stylesheets) == 2
    assert stylesheets[0]["url"] == "https://example.com/style1.css"
    assert stylesheets[1]["url"] == "https://example.com/style2.css"

    prev_link = next(x for x in links if x.get("rel") == "prev")
    assert prev_link["title"] == "Previous; Chapter"
