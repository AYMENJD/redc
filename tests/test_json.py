import pytest


async def test_json_request_body(client):
    data = {"key": "value", "numbers": [1, 2, 3]}
    r = await client.post("/post", json=data)

    assert r.status_code == 200
    assert r.json()["json"] == data
    assert r.json()["headers"]["Content-Type"] == "application/json"


async def test_json_response_parsing(client):
    r = await client.get("/json")

    assert r.status_code == 200
    data = r.json()

    assert isinstance(data, dict)
    assert "slideshow" in data


async def test_json_decoding_error(client):
    r = await client.get("/html")

    assert r.status_code == 200
    with pytest.raises(Exception):
        r.json()
