async def test_params_as_dict(client):
    params = {"key1": "value1", "key2": "value2"}
    r = await client.get("/get", params=params)
    r.raise_for_status()

    assert r.json()["args"]["key1"] == "value1"
    assert r.json()["args"]["key2"] == "value2"


async def test_params_list_values(client):
    params = {"key": ["val1", "val2"]}
    r = await client.get("/get", params=params)
    r.raise_for_status()

    assert r.json()["args"]["key"] == ["val1", "val2"]


async def test_params_url_encoding(client):
    params = {"msg": "hello world&goodbye"}
    r = await client.get("/get", params=params)
    r.raise_for_status()

    assert r.json()["args"]["msg"] == "hello world&goodbye"


async def test_params_as_none_value(client):
    params = {"key1": None, "key2": "value2"}
    r = await client.get("/get", params=params)
    r.raise_for_status()

    assert r.json()["args"]["key1"] == ""
    assert r.json()["args"]["key2"] == "value2"
