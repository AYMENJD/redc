async def test_data_dict_sent_as_form(client):
    payload = {
        "city": "Jeddah",
        "country": "Saudi Arabia",
    }

    r = await client.post("/post", data=payload)

    body = r.json()

    assert body["form"]["city"] == "Jeddah"
    assert body["form"]["country"] == "Saudi Arabia"

    assert body["json"] is None
    assert body["files"] == {}


async def test_data_dict_sent_as_none(client):
    payload = {
        None: None,
        "city": "Jeddah",
        "country": "Saudi Arabia",
    }

    r = await client.post("/post", data=payload)

    body = r.json()

    assert body["form"][""] == ""
    assert body["form"]["city"] == "Jeddah"
    assert body["form"]["country"] == "Saudi Arabia"

    assert body["json"] is None
    assert body["files"] == {}
