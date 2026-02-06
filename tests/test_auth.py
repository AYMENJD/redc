import pytest
from redc.exceptions import HTTPError


async def test_basic_auth(client):
    user = "user"
    pwd = "pass"

    r = await client.get(f"/basic-auth/{user}/{pwd}", auth=(user, pwd))
    assert r.status_code == 200

    data = r.json()
    assert data["authenticated"] is True
    assert data["user"] == user


async def test_basic_auth_fail(client):
    user = "user"
    pwd = "pass"

    with pytest.raises(HTTPError):
        await client.get(f"/basic-auth/{user}/{pwd}", auth=(user, "wrong"))


async def test_hidden_basic_auth(client):
    user = "user"
    pwd = "pass"
    r = await client.get(f"/hidden-basic-auth/{user}/{pwd}", auth=(user, pwd))
    assert r.status_code == 200


async def test_bearer_auth(client):
    token = "mytoken"
    r = await client.get("/bearer", auth=token)

    assert r.status_code == 200
    assert r.json()["authenticated"] is True


async def test_digest_auth(client):
    user = "user"
    pwd = "pass"
    r = await client.get(f"/digest-auth/auth/{user}/{pwd}", auth=(user, pwd, "digest"))

    assert r.status_code == 200
