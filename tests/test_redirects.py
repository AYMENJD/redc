import pytest
from redc.exceptions import TooManyRedirectsError


async def test_follow_redirect(client):
    r = await client.get("/redirect/1")

    assert r.status_code == 200
    assert r.redirect_count == 1


async def test_disallow_redirects(client):
    r = await client.get("/redirect/1", allow_redirects=False)

    assert r.is_redirect
    assert r.status_code in (301, 302)


async def test_is_permanent_redirect(client):
    r = await client.get("/redirect-to?url=/get&status_code=308", allow_redirects=False)

    assert r.is_permanent_redirect
    assert r.status_code == 308


async def test_follow_redirect_20(client):
    r = await client.get("/redirect/20")

    assert r.status_code == 200
    assert r.redirect_count == 20
    assert len(r.history) == 20


async def test_allow_redirect_10(client):
    with pytest.raises(TooManyRedirectsError):
        await client.get("/redirect/11", allow_redirects=10)


async def test_redirect_307_preserves_post(client):
    r = await client.post(
        "/redirect-to?url=/post&status_code=307", json={"test": "data"}
    )

    assert r.status_code == 200
    assert r.json()["json"] == {"test": "data"}
    assert r.url.endswith("/post")
