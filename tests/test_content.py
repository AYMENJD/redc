import pytest


async def test_response_bytes(client):
    r = await client.get("/bytes/10")

    assert r.status_code == 200
    assert isinstance(r.content, bytes)
    assert len(r.content) == 10


async def test_response_text_encoding(client):
    r = await client.get("/encoding/utf8")
    text = r.text()

    assert isinstance(text, str)
    assert "∮" in text


async def test_force_encoding(client):
    r = await client.get("/encoding/utf8")
    with pytest.raises(UnicodeError):
        _ = r.text("ascii")
