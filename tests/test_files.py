from io import BytesIO


async def test_file_upload_bytes(client):
    r = await client.post(
        "/post",
        files={"file": b"hello world"},
    )

    assert r.status_code == 200
    data = r.json()

    assert "file" in data["files"]
    assert data["files"]["file"] == "hello world"


async def test_file_upload_tuple(client):
    r = await client.post(
        "/post",
        files={"file": ("test.txt", b"abc", "text/plain")},
    )

    assert r.status_code == 200
    data = r.json()

    assert "file" in data["files"]
    assert data["files"]["file"] == "abc"


async def test_file_upload_tuple_io(client):
    r = await client.post(
        "/post",
        files={"file": ("test.txt", BytesIO(b"hello world"), "text/plain")},
    )

    assert r.status_code == 200
    data = r.json()

    assert "file" in data["files"]
    assert data["files"]["file"] == "hello world"


async def test_file_upload_io(client):
    r = await client.post(
        "/post",
        files={"file": BytesIO(b"hello world")},
    )

    assert r.status_code == 200
    data = r.json()

    assert "file" in data["files"]
    assert data["files"]["file"] == "hello world"
