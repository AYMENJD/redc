import pytest


async def test_url(client):
    r = await client.get("/get")

    assert r.url.endswith("/get")


async def test_http_version_value_1(client):
    r = await client.get("/get", http_version="1")

    assert r.http_version == "1"


async def test_http_version_value_1_1(client):
    r = await client.get("/get", http_version="1.1")

    assert r.http_version == "1.1"


async def test_connection_addresses(client, server_url):
    r = await client.get("/get")
    port = int(server_url.rsplit(":", 1)[1])

    assert r.primary_ip == "127.0.0.1"
    assert r.primary_port == port
    assert r.local_ip == "127.0.0.1"
    assert r.local_port > 0


async def test_dns_time(client):
    r = await client.get("/get")

    assert isinstance(r.dns_time, float)
    assert isinstance(r.dns_time_us, int)
    assert r.dns_time == pytest.approx(r.dns_time_us / 1_000_000)


async def test_connect_time(client):
    r = await client.get("/get")

    assert isinstance(r.connect_time, float)
    assert isinstance(r.connect_time_us, int)
    assert r.connect_time == pytest.approx(r.connect_time_us / 1_000_000)


async def test_tls_time(client):
    r = await client.get("/get")

    assert isinstance(r.tls_time, float)
    assert isinstance(r.tls_time_us, int)
    assert r.tls_time == pytest.approx(r.tls_time_us / 1_000_000)


async def test_first_byte_time(client):
    r = await client.get("/get")

    assert isinstance(r.first_byte_time, float)
    assert isinstance(r.first_byte_time_us, int)
    assert r.first_byte_time == pytest.approx(r.first_byte_time_us / 1_000_000)
    assert r.first_byte_time_us >= r.connect_time_us
    assert r.first_byte_time_us <= r.elapsed_us


async def test_redirect_time(client):
    r = await client.get("/get")

    assert isinstance(r.redirect_time, float)
    assert isinstance(r.redirect_time_us, int)
    assert r.redirect_time == pytest.approx(r.redirect_time_us / 1_000_000)
    assert r.redirect_time_us == 0

    r = await client.get("/redirect/1")

    assert r.redirect_count == 1
    assert r.redirect_time_us > 0
    assert r.redirect_time_us <= r.elapsed_us


async def test_downlaod_size(client):
    r = await client.get("/stream/100")

    assert r.download_size > 100


async def test_downlaod_speed(client):
    r = await client.get("/stream/1000")

    assert r.download_speed > 10000


async def test_upload_size(client):
    r = await client.post(
        "/post",
        json={
            "data": "test" * 100,
        },
    )

    assert r.upload_size > 100


async def test_upload_speed(client):
    r = await client.post(
        "/post",
        json={
            "data": "test" * 100,
        },
    )

    assert r.upload_speed > 1000


async def test_elapsed(client):
    r = await client.get("/get")

    assert r.elapsed != 0.0
    assert r.elapsed_us != 0.0
    assert r.elapsed == r.elapsed_us / 1_000_000


async def test_reason(client):
    r = await client.get("/get")

    assert r.status_code == 200
    assert r.reason == "OK"
