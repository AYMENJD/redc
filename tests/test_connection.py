async def test_connection_addresses(client, server_url):
    response = await client.get("/get")
    port = int(server_url.rsplit(":", 1)[1])

    assert response.primary_ip == "127.0.0.1"
    assert response.primary_port == port
    assert response.local_ip == "127.0.0.1"
    assert response.local_port > 0
