from redc import StreamCallback


async def test_streaming_callback(client):
    chunks = []

    def on_chunk(data: bytes, data_size: int):
        chunks.append(data)

    r = await client.get("/stream/10", stream_callback=StreamCallback(on_chunk))

    assert r.status_code == 200
    assert len(chunks) > 0
