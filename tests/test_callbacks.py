from redc import ProgressCallback


async def test_progress_callback(client):
    calls = []

    def on_progress(dltotal: int, dlnow: int, ultotal: int, ulnow: int):
        calls.append((dlnow, dltotal))

    r = await client.get(
        "/bytes/102400", progress_callback=ProgressCallback(on_progress)
    )

    assert r.status_code == 200
    assert len(calls) > 0
    assert calls[-1][0] == calls[-1][1]


async def test_progress_callback_chunked(client):
    calls = []

    def on_progress(dltotal, dlnow, ultotal, ulnow):
        calls.append((dlnow, dltotal))

    await client.get(
        "/stream-bytes/102400", progress_callback=ProgressCallback(on_progress)
    )

    assert calls[-1][1] == 0
    assert calls[-1][0] == 102400
