import tempfile

import pytest

from redc.exceptions import UnsupportedProtocolError


async def test_file_url_reads_local_file(client_with_no_base):
    with tempfile.NamedTemporaryFile() as local:
        local.write(b"redc-file")
        local.flush()
        response = await client_with_no_base.get(f"file://{local.name}")
    assert response.content == b"redc-file"


async def test_redirect_off_http_rejected(client):
    with pytest.raises(UnsupportedProtocolError):
        await client.get("/redirect-to", params={"url": "file:///etc/passwd"})
