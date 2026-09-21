import os
import socket
import tempfile
import threading

import pytest

from redc import Client
from redc.exceptions import CouldntConnectError


def _serve_once(path, body, ready):
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(1)
    srv.settimeout(5)
    ready.set()
    try:
        conn, _ = srv.accept()
    except socket.timeout:
        srv.close()
        return
    try:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = conn.recv(4096)
            if not chunk:
                break
            data += chunk
        payload = body.encode()
        head = (
            f"HTTP/1.1 200 OK\r\nContent-Length: {len(payload)}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        conn.sendall(head + payload)
    finally:
        conn.close()
        srv.close()


def test_unix_socket_rejects_non_string():
    with pytest.raises(AssertionError):
        Client(unix_socket=1)


async def test_unix_socket_reads_local_server():
    with tempfile.TemporaryDirectory() as directory:
        path = os.path.join(directory, "httpd.sock")
        ready = threading.Event()
        thread = threading.Thread(target=_serve_once, args=(path, "pong", ready), daemon=True)
        thread.start()
        assert ready.wait(2)
        try:
            async with Client(http_version="1.1", raise_for_status=True) as client:
                response = await client.get("http://localhost/v1/info", unix_socket=path)
            assert response.content == b"pong"
        finally:
            thread.join(2)


async def test_unix_socket_missing():
    async with Client(http_version="1.1", raise_for_status=True, timeout=(2.0, 1.0)) as client:
        with pytest.raises(CouldntConnectError):
            await client.get("http://localhost/", unix_socket="/tmp/redc-missing-socket.sock")


async def test_unix_socket_empty_uses_tcp(server_url, backend):
    kwargs = {"backend": "threaded"} if backend == "threaded" else {}
    async with Client(
        base_url=server_url,
        unix_socket="/tmp/redc-missing-socket.sock",
        raise_for_status=True,
        timeout=(2.0, 1.0),
        **kwargs,
    ) as client:
        response = await client.get("/get", unix_socket="")
        assert response.status_code == 200
