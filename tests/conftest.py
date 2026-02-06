import socket
import subprocess
import sys
import time

import pytest
import pytest_asyncio
from redc import Client


def get_free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_server(host, port, timeout=10):
    start = time.time()
    while time.time() - start < timeout:
        with socket.socket() as s:
            if s.connect_ex((host, port)) == 0:
                return True
        time.sleep(0.1)
    return False


@pytest.fixture(scope="session", autouse=True)
def httpbin_server():
    host = "127.0.0.1"
    port = get_free_port()

    base_url = f"http://{host}:{port}"

    cmd = [
        sys.executable,
        "-m",
        "gunicorn",
        "--bind",
        f"{host}:{port}",
        "--workers",
        "2",
        "--log-level",
        "warning",
        "httpbin.core:app",
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if not wait_for_server(host, port):
        stdout, stderr = proc.communicate(timeout=5)
        raise RuntimeError(
            f"httpbin failed to start\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        )

    yield base_url

    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


@pytest.fixture(scope="session")
def server_url(httpbin_server):
    return httpbin_server


@pytest.fixture(
    scope="session", params=["async", "threaded"], ids=["async", "threaded"]
)
def backend(request):
    return request.param


def backend_kwargs(backend):
    return {"backend": "threaded"} if backend == "threaded" else {}


@pytest_asyncio.fixture(scope="session")
async def client(server_url, backend):
    async with Client(
        base_url=server_url,
        raise_for_status=True,
        **backend_kwargs(backend),
    ) as c:
        yield c


@pytest_asyncio.fixture(scope="session")
async def client_with_cookies(server_url, backend):
    async with Client(
        base_url=server_url,
        persist_cookies=True,
        raise_for_status=True,
        **backend_kwargs(backend),
    ) as c:
        yield c


@pytest_asyncio.fixture(scope="session")
async def client_with_no_base(backend):
    async with Client(
        raise_for_status=True,
        **backend_kwargs(backend),
    ) as c:
        yield c
