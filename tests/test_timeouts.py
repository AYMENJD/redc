import time

import pytest
from redc.exceptions import OperationTimedoutError


async def test_timeout(client):
    start = time.perf_counter()
    with pytest.raises(OperationTimedoutError):
        await client.get("/delay/3", timeout=(1, 1))

    end = time.perf_counter()

    assert (end - start) < 3
