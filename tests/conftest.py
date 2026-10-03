import threading
import time
import pytest
import uvicorn
import httpx

from authrift.detection.authorization import reset_counter

BASE = "http://127.0.0.1:9777"


@pytest.fixture(scope="session", autouse=True)
def mock_server():
    from tests.mock_api import app

    config = uvicorn.Config(app, host="127.0.0.1", port=9777, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    for _ in range(50):
        try:
            r = httpx.get(f"{BASE}/api/profile", headers={"Authorization": "Bearer TOKEN_A"}, timeout=1.0)
            if r.status_code == 200:
                break
        except Exception:
            time.sleep(0.1)
    else:
        pytest.fail("Mock server did not start on port 9777")

    yield
    server.should_exit = True


@pytest.fixture(autouse=True)
def _reset_finding_counter():
    reset_counter()
