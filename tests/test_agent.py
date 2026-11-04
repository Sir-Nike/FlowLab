"""Exercise real authenticated agent HTTP handlers with kernel commands mocked."""

import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest


@pytest.fixture()
def agent(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("a" * 48)
    monkeypatch.setenv("FLOWLAB_TOKEN_FILE", str(token))
    spec = importlib.util.spec_from_file_location(
        "flowlab_test_agent", Path(__file__).parents[1] / "lab/agent.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    calls = []
    monkeypatch.setattr(module, "command", lambda args, optional=False: calls.append(args) or "{}")
    server = ThreadingHTTPServer(("127.0.0.1", 0), module.Agent)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    with httpx.Client(base_url=f"http://127.0.0.1:{server.server_port}", trust_env=False) as client:
        yield module, client, calls
    server.shutdown()
    server.server_close()


def test_agent_requires_auth_and_restricts_targets(agent):
    module, client, calls = agent
    assert client.get("/health").status_code == 401
    client.headers["Authorization"] = "Bearer " + "a" * 48
    assert client.get("/health").json()["capture"] == "stopped"
    request = {"src": "8.8.8.8", "dst": "192.168.56.11", "sport": 1234, "dport": 80, "protocol": 6}
    assert client.post("/block", json=request).status_code == 400
    assert calls == []
    request["src"] = "192.168.56.12"
    assert client.post("/block", json=request).status_code == 200
    assert len(calls) == 2
    assert calls[0][-2:] == ["counter", "drop"]
    assert calls[0][0] == "nft"


def test_agent_loss_validation_and_buffer_cursor(agent):
    module, client, calls = agent
    client.headers["Authorization"] = "Bearer " + "a" * 48
    assert client.post("/loss", json={"rate": 1, "kind": "random", "seed": 42}).status_code == 400
    assert not calls
    assert client.post("/loss", json={"rate": 0.05, "kind": "burst", "seed": 42}).status_code == 200
    assert "gemodel" in calls[-1] and "seed" in calls[-1]
    with module.LOCK:
        for i in range(1, 10005):
            module.PACKETS.append((i, {"number": i}))
    first = client.get("/packets?after=0").json()
    assert first["cursor"] == 10000 and len(first["packets"]) == 10000
    second = client.get("/packets?after=10000").json()
    assert second["cursor"] == 10004 and len(second["packets"]) == 4
