import importlib.util
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import httpx
import numpy as np
from sklearn.linear_model import LogisticRegression

from flowlab.ml import TemperatureClassifier


def test_temperature_preserves_training_classes_missing_in_calibration():
    x = np.array([[-3], [-2], [0], [0.2], [2], [3]])
    y = np.array([0, 0, 1, 1, 2, 2])
    model = LogisticRegression().fit(x, y)
    calibrated = TemperatureClassifier(model).fit(x[:4], y[:4])
    p = calibrated.predict_proba(x)
    assert p.shape == (6, 3)
    assert np.allclose(p.sum(1), 1)
    assert calibrated.classes_.tolist() == [0, 1, 2]
    assert 0 < calibrated.temperature_ < 21


def test_http_authentication_checks_credentials_and_counts(tmp_path, monkeypatch):
    token = tmp_path / "token"
    token.write_text("a" * 48)
    monkeypatch.setenv("FLOWLAB_TOKEN_FILE", str(token))
    spec = importlib.util.spec_from_file_location(
        "flowlab_auth_test", Path(__file__).parents[1] / "lab/agent.py"
    )
    agent = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(agent)
    server = ThreadingHTTPServer(("127.0.0.1", 0), agent.Service)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        with httpx.Client(base_url=f"http://127.0.0.1:{server.server_port}", trust_env=False) as client:
            assert client.get("/auth", auth=("student", "wrong")).status_code == 401
            assert client.get("/auth", auth=("student", "lab-only-correct-password")).status_code == 200
            assert client.get("/auth", headers={"Authorization": "Basic malformed"}).status_code == 401
            assert agent.COUNTERS["auth_success"] == 1
            assert agent.COUNTERS["auth_failure"] == 2
    finally:
        server.shutdown()
        server.server_close()


def test_cic_flow_contract_rejects_missing_features(monkeypatch, tmp_path):
    import flowlab.cic as cic
    from types import SimpleNamespace

    monkeypatch.setattr(cic, "ROOT", tmp_path)
    runtime = tmp_path / "tools/CICFlowMeter/runtime"
    runtime.mkdir(parents=True)
    (runtime / "build.json").write_text(__import__("json").dumps({"commit": cic.COMMIT, "java": "java"}))

    def fake_export(command, **kwargs):
        (Path(command[-1]) / "export.csv").write_text("Flow Duration\n10\n")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(cic.subprocess, "run", fake_export)
    import pytest

    with pytest.raises(ValueError, match="missing.*|schema mismatch"):
        cic.extract_cic(tmp_path / "capture.pcap", ["Flow Duration", "Total TCP Flow Time"])


def test_cic_completed_models_cannot_enforce(monkeypatch):
    import pytest
    import flowlab.live as live
    from flowlab.cic import SCHEMA

    monkeypatch.setattr(live, "resolve_peers", lambda: [dict(ip="192.168.56.11"), dict(ip="192.168.56.12")])
    monkeypatch.setattr(live, "load_model", lambda _: {"metadata": {"schema": SCHEMA}})
    with pytest.raises(ValueError, match="completed-flow models"):
        live.run_live(
            dict(src="192.168.56.11", dst="192.168.56.12", scenario="BENIGN", model_id="cic", enforce=True)
        )
