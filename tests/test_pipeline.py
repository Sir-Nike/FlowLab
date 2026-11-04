import json

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from flowlab import app as application
from flowlab import datasets, experiments, ml, store
from flowlab.fixtures import generate, write_pcap
from flowlab.packets import extract


@pytest.fixture()
def workspace(tmp_path, monkeypatch):
    data = tmp_path / "data"
    models = tmp_path / "models"
    results = tmp_path / "results"
    for p in [data, models, results, data / "captures"]:
        p.mkdir(parents=True, exist_ok=True)
    for mod in [application, ml, datasets, experiments]:
        if hasattr(mod, "DATA"):
            monkeypatch.setattr(mod, "DATA", data)
        if hasattr(mod, "MODELS"):
            monkeypatch.setattr(mod, "MODELS", models)
    monkeypatch.setattr(store, "RESULTS", results)
    store.initialize()
    return data, models


@pytest.fixture()
def trained(workspace):
    metadata = datasets.prepare_fixture(episodes=12)
    ml.train(metadata["name"], algorithms=["logistic", "rf"])
    return workspace


def test_training_split_integrity_and_provenance(trained):
    data, models = trained
    frame = pd.read_csv(data / "fixture_completed.csv")
    assert frame.groupby("group").split.nunique().max() == 1
    meta = json.loads((models / "fixture_completed--rf.json").read_text())
    assert meta["synthetic"] and meta["schema"] == "flowlab-payload-v1"
    assert meta["dataset_sha256"] == datasets.fingerprint(data / "fixture_completed.csv")
    assert meta["metrics"]["test"]["report"]["BENIGN"]["support"] > 0
    assert not meta["calibrated"]


def test_repeated_flow_decisions_have_independent_record_ids(workspace):
    a = store.add("decision", {"id": "same-flow", "prediction": "BENIGN"})
    b = store.add("decision", {"id": "same-flow", "prediction": "BENIGN"})
    assert a["id"] != b["id"]
    assert a["flow_id"] == b["flow_id"] == "same-flow"
    assert len(store.listing("decision")) == 2


def test_prediction_sensitivity_and_schema(trained):
    model = ml.load_model("fixture_completed--logistic")
    flow = extract(generate("BENIGN", count=1))[0]
    prediction = ml.predict(model, [flow["features"]], explain=True)[0]
    assert prediction["prediction"] in model["metadata"]["classes"]
    assert prediction["explanation"]["method"] == "Median replacement sensitivity"
    with pytest.raises(ValueError):
        ml.predict(model, [{"bad": 1}])
    with pytest.raises(ValueError):
        ml.load_model("../secret")


def test_invisible_attacks_count_as_missed(trained):
    result = experiments.analyze(
        "fixture_completed--rf", generate("DoS", count=4), label="DoS", rate=1, explain=False
    )
    assert result["flows_original"] == 4
    assert result["flows_invisible"] == 4
    assert result["end_to_end_attack_recall"] == 0
    assert result["conditional"] is None


def test_reproducible_matrix_and_exports(trained):
    result = experiments.matrix(
        {
            "source": "fixture",
            "scenario": "PortScan",
            "seed": 42,
            "src": "192.168.56.11",
            "dst": "192.168.56.12",
            "model_ids": ["fixture_completed--logistic"],
            "kinds": ["random", "burst"],
            "rates": [0, 0.1],
            "seeds": [1, 2],
        }
    )
    experiment = store.get(result["experiment_id"], "experiment")
    assert len(experiment["results"]) == 8 and len(experiment["summary"]) == 4
    assert all(r["enforcement"].startswith("observation") for r in experiment["results"])


def test_api_rejects_cross_origin_and_invalid_input(trained):
    # Do not enter lifespan: its global executor belongs to the application process.
    client = TestClient(application.app)
    assert client.get("/api/models").status_code == 200
    assert (
        client.post("/api/scenarios", headers={"Origin": "https://evil.example"}, json={}).status_code == 403
    )
    assert client.get("/api/status", headers={"Host": "evil.example"}).status_code == 403
    assert (
        client.post(
            "/api/scenarios", json={"model_id": "fixture_completed--rf", "loss_rate": 0.9}
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/api/scenarios", json={"model_id": "fixture_completed--rf", "src": "8.8.8.8"}
        ).status_code
        == 422
    )
    assert (
        client.post("/api/scenarios", json={"model_id": "fixture_completed--rf", "enforce": True}).status_code
        == 422
    )


def test_capture_import_csv_prediction_and_invalid_capture(trained, tmp_path):
    client = TestClient(application.app)
    path = tmp_path / "sample.pcap"
    write_pcap(generate("BENIGN", count=2), path)
    response = client.post("/api/captures?label=BENIGN", files={"file": ("sample.pcap", path.read_bytes())})
    assert response.status_code == 200, response.text
    capture = response.json()
    assert capture["label"] == "BENIGN" and capture["packets"] > 0
    assert client.post("/api/captures", files={"file": ("bad.pcap", b"not a pcap")}).status_code == 400
    flow = extract(generate("BENIGN", count=1))[0]
    csv = pd.DataFrame([flow["features"]]).to_csv(index=False)
    response = client.post("/api/predict-csv/fixture_completed--rf", files={"file": ("flows.csv", csv)})
    assert response.status_code == 200, response.text
    assert response.json()["rows"] == 1
    exported = client.get("/api/records/" + response.json()["record_id"] + "/export")
    assert exported.status_code == 200 and exported.json()["rows"][0]["prediction"]


def test_refuses_changed_training_data(trained):
    data, _ = trained
    with (data / "fixture_completed.csv").open("a") as f:
        f.write("\n")
    with pytest.raises(ValueError, match="fingerprint"):
        ml.train("fixture_completed", ["logistic"])


def test_pcap_manifest_rejects_duplicate_capture_across_splits(workspace, tmp_path):
    path = tmp_path / "sample.pcap"
    write_pcap(generate("BENIGN", count=2), path)
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "captures": [
                    {"path": "sample.pcap", "split": s, "label": "BENIGN", "group": s}
                    for s in ["train", "validation", "test"]
                ]
            }
        )
    )
    with pytest.raises(ValueError, match="multiple splits"):
        datasets.prepare_pcaps(manifest)
