"""Measured transfer and live NetEm study; outputs resumable, traceable JSON."""

import json
import time
import numpy as np
from flowlab import store
from flowlab.config import DATA, MODELS, RESULTS
from flowlab.datasets import fingerprint
from flowlab.ml import MODEL_NAMES, load_model, metrics, predict, train
from flowlab.packets import extract, read_pcap
from flowlab.cic import extract_cic, COMMIT
from flowlab.live import run_live


def snapshot(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, allow_nan=False))
    temporary.replace(path)


def transfer():
    manifest = json.loads((DATA / "manifests/extended.json").read_text())
    bundles = {name: load_model("cicids2017--" + name) for name in MODEL_NAMES}
    output = {
        "exporter_commit": COMMIT,
        "dataset": "CICIDS2017 corrected",
        "domain": "independent controlled VM sessions",
        "captures": [],
    }
    for item in manifest["captures"]:
        if item["split"] != "test":
            continue
        path = (DATA / "manifests" / item["path"]).resolve()
        frame = extract_cic(path, bundles["rf"]["metadata"]["features"])
        row = {
            "path": str(path),
            "sha256": fingerprint(path),
            "group": item["group"],
            "scenario": item["label"],
            "flows": len(frame),
            "models": {},
        }
        for name, bundle in bundles.items():
            start = time.perf_counter()
            predictions = predict(bundle, frame.to_dict("records"))
            labels = [p["prediction"] for p in predictions]
            # Family names differ and UDP DoS differs from the CICIDS DoS scenarios.
            # Report binary transfer and raw class histogram, rather than inventing a type equivalence.
            binary = ["BENIGN" if label == "BENIGN" else "ATTACK" for label in labels]
            truth = ["BENIGN" if item["label"] == "BENIGN" else "ATTACK"] * len(labels)
            row["models"][name] = {
                "binary_metrics": metrics(truth, binary),
                "predicted_classes": {label: labels.count(label) for label in set(labels)},
                "batch_ms_per_flow": 1000 * (time.perf_counter() - start) / len(labels),
            }
        output["captures"].append(row)
        snapshot(RESULTS / "cic-transfer.json", output)
        print("CIC transfer", item["group"], len(frame), flush=True)
    return output


def live_matrix():
    path = RESULTS / "live-study.json"
    output = (
        json.loads(path.read_text())
        if path.exists()
        else {
            "conditions": [],
            "duration_seconds": 6,
            "note": "Each fresh NetEm trace is shared by all six shadow models; shadow classification does not enforce. Two repeated sessions per condition, not broad network confidence intervals.",
        }
    )
    bundles = {name: load_model("extended_prefix10--" + name + "_tuned") for name in MODEL_NAMES}
    artifacts = {
        name: {
            "id": b["metadata"]["id"],
            "dataset_sha256": b["metadata"]["dataset_sha256"],
            "artifact_sha256": fingerprint(MODELS / (b["metadata"]["id"] + ".joblib")),
        }
        for name, b in bundles.items()
    }
    if output.get("model_artifacts") and output["model_artifacts"] != artifacts:
        raise ValueError(
            "Existing live study used different model artifacts; archive its JSON before starting a new study"
        )
    output["model_artifacts"] = artifacts
    for repetition in range(2):
        for kind in ["random", "burst"]:
            for rate in [0, 0.01, 0.05, 0.1]:
                for scenario in ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce"]:
                    key = f"{repetition}-{kind}-{rate}-{scenario}"
                    if any(c["key"] == key for c in output["conditions"]):
                        continue
                    request = dict(
                        src=f"192.168.56.{11 + repetition}",
                        dst=f"192.168.56.{14 - repetition}",
                        scenario=scenario,
                        model_id="extended_prefix10--rf_tuned",
                        loss_rate=rate,
                        loss_kind=kind,
                        seed=400 + repetition,
                        duration=6,
                        rate=80 + 30 * repetition,
                        enforce=False,
                    )
                    print("Live condition", key, flush=True)
                    result = run_live(request)
                    run = store.get(result["live_run_id"])
                    capture = store.get(run["capture_ids"][-1], "capture")
                    packets, _ = read_pcap(DATA / "captures" / capture["filename"])
                    flows = extract(packets, prefix=10)
                    counters = run.get("source_counter_list", [run["source_counters"]])
                    qdiscs = [q for c in counters for q in c["qdiscs"] if q["kind"] == "netem"]
                    drops = sum(q.get("drops", 0) for q in qdiscs)
                    sent = sum(q.get("packets", 0) for q in qdiscs)
                    row = dict(
                        key=key,
                        repetition=repetition,
                        scenario=scenario,
                        requested_loss=rate,
                        pattern=kind,
                        run_id=run["id"],
                        captured_packets=len(packets),
                        flows=len(flows),
                        measured_link_loss=drops / (sent + drops) if sent + drops else 0,
                        source_count=len(run["sources"]),
                        destination_counters=run["destination_counters"],
                        models={},
                    )
                    for name, bundle in bundles.items():
                        predictions = predict(bundle, [f["features"] for f in flows])
                        pp = [p["prediction"] for p in predictions]
                        timing = [f["end"] - f["start"] for f in flows]
                        row["models"][name] = dict(
                            metrics=metrics([scenario] * len(pp), pp),
                            attack_recall=float(np.mean([p != "BENIGN" for p in pp]))
                            if scenario != "BENIGN"
                            else None,
                            false_positive_rate=float(np.mean([p != "BENIGN" for p in pp]))
                            if scenario == "BENIGN"
                            else None,
                            prefix_observation_delay_ms_median=1000 * float(np.median(timing)),
                            batch_inference_ms_per_flow=float(
                                np.mean([p["inference_ms"] for p in predictions])
                            ),
                        )
                    output["conditions"].append(row)
                    snapshot(path, output)
    return output


def main():
    store.initialize()
    print("Waiting for extended corpus and baseline models", flush=True)
    while not (RESULTS / "extended-corpus-ready.json").exists():
        time.sleep(5)
    print("Tuning extended prefix classifiers", flush=True)
    dataset_meta = json.loads((DATA / "extended_prefix10.json").read_text())
    existing = [MODELS / f"extended_prefix10--{name}_tuned.json" for name in MODEL_NAMES]
    if not all(
        path.exists() and json.loads(path.read_text())["dataset_sha256"] == dataset_meta["sha256"]
        for path in existing
    ):
        train("extended_prefix10", progress=lambda s: print(s, flush=True), study=True)
    transfer()
    live_matrix()
    snapshot(
        RESULTS / "research-study-ready.json",
        {"complete": True, "outputs": ["cic-transfer.json", "live-study.json"]},
    )
    print("RESEARCH STUDY COMPLETE", flush=True)


if __name__ == "__main__":
    main()
