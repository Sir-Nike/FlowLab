"""Paired live comparison of flow-only and contextual hierarchical detectors."""

import json
import time
import numpy as np
from flowlab import store
from flowlab.config import DATA, MODELS, RESULTS
from flowlab.context import extract_context
from flowlab.packets import extract, read_pcap
from flowlab.datasets import fingerprint
from flowlab.ml import MODEL_NAMES, load_model, metrics
from flowlab.ml import predict, train
from flowlab.live import run_live
from scripts.collect_refined import SCENARIOS


def summarize_predictions(truth, flows, predictions):
    labels = [p["prediction"] for p in predictions]
    scores = np.array([p["attack_score"] for p in predictions])
    accepted = np.array([not p.get("uncertain", False) for p in predictions])
    return dict(
        classification=metrics([truth] * len(labels), labels),
        attack_recall=float((scores >= 0.5).mean()) if truth != "BENIGN" else None,
        benign_fpr=float((scores >= 0.5).mean()) if truth == "BENIGN" else None,
        blocking_fpr=float(np.mean([p["block_eligible"] for p in predictions]))
        if truth == "BENIGN"
        else None,
        class_recall=float(np.mean([p == truth for p in labels])),
        coverage=float(accepted.mean()),
        accepted_accuracy=float(np.mean([p == truth for p, a in zip(labels, accepted) if a]))
        if accepted.any()
        else None,
        uncertain=int((~accepted).sum()),
        leading_types={p: labels.count(p) for p in sorted(set(labels))},
        inference_ms_per_flow=float(np.mean([p["inference_ms"] for p in predictions])),
        observation_delay_median_ms=1000
        * float(np.median([f.get("decision_time", f["end"]) - f["start"] for f in flows])),
    )


def persist(path, value):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(value, indent=2, allow_nan=False))
    tmp.replace(path)


def main():
    store.initialize()
    while not (RESULTS / "refined-augmented-ready.json").exists():
        time.sleep(5)
    print("Training contextual flat control for ablation", flush=True)
    train("refined_context", study=True, progress=lambda s: print(s, flush=True))
    bundles = {}
    for algorithm in MODEL_NAMES:
        for variant, dataset, suffix in [
            ("flow", "refined_flow", "_tuned"),
            ("context", "refined_context", "_hier"),
        ]:
            key = f"{algorithm}_{variant}"
            bundles[key] = load_model(f"{dataset}--{algorithm}{suffix}")
    path = RESULTS / "refinement-live.json"
    out = (
        json.loads(path.read_text())
        if path.exists()
        else {
            "conditions": [],
            "note": "Paired flow-only vs contextual hierarchical predictions on fresh live NetEm traces. Uncertainty is not counted as correct classification.",
        }
    )
    artifacts = {
        k: dict(
            id=b["metadata"]["id"],
            dataset_sha256=b["metadata"]["dataset_sha256"],
            sha256=fingerprint(MODELS / (b["metadata"]["id"] + ".joblib")),
        )
        for k, b in bundles.items()
    }
    if out.get("model_artifacts") and out["model_artifacts"] != artifacts:
        raise ValueError("Models changed since the study checkpoint")
    out["model_artifacts"] = artifacts
    for repetition in range(2):
        for kind in ["random", "burst"]:
            for rate in [0, 0.01, 0.05, 0.1]:
                for scenario in SCENARIOS:
                    key = f"{repetition}-{kind}-{rate}-{scenario}"
                    if any(r["key"] == key for r in out["conditions"]):
                        continue
                    print("Refined live", key, flush=True)
                    request = dict(
                        src=f"192.168.56.{11 + repetition}",
                        dst=f"192.168.56.{14 - repetition}",
                        scenario=scenario,
                        source_count=1 if scenario == "BenignBurst" and repetition == 0 else 3,
                        model_id="refined_context--extra_hier",
                        loss_rate=rate,
                        loss_kind=kind,
                        seed=910 + repetition,
                        duration=5,
                        rate=70 + 30 * repetition,
                        enforce=False,
                    )
                    r = store.get(run_live(request)["live_run_id"])
                    capture = store.get(r["capture_ids"][-1], "capture")
                    packets, _ = read_pcap(DATA / "captures" / capture["filename"])
                    plain = extract(packets, prefix=10)
                    context = extract_context(packets, prefix=10)
                    label = (
                        "BENIGN"
                        if scenario == "BenignBurst"
                        else "DoS"
                        if scenario == "HTTPDoS"
                        else scenario
                    )
                    row = dict(
                        key=key,
                        label=label,
                        scenario=scenario,
                        loss=rate,
                        kind=kind,
                        repetition=repetition,
                        run_id=r["id"],
                        capture_filename=capture["filename"],
                        source_count=len(r["sources"]),
                        packets=len(packets),
                        models={},
                    )
                    q = [q for c in r["source_counter_list"] for q in c["qdiscs"] if q["kind"] == "netem"]
                    drops = sum(q.get("drops", 0) for q in q)
                    sent = sum(q.get("packets", 0) for q in q)
                    row["measured_link_loss"] = drops / (sent + drops) if sent + drops else 0
                    for model_id, bundle in bundles.items():
                        flows = context if model_id.endswith("_context") else plain
                        predictions = predict(bundle, [f["features"] for f in flows])
                        row["models"][model_id] = summarize_predictions(label, flows, predictions)
                    out["conditions"].append(row)
                    persist(path, out)
    persist(RESULTS / "refined-live-ready.json", {"complete": True, "sessions": len(out["conditions"])})
    print("REFINED LIVE COMPLETE", flush=True)


if __name__ == "__main__":
    main()
