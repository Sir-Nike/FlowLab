"""Paired sensor-loss comparison including entirely invisible original flows."""

import json
import time
from flowlab.config import DATA, RESULTS
from flowlab.experiments import identify_originals
from flowlab.context import extract_context
from flowlab.packets import read_pcap, extract, apply_loss
from flowlab.ml import MODEL_NAMES, load_model, predict
from scripts.evaluate_refinement import summarize_predictions, persist


def main():
    while not (RESULTS / "refined-augmented-ready.json").exists():
        time.sleep(5)
    bundles = {
        f"{m}_{kind}": load_model(f"{dataset}--{m}{suffix}")
        for m in MODEL_NAMES
        for kind, dataset, suffix in [
            ("flow", "refined_flow", "_tuned"),
            ("context", "refined_context", "_hier"),
        ]
    }
    path = RESULTS / "refinement-capture-loss.json"
    out = (
        json.loads(path.read_text())
        if path.exists()
        else {
            "conditions": [],
            "note": "Seeded sensor loss. All variants of a held-out capture stay in its test group. Invisible original flows count as misses.",
        }
    )
    manifest = json.loads((DATA / "manifests/refined.json").read_text())
    for item in manifest["captures"]:
        if item["split"] != "test":
            continue
        packets, _ = read_pcap((DATA / "manifests" / item["path"]).resolve())
        packets = identify_originals(packets)
        origins = {p.origin for p in packets}
        for kind in ["random", "burst"]:
            for rate in [0, 0.01, 0.05, 0.1]:
                for seed in [41, 42]:
                    key = f"{item['group']}-{kind}-{rate}-{seed}"
                    if any(c["key"] == key for c in out["conditions"]):
                        continue
                    kept = apply_loss(packets, rate, kind, seed)
                    plain = extract(kept, prefix=10)
                    context = extract_context(kept, prefix=10)
                    visible = {o for f in context for o in f["origins"]}
                    row = dict(
                        key=key,
                        group=item["group"],
                        label=item["label"],
                        kind=kind,
                        rate=rate,
                        seed=seed,
                        actual_loss=1 - len(kept) / len(packets),
                        original_flows=len(origins),
                        invisible_flows=len(origins - visible),
                        models={},
                    )
                    for model, bundle in bundles.items():
                        flows = context if model.endswith("_context") else plain
                        pp = predict(bundle, [f["features"] for f in flows])
                        result = summarize_predictions(item["label"], flows, pp)
                        correct = {
                            o
                            for f, p in zip(flows, pp)
                            if p["prediction"] == item["label"]
                            for o in f["origins"]
                        }
                        detected = {
                            o for f, p in zip(flows, pp) if p["attack_score"] >= 0.5 for o in f["origins"]
                        }
                        result["end_to_end_class_recall"] = len(correct) / len(origins)
                        result["end_to_end_attack_recall"] = (
                            len(detected) / len(origins) if item["label"] != "BENIGN" else None
                        )
                        row["models"][model] = result
                    out["conditions"].append(row)
                    persist(path, out)
        print("Capture loss complete", item["group"], flush=True)
    persist(
        RESULTS / "refined-capture-loss-ready.json", {"complete": True, "conditions": len(out["conditions"])}
    )


if __name__ == "__main__":
    main()
