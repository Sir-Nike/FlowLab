"""CICIDS-only, lab-only and domain-balanced combined prefix comparison."""

import json
import time
import pandas as pd
from flowlab.config import DATA, RESULTS
from flowlab.datasets import save_dataset, fingerprint
from flowlab.context import SCHEMA, ALL_FEATURES, extract_context
from flowlab.packets import read_pcap, extract
from flowlab.ml import train, MODEL_NAMES, load_model, predict
from scripts.evaluate_refinement import summarize_predictions, persist


def main():
    while (
        not (RESULTS / "cic-prefix-ready.json").exists()
        or not (RESULTS / "refined-augmented-ready.json").exists()
    ):
        time.sleep(5)
    cic = pd.read_csv(DATA / "cic_prefix_context.csv")
    lab = pd.read_csv(DATA / "refined_context.csv")
    cap = []
    for (label, split), group in cic.groupby(["label", "split"]):
        cap.append(group.sample(min(len(group), 4000), random_state=42))
    cic = pd.concat(cap, ignore_index=True)
    old = json.loads((DATA / "cic_prefix_context.json").read_text())
    old.pop("name", None)
    save_dataset("cic_prefix_context", cic, old)
    pieces = [lab]
    for (label, split), group in cic.groupby(["label", "split"]):
        lab_count = int(((lab.label == label) & (lab.split == split)).sum())
        pieces.append(group.sample(min(len(group), max(1, lab_count)), random_state=42))
    combined = pd.concat(pieces, ignore_index=True)
    save_dataset(
        "mixed_prefix_context",
        combined,
        dict(
            schema=SCHEMA,
            features=ALL_FEATURES,
            synthetic=False,
            live_compatible=True,
            observation="prefix10",
            prefix=10,
            context=True,
            split_policy="Preserved source-domain partitions; held-out windows and lab episodes never enter fitting",
            source="Domain-balanced original CICIDS packet prefixes plus independent lab captures",
            source_sha256=fingerprint(DATA / "cic_prefix_context.csv"),
            lab_sha256=fingerprint(DATA / "refined_context.csv"),
            warnings=[
                "CIC rows capped per label and partition at the lab count to balance domains.",
                "Shared family names do not imply identical attack tools or environments.",
                "Held-out CIC windows and held-out lab episodes remain separate from all training and calibration.",
            ],
        ),
    )
    for name in ["cic_prefix_context", "mixed_prefix_context"]:
        print("Train shared prefix", name, flush=True)
        train(name, study=True, hierarchical=True, progress=lambda s: print(s, flush=True))
    # Paired ablation and transfer on untouched lab capture groups.
    manifest = json.loads((DATA / "manifests/refined.json").read_text())
    bundles = {}
    for model in MODEL_NAMES:
        for variant, dataset, suffix in [
            ("flow", "refined_flow", "_tuned"),
            ("context_flat", "refined_context", "_tuned"),
            ("lab", "refined_context", "_hier"),
            ("cic", "cic_prefix_context", "_hier"),
            ("mixed", "mixed_prefix_context", "_hier"),
        ]:
            bundles[f"{model}_{variant}"] = load_model(f"{dataset}--{model}{suffix}")
    output = {
        "captures": [],
        "note": "Paired predictions on held-out lab sessions; uncertain classes count as misses; binary detection and accepted coverage reported separately.",
    }
    for item in manifest["captures"]:
        if item["split"] != "test":
            continue
        print("Held-out comparison", item["group"], flush=True)
        packets, _ = read_pcap((DATA / "manifests" / item["path"]).resolve())
        contexts = extract_context(packets, prefix=10)
        plain = extract(packets, prefix=10)
        row = {"group": item["group"], "label": item["label"], "scenario": item["scenario"], "models": {}}
        for key, bundle in bundles.items():
            flows = plain if key.endswith("_flow") else contexts
            pp = predict(bundle, [f["features"] for f in flows])
            row["models"][key] = summarize_predictions(item["label"], flows, pp)
        output["captures"].append(row)
        persist(RESULTS / "refinement-transfer.json", output)
    persist(
        RESULTS / "shared-prefix-models-ready.json",
        {"complete": True, "test_captures": len(output["captures"])},
    )
    print("SHARED PREFIX TRAINING AND TRANSFER COMPLETE", flush=True)


if __name__ == "__main__":
    main()
