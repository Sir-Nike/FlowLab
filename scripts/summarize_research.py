"""Aggregate actual measurements for documentation; never fill absent results."""

import json
from statistics import mean
from flowlab.config import ROOT, RESULTS, MODELS, DATA
from flowlab.ml import MODEL_NAMES
from flowlab.datasets import fingerprint


def metric_summary(values):
    keys = [
        "macro_f1",
        "accuracy",
        "false_positive_rate",
        "inference_ms_per_flow",
        "multiclass_brier",
        "uncalibrated_multiclass_brier",
        "ece_10_bins",
        "unseen_classes",
        "macro_definition",
    ]
    return {key: values[key] for key in keys if key in values}


def summarize():
    live = json.loads((RESULTS / "live-study.json").read_text())
    transfer = json.loads((RESULTS / "cic-transfer.json").read_text())
    manifest = json.loads((DATA / "manifests/extended.json").read_text())
    output = dict(
        live_sessions=len(live["conditions"]),
        transfer_captures=len(transfer["captures"]),
        corpus_sessions=len(manifest["captures"]),
        models={},
        transfer={},
        live={},
        exporter_commit=transfer["exporter_commit"],
        model_artifacts=live.get("model_artifacts", {}),
        corpus_manifest_sha256=fingerprint(DATA / "manifests/extended.json"),
    )
    for name in MODEL_NAMES:
        base = json.loads((MODELS / f"cicids2017--{name}.json").read_text())
        tuned = json.loads((MODELS / f"cicids2017--{name}_tuned.json").read_text())
        lab = json.loads((MODELS / f"extended_prefix10--{name}_tuned.json").read_text())
        output["models"][name] = dict(
            name=MODEL_NAMES[name],
            baseline=metric_summary(base["metrics"]["test"]),
            tuned=metric_summary(tuned["metrics"]["test"]),
            lab=metric_summary(lab["metrics"]["test"]),
            training_seconds=tuned["training_seconds"],
            training_cpu_seconds=tuned["training_cpu_seconds"],
            artifact_mib=tuned["artifact_mib"],
            process_peak_rss_mib=tuned["process_peak_rss_mib"],
            selected_parameters=tuned["selected_parameters"],
            temperature=tuned["temperature"],
        )
        output["transfer"][name] = {
            scenario: mean(
                c["models"][name]["binary_metrics"]["accuracy"]
                for c in transfer["captures"]
                if c["scenario"] == scenario
            )
            for scenario in ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce"]
        }
        output["live"][name] = {}
        for rate in [0, 0.01, 0.05, 0.1]:
            rows = [c for c in live["conditions"] if c["requested_loss"] == rate]
            output["live"][name][str(rate)] = dict(
                sessions=len(rows),
                class_recall=mean(
                    c["models"][name]["metrics"]["report"][c["scenario"]]["recall"] for c in rows
                ),
                benign_fpr=mean(
                    c["models"][name]["false_positive_rate"] for c in rows if c["scenario"] == "BENIGN"
                ),
                attack_recall=mean(
                    c["models"][name]["attack_recall"] for c in rows if c["scenario"] != "BENIGN"
                ),
                inference_ms=mean(c["models"][name]["batch_inference_ms_per_flow"] for c in rows),
                prefix_delay_ms=mean(c["models"][name]["prefix_observation_delay_ms_median"] for c in rows),
                measured_link_loss=mean(c["measured_link_loss"] for c in rows),
            )
    path = ROOT / "docs/STUDY_SUMMARY.json"
    path.write_text(json.dumps(output, indent=2))
    print(path)
    return output


if __name__ == "__main__":
    summarize()
