"""Compact aggregates from measured refinement results; uncertainty remains a miss."""

import json
from collections import defaultdict
from statistics import mean
from flowlab.config import DATA, MODELS, RESULTS, ROOT
from flowlab.datasets import fingerprint
from flowlab.ml import MODEL_NAMES


def aggregate(rows):
    matrix = defaultdict(lambda: defaultdict(int))
    truth_labels = set()
    total = accepted = correct_accepted = 0.0
    positives = benign = true_positive = false_positive = false_block = 0.0
    for r in rows:
        c = r["classification"]
        n = sum(sum(row) for row in c["confusion"])
        total += n
        for i, label in enumerate(c["labels"]):
            support = sum(c["confusion"][i])
            if support:
                truth_labels.add(label)
            for j, pred in enumerate(c["labels"]):
                matrix[label][pred] += c["confusion"][i][j]
        accepted += n * r["coverage"]
        correct_accepted += n * r["coverage"] * (r["accepted_accuracy"] or 0)
        if r["attack_recall"] is not None:
            positives += n
            true_positive += n * r["attack_recall"]
        else:
            benign += n
            false_positive += n * r["benign_fpr"]
            false_block += n * r["blocking_fpr"]
    f1 = []
    for label in truth_labels:
        tp = matrix[label][label]
        fn = sum(matrix[label].values()) - tp
        fp = sum(row[label] for t, row in matrix.items() if t != label)
        f1.append(2 * tp / (2 * tp + fn + fp) if 2 * tp + fn + fp else 0)
    return dict(
        flows=int(total),
        macro_f1=mean(f1),
        attack_recall=true_positive / positives if positives else None,
        benign_fpr=false_positive / benign if benign else None,
        benign_block_eligibility=false_block / benign if benign else None,
        coverage=accepted / total,
        accepted_accuracy=correct_accepted / accepted if accepted else None,
        accuracy=sum(matrix[t][t] for t in truth_labels) / total,
        confusion={t: dict(p) for t, p in matrix.items()},
        note="Pooled supported-class macro F1 includes uncertain predictions as errors; binary detection threshold .5; blocking threshold selected on validation benign scores.",
    )


def summarize():
    transfer = json.loads((RESULTS / "refinement-transfer.json").read_text())
    live = json.loads((RESULTS / "refinement-live.json").read_text())
    loss = json.loads((RESULTS / "refinement-capture-loss.json").read_text())
    cic = json.loads((RESULTS / "cic-prefix-ready.json").read_text())
    manifest = json.loads((DATA / "manifests/refined.json").read_text())
    out = dict(
        complete=True,
        corpus_sessions=len(manifest["captures"]),
        heldout_lab_captures=len(transfer["captures"]),
        live_sessions=len(live["conditions"]),
        live_model_comparisons=sum(len(c["models"]) for c in live["conditions"]),
        sensor_loss_conditions=len(loss["conditions"]),
        sensor_model_comparisons=sum(len(c["models"]) for c in loss["conditions"]),
        cic_windows=len(cic["windows"]),
        cic_source_hashes=cic["source_hashes"],
        cic_matching=cic["statistics"],
        regimes={},
        live={},
        sensor_loss={},
        datasets={},
        models={},
        acceptance=[],
    )
    for model in MODEL_NAMES:
        out["regimes"][model] = {
            kind: aggregate([c["models"][model + "_" + kind] for c in transfer["captures"]])
            for kind in ["flow", "context_flat", "lab", "cic", "mixed"]
        }
        out["live"][model] = {}
        out["sensor_loss"][model] = {}
        for kind in ["flow", "context"]:
            key = model + "_" + kind
            out["live"][model][kind] = {
                "all": aggregate([c["models"][key] for c in live["conditions"]]),
                "by_loss": {
                    str(rate): aggregate([c["models"][key] for c in live["conditions"] if c["loss"] == rate])
                    for rate in [0, 0.01, 0.05, 0.1]
                },
            }
            out["sensor_loss"][model][kind] = {
                str(rate): dict(
                    end_to_end_class_recall=mean(
                        c["models"][key]["end_to_end_class_recall"]
                        for c in loss["conditions"]
                        if c["rate"] == rate
                    ),
                    end_to_end_attack_recall=mean(
                        c["models"][key]["end_to_end_attack_recall"]
                        for c in loss["conditions"]
                        if c["rate"] == rate and c["label"] != "BENIGN"
                    ),
                )
                for rate in [0, 0.01, 0.05, 0.1]
            }
    for name in ["refined_flow", "refined_context", "cic_prefix_context", "mixed_prefix_context"]:
        metadata = json.loads((DATA / f"{name}.json").read_text())
        out["datasets"][name] = {
            k: metadata[k] for k in ["rows", "sha256", "features", "counts", "warnings", "split_policy"]
        }
    candidates = []
    for path in MODELS.glob("*_hier.json"):
        m = json.loads(path.read_text())
        if m["dataset"] not in {"refined_context", "cic_prefix_context", "mixed_prefix_context"}:
            continue
        out["models"][m["id"]] = dict(
            dataset_sha256=m["dataset_sha256"],
            artifact_sha256=fingerprint(path.with_suffix(".joblib")),
            threshold=m["threshold"],
            selected_parameters=m["selected_parameters"],
            temperature=m["temperature"],
            validation_binary=m["metrics"]["validation"]["binary"],
            test_binary=m["metrics"]["test"]["binary"],
            test_selective=m["metrics"]["test"]["selective"],
        )
        if m["dataset"] == "mixed_prefix_context":
            candidates.append(m)
    eligible = [
        m
        for m in candidates
        if m["metrics"]["validation"]["selective"]["blocking_false_positive_rate"] <= 0.01
    ]
    winner = max(eligible or candidates, key=lambda m: m["metrics"]["validation"]["binary"]["macro_f1"])
    out["recommended_model"] = winner["id"]
    out["recommendation_policy"] = (
        "Highest mixed-data validation binary macro F1 among models with <=1% validation benign block eligibility; test results not used for selection."
    )
    perf = RESULTS / "refinement-performance.json"
    out["performance"] = json.loads(perf.read_text()) if perf.exists() else []
    accept = RESULTS / "refinement-acceptance.json"
    out["acceptance"] = json.loads(accept.read_text()) if accept.exists() else []

    def compact(value):
        if isinstance(value, dict):
            return {
                k: compact(v)
                for k, v in value.items()
                if k not in {"confusion", "report", "labels", "evaluated_classes", "note"}
            }
        if isinstance(value, list):
            return [compact(v) for v in value]
        return value

    portable = compact(out)
    portable["acceptance"] = []
    for run in out["acceptance"]:
        drops = sum(
            e.get("counter", {}).get("packets", 0)
            for x in run["destination_counters"]["firewall"]["nftables"]
            if x.get("rule", {}).get("chain") == "input"
            for e in x["rule"]["expr"]
        )
        portable["acceptance"].append(
            dict(
                request=run["request"],
                sources=run["sources"],
                packets_observed=run["packets_observed"],
                decisions=run["decisions"],
                destination_counters={
                    k: v
                    for k, v in run["destination_counters"].items()
                    if k in {"udp_datagrams", "http_requests", "auth_success", "auth_failure"}
                },
                firewall_drops=drops,
                blocks=[{"installation_ms": b["installation_ms"]} for b in run["blocks"]],
            )
        )
    portable["metric_definition"] = (
        "Pooled supported-truth-class macro F1; uncertain predictions count as errors. Binary threshold .5; blocking threshold selected on validation. Detailed confusion matrices remain in local raw evidence."
    )
    (RESULTS / "REFINEMENT_SUMMARY.json").write_text(json.dumps(out, indent=2))
    (ROOT / "docs/REFINEMENT_SUMMARY.json").write_text(json.dumps(portable, indent=2))
    print("Refinement summary:", out["recommended_model"], out["live_sessions"], "live sessions", flush=True)
    return out


if __name__ == "__main__":
    summarize()
