"""Generate a factual report from saved artifacts; no invented experiment scores."""

import json
from flowlab import store
from flowlab.config import DATA, MODELS, RESULTS, ROOT


def main():
    ready = json.loads((RESULTS / "acceptance-ready.json").read_text())
    cic = json.loads((DATA / "cicids2017.json").read_text())
    lines = [
        "# FlowLab measured results",
        "",
        "4 November 2026",
        "",
        "The software, four real KVM guests, packet capture, inference and connection enforcement were exercised locally. These are initial controlled-lab measurements, not a claim of production security or a full reproduction of every paper in the literature review.",
        "",
        "## Corrected CICIDS2017 benchmark",
        "",
        f"The source archive contained {cic['original_rows']:,} rows. Seeded sampling capped each original label at 4,000 rows, then removed duplicate feature vectors. The prepared dataset contains {cic['rows']:,} rows and {len(cic['features'])} input features. Group separation uses host pairs and two-minute time blocks before preprocessing.",
        "",
        "| Model | Test macro F1 | Test accuracy | Benign false positive rate |",
        "| --- | ---: | ---: | ---: |",
    ]
    for p in sorted(MODELS.glob("cicids2017--*.json")):
        m = json.loads(p.read_text())
        t = m["metrics"]["test"]
        lines.append(
            f"| {m['name']} | {t['macro_f1']:.4f} | {t['accuracy']:.4f} | {t['false_positive_rate']:.4f} |"
        )
    lines += [
        "",
        "Macro F1 uses only classes with ground-truth support in the evaluated partition, identically across models. Per-class reports and the confusion matrix retain all corpus labels, including zero-support classes. Attempted-attack labels are retained as supplied. Some rare classes have no training examples; inspect the dashboard before interpreting aggregate scores. Hyperparameters are fixed baselines, not an equal-budget optimization study. Probabilities are not calibrated.",
        "",
        "The corrected CIC exporter has a separate schema. These models classify compatible CSVs; the application refuses to feed its different packet features into them. Transfer from the CIC benchmark directly to live VM traffic has not been established.",
        "",
        "## Real VM packet corpus",
        "",
        "Collected six independent three-second sessions for each of four controlled scenarios: benign web plus occasional UDP traffic, bounded UDP DoS, port probes, and repeated requests to a failing toy authentication endpoint. Four sessions train, one validates and one tests each scenario. Source peers vary across sessions; target Delta remains fixed. All 24 labelled destination captures and their hashes are retained.",
        "",
        "Both completed-flow and ten-packet-prefix models were trained from initialization on the same versioned extraction code used for inference. These tests are deliberately small and regular; high scores demonstrate this lab configuration, not broad attack recognition.",
        "",
        "| Dataset | Model | Test macro F1 | Test rows |",
        "| --- | --- | ---: | ---: |",
    ]
    for dataset in ["lab_completed", "lab_prefix10"]:
        for p in sorted(MODELS.glob(dataset + "--*.json")):
            m = json.loads(p.read_text())
            t = m["metrics"]["test"]
            n = sum(t["report"][label]["support"] for label in t["labels"])
            lines.append(f"| {dataset} | {m['name']} | {t['macro_f1']:.4f} | {int(n)} |")
    lines += [
        "",
        "## Packet loss comparisons",
        "",
        "Ran 576 held-out capture-loss conditions: four labelled test captures × six models × two loss patterns × four requested rates × three corruption seeds. This changes the sensor view of fixed traffic. Actual live link loss is evaluated separately using NetEm.",
        "",
        "| Scenario | Model | Random 10 percent class recall | Burst 10 percent class recall |",
        "| --- | --- | ---: | ---: |",
    ]
    for item in ready["experiments"]:
        ex = store.get(item["experiment_id"])
        (RESULTS / f"{item['scenario']}-loss-results.json").write_text(json.dumps(ex, indent=2))
        for name in ["logistic", "rf", "xgboost", "extra", "mlp", "tabm"]:
            rs = {
                r["kind"]: r
                for r in ex["summary"]
                if r["model_id"] == f"lab_completed--{name}" and r["rate"] == 0.1
            }
            lines.append(
                f"| {item['scenario']} | {name} | {rs['random']['mean_class_recall']:.4f} | {rs['burst']['mean_class_recall']:.4f} |"
            )
    lines += [
        "",
        "Class recall counts completely invisible original flows as missed. Conditional classifier scores are separate. Repeated seeds of one trace quantify corruption variability; they are not independent attack campaigns or confidence intervals across networks. Explanation overlap compares top-five features for at most two matched same-prediction flows per condition and is only a small-sample stability diagnostic.",
        "",
        "## Live enforcement acceptance",
        "",
        "| Scenario | Source link loss | Captured at destination | Flow decisions | Blocked connections | UDP delivered | Firewall packet drops |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: |",
    ]
    for item in ready["live_runs"]:
        run = store.get(item["live_run_id"])
        c = run["destination_counters"]
        drops = sum(
            x.get("counter", {}).get("packets", 0)
            for e in c["firewall"]["nftables"]
            for x in e.get("rule", {}).get("expr", [])
            if e.get("rule", {}).get("chain") == "input"
        )
        lines.append(
            f"| {run['request']['scenario']} | {run['request']['loss_rate']:.0%} burst | {run['packets_observed']} | {run['decisions']} | {len(run['blocks'])} | {c['udp_datagrams']} | {drops} |"
        )
        (RESULTS / f"acceptance-{run['request']['scenario']}.json").write_text(json.dumps(run, indent=2))
    lines += [
        "",
        "These runs used lab_prefix10 Random Forest, trained on real controlled captures. Capture occurs before the destination firewall; raw observed counts therefore include packets later dropped by nftables. Application delivery counters and firewall counters are independently read from the guest. Blocking is connection-specific and confirmed by the agent. Rules and loss are reset after each run.",
        "",
        "## Verification and limits",
        "",
        "- Four QEMU/KVM guests are running and all four authenticated packet sensors responded.",
        "- Python tests cover extraction, closure, loss, split isolation, fingerprints, inference, imports, API origin protection, repeat-run persistence, and agent authorization/command boundaries.",
        "- Desktop and narrow-screen browser checks exercised the dashboard, source selection, decisions, model inspection and experiment results.",
        "- The original mitlab and chess-builder definitions were removed at the user’s request; their dedicated chess disks were deleted and the mitlab files were already absent.",
        "",
        "The current live generators do not reproduce every CICIDS2017 attack family. Single-source UDP load is DoS, not distributed DDoS. The authentication scenario is a toy service, not an SSH/FTP exploit. Production throughput, unseen attack detection, probability calibration, broad cross-network transfer, and literature-wide benchmark claims remain outside the validated results.",
        "",
        "## Reproduce",
        "",
        "```bash",
        "./start.sh",
        ".venv/bin/python -m pytest -q",
        ".venv/bin/python scripts/validate_project.py",
        ".venv/bin/python scripts/report_results.py",
        "```",
        "",
        "Validation sends bounded traffic only among the four isolated lab addresses. Keep guest setup and token files local. Raw results, captures, manifests and model metadata are stored under data, models and results.",
        "",
    ]
    (ROOT / "docs/RESULTS.md").write_text("\n".join(lines))
    print("Wrote docs/RESULTS.md")


if __name__ == "__main__":
    main()
