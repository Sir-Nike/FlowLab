from dataclasses import replace
from time import perf_counter

import numpy as np

from . import store
from .config import DATA
from .fixtures import generate, write_pcap
from .ml import load_model, metrics, predict
from .packets import SCHEMA, FlowMeter, apply_loss, extract, read_pcap
from .context import SCHEMA as CONTEXT_SCHEMA, extract_context


def identify_originals(packets):
    meter = FlowMeter()
    copies = [replace(p) for p in packets]
    for packet in copies:
        output = meter.push(packet)
        flow = meter.flows.get(packet.key)
        packet.origin = flow.id if flow else output[-1]["id"]
    return copies


def get_packets(source, label, seed, src, dst, capture_id=None):
    if source == "fixture":
        packets = generate(label, seed=seed, source=src, target=dst)
        return packets, label, True, 0
    capture = store.get(capture_id, "capture")
    packets, skipped = read_pcap(DATA / "captures" / capture["filename"])
    return packets, capture.get("label"), False, skipped


def analyze(
    model_id,
    packets,
    label=None,
    rate=0,
    kind="random",
    seed=42,
    explain=True,
    synthetic=False,
    source="capture",
):
    bundle = load_model(model_id)
    meta = bundle["metadata"]
    if meta["schema"] not in {SCHEMA, CONTEXT_SCHEMA}:
        raise ValueError(
            "This is a CSV benchmark model. Select a FlowLab packet model for packet experiments."
        )
    packets = identify_originals(packets)
    origins = {p.origin for p in packets}
    kept = apply_loss(packets, rate, kind, seed)
    start = perf_counter()
    flows = (extract_context if meta["schema"] == CONTEXT_SCHEMA else extract)(
        kept, prefix=meta.get("prefix")
    )
    predictions = predict(bundle, [f["features"] for f in flows], explain=False) if flows else []
    processing_ms = (perf_counter() - start) * 1000
    rows = []
    for flow, decision in zip(flows, predictions):
        if explain and len(rows) < 2:
            decision["explanation"] = predict(bundle, [flow["features"]], explain=True)[0]["explanation"]
        policy = (
            "would_block"
            if decision["prediction"] != "BENIGN"
            and decision.get("block_eligible", decision["attack_score"] >= meta["threshold"])
            else ("allow" if decision["prediction"] == "BENIGN" else "alert")
        )
        rows.append(
            {
                **flow,
                **decision,
                "policy": policy,
                "enforced": False,
                "observation_seconds": flow["end"] - flow["start"],
            }
        )
    visible = {origin for flow in flows for origin in flow["origins"]}
    detected = {origin for flow in rows if flow["prediction"] != "BENIGN" for origin in flow["origins"]}
    correct = {origin for flow in rows if flow["prediction"] == label for origin in flow["origins"]}
    result = {
        "model_id": model_id,
        "model_name": meta["name"],
        "model_synthetic": meta["synthetic"],
        "source": source,
        "traffic_synthetic": synthetic,
        "ground_truth": label,
        "loss_kind": kind,
        "loss_rate": rate,
        "seed": seed,
        "packets_original": len(packets),
        "packets_observed": len(kept),
        "actual_loss": 1 - len(kept) / len(packets) if packets else 0,
        "flows_original": len(origins),
        "flows_observed": len(flows),
        "flows_invisible": len(origins - visible),
        "processing_ms": processing_ms,
        "observation": meta["observation"],
        "schema": meta["schema"],
        "conditional": metrics([label] * len(rows), [r["prediction"] for r in rows])
        if label and rows
        else None,
        "end_to_end_attack_recall": len(detected) / len(origins)
        if label and label != "BENIGN" and origins
        else None,
        "end_to_end_class_recall": len(correct) / len(origins) if label and origins else None,
        "rows": rows,
        "enforcement": "observation only; no packets sent or blocked",
    }
    return result


def run_scenario(request, progress=lambda _: None):
    packets, label, synthetic, skipped = get_packets(
        request["source"],
        request["scenario"],
        request["seed"],
        request["src"],
        request["dst"],
        request.get("capture_id"),
    )
    progress(f"Extracting {len(packets):,} packets")
    result = analyze(
        request["model_id"],
        packets,
        label,
        request["loss_rate"],
        request["loss_kind"],
        request["seed"],
        synthetic=synthetic,
        source=request["source"],
    )
    result["skipped_packets"] = skipped
    record = store.add("run", result)
    if request["source"] == "fixture":
        write_pcap(packets, DATA / "captures" / f"{record['id']}.pcap")
        store.update(record["id"], pcap_available=True)
    for row in result["rows"][:100]:
        store.add(
            "decision",
            {
                **row,
                "run_id": record["id"],
                "model_id": request["model_id"],
                "synthetic": synthetic or result["model_synthetic"],
            },
        )
    return {"run_id": record["id"]}


def matrix(request, progress=lambda _: None):
    packets, label, synthetic, _ = get_packets(
        request["source"],
        request["scenario"],
        request["seed"],
        request["src"],
        request["dst"],
        request.get("capture_id"),
    )
    rows = []
    for model_id in request["model_ids"]:
        baseline = analyze(
            model_id, packets, label, explain=True, synthetic=synthetic, source=request["source"]
        )
        clean = {o: row for row in baseline["rows"] for o in row["origins"]}
        for kind in request["kinds"]:
            for rate in request["rates"]:
                for seed in request["seeds"]:
                    progress(f"{model_id} · {kind} {rate:.0%} · seed {seed}")
                    result = analyze(
                        model_id,
                        packets,
                        label,
                        rate,
                        kind,
                        seed,
                        explain=True,
                        synthetic=synthetic,
                        source=request["source"],
                    )
                    observed = {o: row for row in result["rows"] for o in row["origins"]}
                    shared = clean.keys() & observed.keys()
                    result["prediction_change_rate"] = (
                        sum(clean[o]["prediction"] != observed[o]["prediction"] for o in shared) / len(shared)
                        if shared
                        else None
                    )
                    overlaps, signs = [], []
                    for origin in sorted(shared):
                        a, b = clean[origin], observed[origin]
                        if (
                            a["prediction"] != b["prediction"]
                            or not a.get("explanation")
                            or not b.get("explanation")
                        ):
                            continue
                        if a["explanation"]["method"] != b["explanation"]["method"]:
                            continue
                        fa = {f["feature"]: f["contribution"] for f in a["explanation"]["features"][:5]}
                        fb = {f["feature"]: f["contribution"] for f in b["explanation"]["features"][:5]}
                        intersection = fa.keys() & fb.keys()
                        overlaps.append(len(intersection) / len(fa.keys() | fb.keys()))
                        signs.extend(float(np.sign(fa[f]) == np.sign(fb[f])) for f in intersection)
                    result["explanation_stability"] = {
                        "same_class_matched_samples": len(overlaps),
                        "mean_top5_jaccard": float(np.mean(overlaps)) if overlaps else None,
                        "direction_agreement": float(np.mean(signs)) if signs else None,
                        "note": "Up to two explained flows per condition, compared only when predicted class and method agree",
                    }
                    result.pop("rows")
                    rows.append(result)
    summary = []
    for model in request["model_ids"]:
        for kind in request["kinds"]:
            for rate in request["rates"]:
                matched = [
                    r
                    for r in rows
                    if r["model_id"] == model and r["loss_kind"] == kind and r["loss_rate"] == rate
                ]
                vals = [
                    r["end_to_end_class_recall"] for r in matched if r["end_to_end_class_recall"] is not None
                ]
                stability = [
                    r["explanation_stability"]["mean_top5_jaccard"]
                    for r in matched
                    if r["explanation_stability"]["mean_top5_jaccard"] is not None
                ]
                summary.append(
                    {
                        "model_id": model,
                        "kind": kind,
                        "rate": rate,
                        "mean_class_recall": float(np.mean(vals)) if vals else None,
                        "std_class_recall": float(np.std(vals, ddof=1)) if len(vals) > 1 else None,
                        "seeds": len(matched),
                        "mean_top5_jaccard": float(np.mean(stability)) if stability else None,
                        "explained_samples": sum(
                            r["explanation_stability"]["same_class_matched_samples"] for r in matched
                        ),
                    }
                )
    record = store.add(
        "experiment",
        {
            "request": request,
            "results": rows,
            "summary": summary,
            "traffic_synthetic": synthetic,
            "ground_truth": label,
            "note": "Repeated corruption seeds of one trace measure loss variability, not independent attack campaigns.",
        },
    )
    return {"experiment_id": record["id"]}
