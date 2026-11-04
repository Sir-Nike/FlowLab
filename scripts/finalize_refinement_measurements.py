"""Finish independent lab acceptance after all observation experiments release VMs."""

import json
import time
from flowlab import store
from flowlab.config import RESULTS
from flowlab.live import run_live, peers
from scripts.summarize_refinement import summarize
from scripts.evaluate_refinement import persist


def main():
    flags = ["refined-live-ready.json", "refined-capture-loss-ready.json", "shared-prefix-models-ready.json"]
    while not all((RESULTS / f).exists() for f in flags):
        time.sleep(5)
    while (
        not (RESULTS / "refinement-performance.json").exists()
        or len(json.loads((RESULTS / "refinement-performance.json").read_text())) < 18
    ):
        time.sleep(5)
    summary = summarize()
    selected = summary["recommended_model"]
    runs = []
    for scenario, model, enforce, count in [
        ("BENIGN", selected, True, 1),
        ("BenignBurst", selected, True, 1),
        ("BenignBurst", selected, True, 3),
        ("DDoS", selected, True, 3),
        ("DoS", "cic_prefix_context--rf_hier", False, 1),
    ]:
        print("Final refined acceptance", scenario, model, count, flush=True)
        request = dict(
            src="192.168.56.11",
            dst="192.168.56.14",
            scenario=scenario,
            source_count=count,
            model_id=model,
            loss_rate=0.1 if scenario == "DDoS" else 0,
            loss_kind="burst",
            seed=1026,
            duration=5,
            rate=80,
            enforce=enforce,
        )
        run = store.get(run_live(request)["live_run_id"])
        runs.append(run)
        persist(RESULTS / "refinement-acceptance.json", runs)
        print("Acceptance observed", run["packets_observed"], "blocks", len(run["blocks"]), flush=True)
    health = peers()
    if not all(p["online"] for p in health):
        raise RuntimeError("Final sensor health check failed")
    summarize()
    persist(
        RESULTS / "refinement-ready.json",
        {"complete": True, "live_sessions": summary["live_sessions"], "online_vms": len(health)},
    )
    job = RESULTS / "refinement-job-id"
    if job.exists():
        store.update(
            job.read_text(),
            status="complete",
            message="Refinement training, transfer, sensor loss, live loss, benchmarks and acceptance complete",
            result={"summary": "/api/refinement"},
        )
    print("REFINEMENT MEASUREMENTS COMPLETE", flush=True)


if __name__ == "__main__":
    main()
