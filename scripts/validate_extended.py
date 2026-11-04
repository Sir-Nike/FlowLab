"""Real final acceptance; waits for observation study to release the lab."""

import json
import time
from flowlab import store
from flowlab.config import RESULTS
from flowlab.live import run_live, peers


def main():
    store.initialize()
    while not (RESULTS / "research-study-ready.json").exists():
        time.sleep(5)
    output = []
    for scenario, model, enforce in [
        ("BENIGN", "cicids2017--rf", False),
        ("BENIGN", "extended_prefix10--extra_tuned", True),
        ("DDoS", "extended_prefix10--extra_tuned", True),
    ]:
        print("Acceptance", scenario, model, flush=True)
        request = dict(
            src="192.168.56.11",
            dst="192.168.56.14",
            scenario=scenario,
            model_id=model,
            enforce=enforce,
            loss_rate=0.1 if scenario == "DDoS" else 0,
            loss_kind="burst",
            seed=991,
            duration=6,
            rate=80,
        )
        result = run_live(request)
        run = store.get(result["live_run_id"])
        output.append(run)
        (RESULTS / "extended-acceptance.json").write_text(json.dumps(output, indent=2))
        print("complete", run["id"], "decisions", run["decisions"], "blocks", len(run["blocks"]), flush=True)
    health = peers()
    if not all(p["online"] for p in health):
        raise RuntimeError("Final agent health check failed")
    (RESULTS / "extended-acceptance-ready.json").write_text(
        json.dumps(
            {"complete": True, "runs": [r["id"] for r in output], "online_agents": len(health)}, indent=2
        )
    )


if __name__ == "__main__":
    main()
