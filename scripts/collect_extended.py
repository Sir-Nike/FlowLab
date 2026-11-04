"""Independent, varied, longer capture sessions for the extended controlled study."""

import json
from flowlab import store
from flowlab.config import DATA, RESULTS
from flowlab.live import run_live
from flowlab.datasets import prepare_pcaps
from flowlab.ml import train


def main():
    store.initialize()
    path = DATA / "manifests/extended.json"
    path.parent.mkdir(exist_ok=True)
    manifest = (
        json.loads(path.read_text())
        if path.exists()
        else {"synthetic": False, "controlled_lab": True, "captures": []}
    )
    for episode in range(8):
        split = "train" if episode < 4 else "validation" if episode < 6 else "test"
        for scenario in ["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce"]:
            group = f"extended-{episode}-{scenario}"
            if any(c["group"] == group for c in manifest["captures"]):
                continue
            dst = 11 + episode % 4
            src = 11 + (episode + 1) % 4
            print(group, split, flush=True)
            request = dict(
                src=f"192.168.56.{src}",
                dst=f"192.168.56.{dst}",
                scenario=scenario,
                model_id="lab_prefix10--rf",
                loss_rate=0,
                loss_kind="random",
                seed=2026 + episode,
                duration=8 + episode % 3,
                rate=[30, 65, 100, 140][episode % 4],
                enforce=False,
            )
            result = run_live(request)
            run = store.get(result["live_run_id"])
            capture = store.get(run["capture_ids"][-1], "capture")
            manifest["captures"].append(
                dict(
                    path=f"../captures/{capture['filename']}",
                    label=scenario,
                    group=group,
                    split=split,
                    run_id=run["id"],
                    request=request,
                )
            )
            path.write_text(json.dumps(manifest, indent=2))
            print(
                "packets",
                run["packets_observed"],
                "auth failures",
                run["destination_counters"].get("auth_failure"),
                flush=True,
            )
    for prefix in [None, 10]:
        name = "extended_completed" if prefix is None else "extended_prefix10"
        prepare_pcaps(path, name=name, prefix=prefix)
        train(name, progress=print)
    (RESULTS / "extended-corpus-ready.json").write_text(
        json.dumps({"manifest": str(path), "captures": len(manifest["captures"])}, indent=2)
    )


if __name__ == "__main__":
    main()
