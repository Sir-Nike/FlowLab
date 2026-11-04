"""Collect independent controlled VM episodes; never mixes scenario labels into features."""

import json
from flowlab import store
from flowlab.config import DATA, RESULTS
from flowlab.live import run_live
from flowlab.datasets import prepare_pcaps
from flowlab.ml import train


def main():
    store.initialize()
    captures = []
    for episode in range(6):
        split = "train" if episode < 4 else "validation" if episode == 4 else "test"
        for scenario in ["BENIGN", "DoS", "PortScan", "BruteForce"]:
            print(f"Collecting episode {episode + 1} {scenario} ({split})", flush=True)
            result = run_live(
                {
                    "src": f"192.168.56.{11 + episode % 3}",
                    "dst": "192.168.56.14",
                    "scenario": scenario,
                    "model_id": "fixture_prefix10--rf",
                    "loss_rate": 0,
                    "loss_kind": "random",
                    "seed": 100 + episode,
                    "duration": 3,
                    "rate": 60,
                    "enforce": False,
                },
                progress=lambda _: None,
            )
            run = store.get(result["live_run_id"])
            # Destination capture is after the physical link and before input filtering.
            capture = store.get(run["capture_ids"][-1], "capture")
            captures.append(
                {
                    "path": f"../captures/{capture['filename']}",
                    "label": scenario,
                    "group": f"episode-{episode}-{scenario}",
                    "split": split,
                }
            )
            print(
                f"  {run['packets_observed']} captured packets; {run['decisions']} provisional decisions",
                flush=True,
            )
    manifest = {"synthetic": False, "controlled_lab": True, "captures": captures}
    path = DATA / "manifests/lab.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(manifest, indent=2))
    for prefix in [None, 10]:
        name = "lab_completed" if prefix is None else "lab_prefix10"
        prepare_pcaps(path, name=name, prefix=prefix)
        train(name, progress=print)
    (RESULTS / "lab-corpus-ready.json").write_text(
        json.dumps({"manifest": str(path), "captures": len(captures)}, indent=2)
    )


if __name__ == "__main__":
    main()
