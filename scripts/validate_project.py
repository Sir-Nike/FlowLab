"""Measured acceptance suite using real held-out lab captures and real VM enforcement."""

import json
import os
from pathlib import Path
from flowlab import store
from flowlab.config import DATA, MODELS, RESULTS
from flowlab.datasets import prepare_pcaps
from flowlab.experiments import matrix
from flowlab.live import run_live, peers
from flowlab.ml import train, MODEL_NAMES


def main():
    ready = RESULTS / "acceptance-ready.json"
    ready.unlink(missing_ok=True)
    store.initialize()
    job = store.add(
        "job",
        {
            "kind": "real lab acceptance",
            "status": "running",
            "pid": os.getpid(),
            "message": "Preparing real packet models and held-out loss matrices",
            "external_result": ready.name,
            "completion_message": "Real packet models, held-out loss comparisons, and live enforcement validated",
        },
    )

    def progress(msg):
        print(msg, flush=True)
        store.update(job["id"], message=msg)

    try:
        manifest = DATA / "manifests/lab.json"
        for prefix in [None, 10]:
            name = "lab_completed" if prefix is None else "lab_prefix10"
            prepare_pcaps(manifest, name=name, prefix=prefix)
            train(name, progress=progress)
        train("cicids2017", algorithms=["mlp"], progress=progress)
        captures = {c["filename"]: c for c in store.listing("capture", 1000)}
        experiments = []
        for item in json.loads(manifest.read_text())["captures"]:
            if item["split"] != "test":
                continue
            capture = captures[Path(item["path"]).name]
            progress("Held-out packet-loss matrix: " + item["label"])
            result = matrix(
                {
                    "source": "capture",
                    "scenario": "BENIGN",
                    "seed": 42,
                    "src": "192.168.56.11",
                    "dst": "192.168.56.14",
                    "capture_id": capture["id"],
                    "model_ids": [f"lab_completed--{m}" for m in MODEL_NAMES],
                    "rates": [0, 0.01, 0.05, 0.1],
                    "kinds": ["random", "burst"],
                    "seeds": [41, 42, 43],
                },
                progress=lambda _: None,
            )
            experiments.append({"scenario": item["label"], **result})
        live = []
        for label, loss, enforce in [("BENIGN", 0, False), ("DoS", 0.1, True)]:
            progress("Real VM acceptance: " + label)
            result = run_live(
                {
                    "src": "192.168.56.11",
                    "dst": "192.168.56.12",
                    "scenario": label,
                    "model_id": "lab_prefix10--rf",
                    "loss_rate": loss,
                    "loss_kind": "burst",
                    "seed": 42,
                    "duration": 3,
                    "rate": 100,
                    "enforce": enforce,
                },
                progress=lambda _: None,
            )
            run = store.get(result["live_run_id"])
            assert run["packets_observed"] > 0
            if enforce:
                assert len(run["blocks"]) > 0, "Expected an installed connection rule"
            live.append(result)
        summary = {
            "models": len(list(MODELS.glob("*.json"))),
            "experiments": experiments,
            "live_runs": live,
            "peers_connected": sum(p["online"] for p in peers()),
            "manifest": str(manifest),
        }
        ready.write_text(json.dumps(summary, indent=2))
        store.update(
            job["id"],
            status="complete",
            message="Real packet models and live enforcement validated",
            result=summary,
        )
        progress("Acceptance passed")
    except Exception as exc:
        store.update(job["id"], status="failed", message=str(exc))
        raise


if __name__ == "__main__":
    main()
