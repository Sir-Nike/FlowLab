"""Legitimate single-source bursts challenge source-count shortcuts."""

import json
import time
from flowlab import store
from flowlab.config import DATA, RESULTS
from flowlab.live import run_live
from flowlab.datasets import prepare_pcaps, fingerprint
from flowlab.ml import train, MODEL_NAMES


def main():
    while not (RESULTS / "refined-corpus-ready.json").exists():
        time.sleep(5)
    path = DATA / "manifests/refined.json"
    manifest = json.loads(path.read_text())
    for episode in range(10):
        group = f"refined-{episode}-BenignBurstSingle"
        if any(c["group"] == group for c in manifest["captures"]):
            continue
        print("Single benign burst", episode, flush=True)
        request = dict(
            src=f"192.168.56.{11 + (episode + 1) % 4}",
            dst=f"192.168.56.{11 + episode % 4}",
            scenario="BenignBurst",
            source_count=1,
            model_id="extended_prefix10--rf_tuned",
            loss_rate=0,
            loss_kind="random",
            seed=730 + episode,
            duration=7 + episode % 3,
            rate=[35, 75, 110, 150, 60][episode % 5],
            enforce=False,
        )
        run = store.get(run_live(request)["live_run_id"])
        capture = store.get(run["capture_ids"][-1], "capture")
        manifest["captures"].append(
            dict(
                path=f"../captures/{capture['filename']}",
                label="BENIGN",
                scenario="BenignBurstSingle",
                group=group,
                split="train" if episode < 6 else "validation" if episode < 8 else "test",
                run_id=run["id"],
                request=request,
            )
        )
        path.write_text(json.dumps(manifest, indent=2))
    for context in [False, True]:
        dataset = "refined_context" if context else "refined_flow"
        metadata_path = DATA / f"{dataset}.json"
        if not metadata_path.exists() or json.loads(metadata_path.read_text()).get(
            "source_sha256"
        ) != fingerprint(path):
            prepare_pcaps(path, name=dataset, prefix=10, context=context)
        metadata = json.loads(metadata_path.read_text())
        from flowlab.config import MODELS

        suffix = "_hier" if context else "_tuned"
        existing = [MODELS / f"{dataset}--{name}{suffix}.json" for name in MODEL_NAMES]
        if not all(
            p.exists() and json.loads(p.read_text())["dataset_sha256"] == metadata["sha256"] for p in existing
        ):
            train(dataset, study=True, hierarchical=context, progress=lambda s: print(s, flush=True))
    (RESULTS / "refined-augmented-ready.json").write_text(
        json.dumps({"complete": True, "captures": len(manifest["captures"])})
    )


if __name__ == "__main__":
    main()
