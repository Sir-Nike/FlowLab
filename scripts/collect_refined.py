"""New independent episodes, including multi-source legitimate traffic."""

import json
from flowlab import store
from flowlab.config import DATA, RESULTS
from flowlab.live import run_live
from flowlab.datasets import prepare_pcaps, fingerprint
from flowlab.ml import train, MODEL_NAMES

SCENARIOS = ["BENIGN", "BenignBurst", "DoS", "HTTPDoS", "DDoS", "PortScan", "BruteForce"]


def main():
    store.initialize()
    path = DATA / "manifests/refined.json"
    manifest = (
        json.loads(path.read_text())
        if path.exists()
        else dict(synthetic=False, controlled_lab=True, captures=[])
    )
    for episode in range(10):
        split = "train" if episode < 6 else "validation" if episode < 8 else "test"
        for scenario in SCENARIOS:
            group = f"refined-{episode}-{scenario}"
            if any(c["group"] == group for c in manifest["captures"]):
                continue
            target = 11 + episode % 4
            source = 11 + (episode + 1) % 4
            request = dict(
                src=f"192.168.56.{source}",
                dst=f"192.168.56.{target}",
                scenario=scenario,
                model_id="extended_prefix10--rf_tuned",
                loss_rate=0,
                loss_kind="random",
                seed=730 + episode,
                duration=7 + episode % 3,
                rate=[35, 75, 110, 150, 60][episode % 5],
                enforce=False,
            )
            print("Collect", group, split, flush=True)
            r = store.get(run_live(request)["live_run_id"])
            c = store.get(r["capture_ids"][-1], "capture")
            label = "BENIGN" if scenario == "BenignBurst" else "DoS" if scenario == "HTTPDoS" else scenario
            manifest["captures"].append(
                dict(
                    path=f"../captures/{c['filename']}",
                    label=label,
                    scenario=scenario,
                    group=group,
                    split=split,
                    run_id=r["id"],
                    request=request,
                )
            )
            path.write_text(json.dumps(manifest, indent=2))
            print("Packets", r["packets_observed"], flush=True)
    for context in [False, True]:
        name = "refined_context" if context else "refined_flow"
        metadata_path = DATA / f"{name}.json"
        if not metadata_path.exists() or json.loads(metadata_path.read_text()).get(
            "source_sha256"
        ) != fingerprint(path):
            prepare_pcaps(path, name=name, prefix=10, context=context)
        metadata = json.loads(metadata_path.read_text())
        from flowlab.config import MODELS

        suffix = "_hier" if context else "_tuned"
        existing = [MODELS / f"{name}--{model}{suffix}.json" for model in MODEL_NAMES]
        if not all(
            p.exists() and json.loads(p.read_text())["dataset_sha256"] == metadata["sha256"] for p in existing
        ):
            train(name, study=True, hierarchical=context, progress=lambda s: print(s, flush=True))
    (RESULTS / "refined-corpus-ready.json").write_text(
        json.dumps({"complete": True, "captures": len(manifest["captures"])})
    )


if __name__ == "__main__":
    main()
