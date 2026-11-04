"""Isolated-process memory and CPU measurements on a fixed held-out workload."""

import json
import resource
import subprocess
import sys
import time
import numpy as np
import pandas as pd
from flowlab.config import DATA, MODELS, RESULTS
from flowlab.ml import MODEL_NAMES, load_model, predict


def worker(model_id):
    dataset = model_id.split("--")[0]
    meta = json.loads((DATA / f"{dataset}.json").read_text())
    frame = pd.read_csv(DATA / f"{dataset}.csv")
    rows = frame.loc[frame.split == "test", meta["features"]].head(256).to_dict("records")
    before = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    bundle = load_model(model_id)
    predict(bundle, rows[:1])  # Warm imports and estimator caches.
    cpu = time.process_time()
    latencies = []
    for i in range(30):
        start = time.perf_counter()
        predict(bundle, rows[i % len(rows) : i % len(rows) + 1])
        latencies.append(1000 * (time.perf_counter() - start))
    singles_cpu = time.process_time() - cpu
    start = time.perf_counter()
    for _ in range(5):
        predict(bundle, rows)
    batch_seconds = time.perf_counter() - start
    return dict(
        model_id=model_id,
        sampled_test_flows=len(rows),
        warm_single_p50_ms=float(np.median(latencies)),
        warm_single_p95_ms=float(np.quantile(latencies, 0.95)),
        warm_single_p99_ms=float(np.quantile(latencies, 0.99)),
        single_cpu_ms=1000 * singles_cpu / 30,
        batch_flows_per_second=5 * len(rows) / batch_seconds,
        peak_process_rss_mib=resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024,
        before_load_peak_rss_mib=before,
        note="Independent process per model. RSS includes Python, imported libraries, test sample and model. Warm single-flow timings are 30 observations; batch throughput excludes packet decoding, polling and firewall installation.",
    )


def main():
    if len(sys.argv) > 1 and not sys.argv[1].startswith("--"):
        print(json.dumps(worker(sys.argv[1])))
        return
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--datasets", nargs="+", default=["cicids2017", "extended_prefix10"])
    parser.add_argument("--suffix", default="_tuned")
    parser.add_argument("--wait-for")
    parser.add_argument("--output", default="model-performance.json")
    args = parser.parse_args()
    if args.wait_for:
        while not (RESULTS / args.wait_for).exists():
            time.sleep(5)
    output = []
    for dataset in args.datasets:
        for name in MODEL_NAMES:
            model_id = f"{dataset}--{name}{args.suffix}"
            while not (MODELS / f"{model_id}.json").exists():
                time.sleep(5)
            print("Benchmark", model_id, flush=True)
            result = subprocess.run(
                [sys.executable, __file__, model_id], capture_output=True, text=True, check=True
            )
            output.append(json.loads(result.stdout))
            (RESULTS / args.output).write_text(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
