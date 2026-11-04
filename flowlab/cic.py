"""Exact pinned corrected CICFlowMeter PCAP bridge; no guessed column mapping."""

import math
import json
import os
import subprocess
import tempfile
from pathlib import Path
import pandas as pd
from .config import ROOT

SCHEMA = "cicflowmeter-improved-completed-v1"
COMMIT = "55f60addd21ada7635a79ee3c596a389756552a6"


def available():
    return (ROOT / "tools/CICFlowMeter/runtime/build.json").exists()


def extract_cic(path, features):
    source = ROOT / "tools/CICFlowMeter"
    runtime = source / "runtime"
    if not available():
        raise ValueError("Run .venv/bin/python scripts/setup_cicflowmeter.py first")
    build = json.loads((runtime / "build.json").read_text())
    if build["commit"] != COMMIT:
        raise ValueError("CICFlowMeter build does not match the pinned feature contract")
    with tempfile.TemporaryDirectory(prefix="flowlab-cic-") as out:
        command = [
            build["java"],
            "-Djava.awt.headless=true",
            f"-Djava.library.path={source}/jnetpcap/linux/jnetpcap-1.4.r1500",
            "-cp",
            f"{runtime}/classes:{runtime}/*:{source}/jnetpcap/linux/jnetpcap-1.4.r1425/jnetpcap.jar",
            "cic.cs.unb.ca.ifm.Cmd",
            str(Path(path).resolve()),
            out,
        ]
        run = subprocess.run(
            command,
            env={**os.environ, "LD_LIBRARY_PATH": str(runtime)},
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if run.returncode:
            raise ValueError("Corrected exporter failed: " + run.stderr[-1500:])
        files = list(Path(out).glob("*.csv"))
        if not files:
            raise ValueError("Corrected exporter emitted no flows")
        frame = pd.concat([pd.read_csv(f) for f in files], ignore_index=True)
    missing = set(features) - set(frame.columns)
    if missing:
        raise ValueError("Corrected exporter schema mismatch: " + ", ".join(sorted(missing)))
    frame[features] = frame[features].apply(pd.to_numeric, errors="coerce")
    return frame


def flow_records(frame, features):
    for index, row in frame.iterrows():
        yield dict(
            flow_id=f"cic-{index}-{row['Flow ID']}",
            src=str(row["Src IP"]),
            dst=str(row["Dst IP"]),
            sport=int(row["Src Port"]),
            dport=int(row["Dst Port"]),
            protocol=int(row["Protocol"]),
            packet_count=int(row["Total Fwd Packet"] + row["Total Bwd packets"]),
            features={f: float(row[f]) if math.isfinite(float(row[f])) else None for f in features},
            extractor_commit=COMMIT,
            observation="completed capture",
            schema=SCHEMA,
        )
