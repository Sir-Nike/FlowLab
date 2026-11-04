"""Bounded data preparation with group-separated splits and provenance."""

import json
import zipfile
from hashlib import sha256
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from .config import DATA
from .fixtures import SCENARIOS, generate
from .packets import FEATURES, SCHEMA, apply_loss, extract, read_pcap

SOURCE = "https://intrusion-detection.distrinet-research.be/CNS2022/Datasets/CICIDS2017_improved.zip"
EXCLUDE = {
    "id",
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Timestamp",
    "Label",
    "Attempted Category",
    "ICMP Code",
    "ICMP Type",
}


def fingerprint(path):
    h = sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def split_groups(frame, seed=42):
    if frame.group.nunique() < 6:
        raise ValueError("At least six independent traffic groups are required")
    outer = GroupShuffleSplit(n_splits=1, test_size=0.2, random_state=seed)
    trainval, test = next(outer.split(frame, groups=frame.group))
    inner = GroupShuffleSplit(n_splits=1, test_size=0.25, random_state=seed + 1)
    train, valid = next(inner.split(frame.iloc[trainval], groups=frame.iloc[trainval].group))
    split = np.full(len(frame), "test", dtype=object)
    split[trainval[train]] = "train"
    split[trainval[valid]] = "validation"
    frame = frame.copy()
    frame["split"] = split
    return frame


def save_dataset(name, frame, metadata):
    frame = frame.reset_index(drop=True)
    path = DATA / f"{name}.csv"
    frame.to_csv(path, index=False)
    metadata.update(
        name=name,
        rows=len(frame),
        sha256=fingerprint(path),
        counts=pd.crosstab(frame.label, frame.split).to_dict(),
        split_policy=metadata.get("split_policy", "GroupShuffleSplit 60/20/20 before preprocessing"),
        warnings=metadata.get("warnings", []),
    )
    (DATA / f"{name}.json").write_text(json.dumps(metadata, indent=2))
    return metadata


def prepare_cic(archive=None, per_class=5000, seed=42):
    archive = Path(archive or DATA / "raw/CICIDS2017_improved.zip")
    rng = np.random.default_rng(seed)
    reservoirs = {}
    features = None
    raw_count = 0
    with zipfile.ZipFile(archive) as z:
        for name in sorted(z.namelist()):
            if not name.endswith(".csv"):
                continue
            with z.open(name) as stream:
                for frame in pd.read_csv(stream, chunksize=75000, low_memory=False):
                    frame.columns = frame.columns.str.strip()
                    raw_count += len(frame)
                    if features is None:
                        features = [c for c in frame.columns if c not in EXCLUDE]
                    # Host pairs and two-minute time blocks keep near-related rows together.
                    a, b = frame["Src IP"].astype(str), frame["Dst IP"].astype(str)
                    pair = np.where(a < b, a + "/" + b, b + "/" + a)
                    blocks = pd.to_datetime(frame.Timestamp, errors="coerce").dt.floor("2min").astype(str)
                    frame["group"] = name + ":" + pd.Series(pair, index=frame.index) + ":" + blocks
                    frame["label"] = frame.Label.astype(str).str.strip()
                    frame = frame[features + ["label", "group"]].copy()
                    frame[features] = frame[features].apply(pd.to_numeric, errors="coerce")
                    frame["_priority"] = rng.random(len(frame))
                    for label, part in frame.groupby("label"):
                        old = reservoirs.get(label)
                        pool = pd.concat([old, part]) if old is not None else part
                        reservoirs[label] = pool.nsmallest(per_class, "_priority")
    frame = pd.concat(reservoirs.values(), ignore_index=True).drop(columns="_priority")
    # Exact duplicate feature rows never straddle partitions, including conflicting labels.
    frame = frame.drop_duplicates(subset=features, keep="first")
    frame = split_groups(frame, seed)
    return save_dataset(
        "cicids2017",
        frame,
        {
            "schema": "cicflowmeter-improved-completed-v1",
            "features": features,
            "source": SOURCE,
            "source_sha256": fingerprint(archive),
            "original_rows": raw_count,
            "synthetic": False,
            "live_compatible": False,
            "observation": "completed",
            "seed": seed,
            "per_class_cap": per_class,
            "warnings": [
                "Class-balanced capped sample, not natural deployment prevalence.",
                "Time-block and host-pair split is not independent campaign validation.",
                "CIC exporter models cannot classify FlowLab packet features.",
                "Rare classes may be absent in training or held-out partitions.",
            ],
        },
    )


def prepare_fixture(seed=42, episodes=24, prefix=None, augment=False):
    rows = []
    # Independent episodes, including all corruptions, stay in the same partition.
    for episode in range(episodes):
        for j, label in enumerate(SCENARIOS):
            packets = generate(label, seed + episode * 7 + j, count=12)
            variants = [(0, "random")]
            if augment:
                variants += [(0.05, "random"), (0.1, "burst")]
            for rate, kind in variants:
                flows = extract(apply_loss(packets, rate, kind, seed + episode), prefix=prefix)
                for flow in flows:
                    rows.append({**flow["features"], "label": label, "group": f"episode-{episode}"})
    frame = split_groups(pd.DataFrame(rows), seed)
    suffix = f"prefix{prefix}" if prefix else "completed"
    name = f"fixture_{suffix}" + ("_augmented" if augment else "")
    return save_dataset(
        name,
        frame,
        {
            "schema": SCHEMA,
            "features": FEATURES,
            "source": "FlowLab generated packet fixtures",
            "synthetic": True,
            "live_compatible": True,
            "observation": suffix,
            "prefix": prefix,
            "seed": seed,
            "augmentation": augment,
            "warnings": [
                "Synthetic functional validation only. Scores are not evidence of real attack detection."
            ],
        },
    )


def prepare_pcaps(manifest_path, name="pcap_training", prefix=None, context=False):
    from .context import extract_context, SCHEMA as CONTEXT_SCHEMA, ALL_FEATURES

    manifest_path = Path(manifest_path).resolve()
    manifest = json.loads(manifest_path.read_text())
    rows, hashes = [], {}
    for item in manifest["captures"]:
        path = (manifest_path.parent / item["path"]).resolve()
        digest = fingerprint(path)
        hashes.setdefault(digest, set()).add(item["split"])
        if item["split"] not in {"train", "validation", "test"}:
            raise ValueError("Capture split must be train, validation or test")
        packets, _ = read_pcap(path)
        flows = extract_context(packets, prefix=prefix) if context else extract(packets, prefix=prefix)
        for flow in flows:
            rows.append(
                {**flow["features"], "label": item["label"], "group": item["group"], "split": item["split"]}
            )
    if any(len(splits) > 1 for splits in hashes.values()):
        raise ValueError("Same PCAP content appears in multiple splits")
    frame = pd.DataFrame(rows)
    if frame.empty or set(frame.split) != {"train", "validation", "test"}:
        raise ValueError("Nonempty train, validation and test captures are required")
    if (frame.groupby("group").split.nunique() > 1).any():
        raise ValueError("A traffic group appears in multiple splits")
    return save_dataset(
        name,
        frame,
        {
            "schema": CONTEXT_SCHEMA if context else SCHEMA,
            "features": ALL_FEATURES if context else FEATURES,
            "source": str(manifest_path),
            "source_sha256": fingerprint(manifest_path),
            "capture_hashes": list(hashes),
            "synthetic": bool(manifest.get("synthetic", False)),
            "live_compatible": True,
            "observation": f"prefix{prefix}" if prefix else "completed",
            "prefix": prefix,
            "controlled_lab": bool(manifest.get("controlled_lab", False)),
            "split_policy": "Explicit capture-group partitions from manifest; no group crosses partitions",
            "context": context,
            "warnings": [
                "Manifest labels apply to every flow in each capture; use homogeneous captures.",
                "Controlled lab traffic does not establish generalization to Internet attacks.",
            ],
        },
    )
