"""Slice real CICIDS PCAPs, match corrected flow labels, extract causal prefixes.

The public mirror is not an official redistribution attestation. Full-file SHA256
must match its published LFS object digest before any extraction starts.
"""

import bisect
import json
import mmap
import struct
import time
import zipfile
from collections import defaultdict
import numpy as np
import pandas as pd
from flowlab.config import DATA, RESULTS
from flowlab.datasets import fingerprint, save_dataset
from flowlab.packets import FEATURES, SCHEMA, read_pcap, extract
from flowlab.context import ALL_FEATURES, SCHEMA as CONTEXT_SCHEMA, extract_context

FILES = {
    "friday": (
        "Friday-WorkingHours.pcap",
        "beff0dcce1eebc9b2454582f4dc8ed0ba0112b2c619a710bf03af93147254cd0",
        8839309056,
    ),
    "wednesday": (
        "Wednesday-workingHours.pcap",
        "cd2674db7559a53f24bc03be3239b315700174ccaef72d10f5edc4c1a08f6186",
        13420789612,
    ),
    "thursday": (
        "Thursday-WorkingHours.pcap",
        "38f8b1bb276849bf1721f7c4de22bebfa7f59a74e52286d4c0a37edbb118fe01",
        8302500180,
    ),
}
LABELS = {
    "BENIGN": "BENIGN",
    "DDoS": "DDoS",
    "Portscan": "PortScan",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS Slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Web Attack - Brute Force": "BruteForce",
}

for original, family in list(LABELS.items()):
    if family in {"DoS", "BruteForce"}:
        LABELS[original + " - Attempted"] = family


def load_corrected(day):
    cols = [
        "id",
        "Src IP",
        "Src Port",
        "Dst IP",
        "Dst Port",
        "Protocol",
        "Timestamp",
        "Flow Duration",
        "Label",
    ]
    with zipfile.ZipFile(DATA / "raw/CICIDS2017_improved.zip") as z:
        f = pd.read_csv(z.open(day + ".csv"), usecols=cols)
    f["start"] = pd.to_datetime(f.Timestamp, utc=True).dt.as_unit("ns").astype("int64") / 1e9
    f["end"] = f.start + f["Flow Duration"] / 1e6
    f["family"] = f.Label.map(LABELS)
    return f


def plan_windows(day, frame):
    windows = []
    for label in sorted(set(frame.Label) & set(LABELS)):
        times = np.sort(frame.loc[frame.Label == label, "start"].to_numpy())
        candidates = np.quantile(times, np.linspace(0.1, 0.9, 6))
        for index, t in enumerate(candidates):
            start = float(t) - 1
            # Entire context windows must be isolated across splits and families.
            if any(not (start + 12 < w["start"] or start > w["end"] + 12) for w in windows):
                continue
            split = "train" if index < 3 else "validation" if index == 3 else "test"
            windows.append(
                dict(
                    start=start,
                    end=start + 10,
                    label=label,
                    family=LABELS[label],
                    split=split,
                    group=f"cic-{day}-{label}-{index}",
                    day=day,
                    path=f"cic-{day}-{len(windows)}.pcap",
                )
            )
    return sorted(windows, key=lambda w: w["start"])


def slice_windows(source, windows, outdir):
    """Select native PCAPNG blocks without decoding the entire multi-GB capture."""
    plan_path = outdir / (source.name + ".windows.json")
    if (
        plan_path.exists()
        and json.loads(plan_path.read_text()) == windows
        and all((outdir / w["path"]).exists() for w in windows)
    ):
        return
    handles = []
    starts = [w["start"] for w in windows]
    count = 0
    with open(source, "rb") as file:
        mm = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)
        if mm[:4] != b"\x0a\x0d\x0d\x0a":
            raise ValueError("This version expects the verified source PCAPNG encoding")
        for window in windows:
            handle = open((outdir / window["path"]).with_suffix(".part"), "wb")
            handle.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
            handles.append(handle)
        offset = 0
        endian = "<"
        interfaces = []
        while offset + 12 <= len(mm):
            raw_type = mm[offset : offset + 4]
            if raw_type == b"\x0a\x0d\x0d\x0a":
                bom = mm[offset + 8 : offset + 12]
                endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else None
                if endian is None:
                    raise ValueError("Invalid PCAPNG byte order")
                interfaces = []
            block_type, length = struct.unpack_from(endian + "II", mm, offset)
            if (
                length < 12
                or length % 4
                or offset + length > len(mm)
                or struct.unpack_from(endian + "I", mm, offset + length - 4)[0] != length
            ):
                raise ValueError("Malformed PCAPNG block boundary")
            if block_type == 1:
                link = struct.unpack_from(endian + "H", mm, offset + 8)[0]
                resolution = 1000000
                option = offset + 16
                while option + 4 <= offset + length - 4:
                    code, n = struct.unpack_from(endian + "HH", mm, option)
                    option += 4
                    if code == 0:
                        break
                    if code == 9 and n == 1:
                        value = mm[option]
                        resolution = 2 ** (value & 127) if value & 128 else 10**value
                    option += (n + 3) // 4 * 4
                interfaces.append((link, resolution))
            elif block_type == 6:
                interface, high, low, captured, original = struct.unpack_from(
                    endian + "IIIII", mm, offset + 8
                )
                if interface >= len(interfaces):
                    raise ValueError("Undefined PCAPNG interface")
                link, resolution = interfaces[interface]
                if captured > 262144 or 28 + captured > length - 4:
                    raise ValueError("Invalid captured packet length")
                timestamp = ((high << 32) | low) / resolution
                index = bisect.bisect_right(starts, timestamp) - 1
                if index >= 0 and timestamp <= windows[index]["end"]:
                    if link != 1:
                        raise ValueError("Selected source interface is not Ethernet")
                    seconds = int(timestamp)
                    micros = round((timestamp - seconds) * 1000000)
                    if micros == 1000000:
                        seconds += 1
                        micros = 0
                    handles[index].write(struct.pack("<IIII", seconds, micros, captured, original))
                    handles[index].write(mm[offset + 28 : offset + 28 + captured])
                    count += 1
            offset += length
        mm.close()
    for handle, window in zip(handles, windows):
        handle.close()
        (outdir / window["path"]).with_suffix(".part").replace(outdir / window["path"])
    plan_path.write_text(json.dumps(windows, indent=2))
    print("Sliced", source.name, "selected packets", count, flush=True)


def tuple_key(protocol, src, sport, dst, dport):
    return (int(protocol), *sorted(((str(src), int(sport)), (str(dst), int(dport)))))


def prepare():
    outdir = DATA / "cic-prefix-captures"
    outdir.mkdir(exist_ok=True)
    rows = {False: [], True: []}
    all_windows = []
    source_hashes = {}
    original_splits = defaultdict(set)
    stats = []
    for day, (filename, expected, size) in FILES.items():
        source = DATA / "raw" / filename
        print("Waiting for complete PCAP", filename, flush=True)
        while not source.exists() or source.stat().st_size < size:
            time.sleep(5)
        if source.stat().st_size != size:
            raise ValueError("Unexpected PCAP length")
        digest = fingerprint(source)
        if digest != expected:
            raise ValueError("Mirror SHA256 does not match published LFS digest")
        source_hashes[filename] = digest
        frame = load_corrected(day)
        windows = plan_windows(day, frame)
        print(
            day,
            "planned windows",
            len(windows),
            "families",
            frame.family.value_counts().to_dict(),
            flush=True,
        )
        slice_windows(source, windows, outdir)
        for w in windows:
            labels = frame[(frame.start >= w["start"] - 0.005) & (frame.start <= w["end"])]
            lookup = defaultdict(list)
            for _, r in labels.iterrows():
                key = tuple_key(r.Protocol, r["Src IP"], r["Src Port"], r["Dst IP"], r["Dst Port"])
                lookup[key].append(r)
            packets, skipped = read_pcap(outdir / w["path"], limit=1500000)
            assigned = 0
            unmatched = 0
            for context in [False, True]:
                flows = (extract_context if context else extract)(packets, prefix=10)
                for f in flows:
                    # Prefix features need a real connection start, not a sliced middle.
                    matches = [
                        r
                        for r in lookup.get(
                            tuple_key(f["protocol"], f["src"], f["sport"], f["dst"], f["dport"]), []
                        )
                        if abs(r.start - f["start"]) <= 0.005 and f["end"] <= r.end + 0.01
                    ]
                    if len(matches) != 1 or pd.isna(matches[0].family):
                        if context:
                            unmatched += 1
                        continue
                    r = matches[0]
                    if f["reason"] == "eof" and r.end > w["end"] + 0.005:
                        if context:
                            unmatched += 1
                        continue
                    identity = f"{day}-{r['id']}"
                    original_splits[identity].add(w["split"])
                    rows[context].append(
                        {
                            **f["features"],
                            "label": r.family,
                            "group": w["group"],
                            "split": w["split"],
                            "original_id": identity,
                            "raw_label": r.Label,
                        }
                    )
                    if context:
                        assigned += 1
            stats.append(
                dict(
                    group=w["group"],
                    packets=len(packets),
                    assigned_prefixes=assigned,
                    discarded_prefixes=unmatched,
                    skipped_packets=skipped,
                    sha256=fingerprint(outdir / w["path"]),
                )
            )
            all_windows.append(w)
            print(w["group"], "assigned", assigned, "discarded", unmatched, flush=True)
    conflicts = {identity for identity, splits in original_splits.items() if len(splits) > 1}
    for context in [False, True]:
        f = pd.DataFrame(rows[context])
        f = f[~f.original_id.isin(conflicts)].drop(columns="original_id")
        if set(f.split) != {"train", "validation", "test"}:
            raise ValueError("Missing split after strict flow matching")
        save_dataset(
            "cic_prefix_context" if context else "cic_prefix_flow",
            f,
            dict(
                schema=CONTEXT_SCHEMA if context else SCHEMA,
                features=ALL_FEATURES if context else FEATURES,
                split_policy="Nonoverlapping capture windows; corrected-flow identities isolated across train, validation and test",
                source="Original CICIDS2017 PCAP mirror plus corrected CNS2022 labels",
                source_url="https://huggingface.co/datasets/bvsam/cic-ids-2017",
                source_hashes=source_hashes,
                corrected_label_archive_sha256=fingerprint(DATA / "raw/CICIDS2017_improved.zip"),
                synthetic=False,
                live_compatible=True,
                observation="prefix10",
                prefix=10,
                context=context,
                seed=42,
                warnings=[
                    "Selected time windows from three capture days; not the whole CICIDS corpus.",
                    "PCAP mirror provenance retained; digest validates mirror content, not an official attestation.",
                    "Only uniquely matched corrected flows with observed starts are included; ambiguous and left- or right-truncated flows are discarded.",
                    "Family labels merge successful and attempted DoS/HTTP guessing; attack means a malicious attempt, not guaranteed compromise.",
                ],
            ),
        )
    report = dict(
        complete=True,
        source_hashes=source_hashes,
        corrected_label_archive_sha256=fingerprint(DATA / "raw/CICIDS2017_improved.zip"),
        windows=all_windows,
        statistics=stats,
        discarded_cross_split_originals=len(conflicts),
    )
    (RESULTS / "cic-prefix-ready.json").write_text(json.dumps(report, indent=2))
    print("CIC PREFIX PREPARATION COMPLETE", flush=True)


if __name__ == "__main__":
    prepare()
