"""Resumable ranged PCAP mirror download with exact size and SHA256 checks."""

import concurrent.futures
import json
import time
import urllib.request
from flowlab.config import DATA, RESULTS
from flowlab.datasets import fingerprint
from scripts.prepare_cic_prefix import FILES


def fetch(task):
    filename, start, end, output = task
    expected = end - start + 1
    for attempt in range(5):
        have = output.stat().st_size if output.exists() else 0
        if have == expected:
            return
        if have > expected:
            raise ValueError("Unexpected partial size")
        url = f"https://huggingface.co/datasets/bvsam/cic-ids-2017/resolve/main/pcap/{filename}?download=true&slice={start}&time={int(time.time())}"
        req = urllib.request.Request(url, headers={"Range": f"bytes={start + have}-{end}"})
        try:
            with urllib.request.urlopen(req, timeout=90) as response:
                if (
                    response.status != 206
                    or response.headers.get("Content-Range")
                    != f"bytes {start + have}-{end}/{next(v[2] for v in FILES.values() if v[0] == filename)}"
                ):
                    raise ValueError("Server did not honor exact byte range")
                with output.open("ab") as stream:
                    while block := response.read(4 * 1024 * 1024):
                        stream.write(block)
            if output.stat().st_size == expected:
                print("Downloaded", filename, start, end, flush=True)
                return
        except (OSError, ValueError) as exc:
            if attempt == 4:
                raise
            print("Retry", filename, start, type(exc).__name__, flush=True)
    raise RuntimeError("Incomplete PCAP range")


def main():
    ranges = DATA / "raw/ranges"
    ranges.mkdir(exist_ok=True)
    tasks = []
    plans = []
    for day, (filename, digest, size) in FILES.items():
        source = DATA / "raw" / filename
        prefix = ranges / (filename + ".prefix")
        if source.exists() and source.stat().st_size == size:
            print("Already downloaded", filename, flush=True)
            continue
        if source.exists() and not prefix.exists():
            source.replace(prefix)
        start = prefix.stat().st_size if prefix.exists() else 0
        boundaries = [start + (size - start) * i // 8 for i in range(9)]
        parts = []
        for i in range(8):
            a, b = boundaries[i], boundaries[i + 1] - 1
            path = ranges / (filename + f".range{i}")
            tasks.append((filename, a, b, path))
            parts.append(path)
        plans.append((source, prefix, parts, digest, size))
    # Interleave capture days and bound total connections.
    tasks.sort(key=lambda x: x[1])
    with concurrent.futures.ThreadPoolExecutor(max_workers=9) as pool:
        list(pool.map(fetch, tasks))
    for source, prefix, parts, digest, size in plans:
        staging = source.with_suffix(".assembling")
        with staging.open("wb") as target:
            for part in [prefix, *parts]:
                if not part.exists():
                    continue
                with part.open("rb") as chunk:
                    while block := chunk.read(16 * 1024 * 1024):
                        target.write(block)
        if staging.stat().st_size != size or fingerprint(staging) != digest:
            raise ValueError("PCAP checksum mismatch")
        staging.replace(source)
        print("Verified PCAP", source.name, size, digest, flush=True)
    (RESULTS / "pcap-download-ready.json").write_text(
        json.dumps({"complete": True, "source": "https://huggingface.co/datasets/bvsam/cic-ids-2017"})
    )


if __name__ == "__main__":
    main()
