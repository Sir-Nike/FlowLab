"""Update our already-provisioned guests without touching host privileges."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import subprocess
from flowlab.live import resolve_peers

root = Path(__file__).resolve().parents[1]
source = (root / "lab/agent.py").read_bytes()


def deploy(item):
    i, peer = item
    key = root / f"lab/.vagrant/machines/flowlab{i}/libvirt/private_key"
    host = peer.get("control_ip")
    if not key.exists() or not host:
        raise RuntimeError(f"{peer['name']} is not provisioned")
    base = [
        "ssh",
        "-i",
        str(key),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=8",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        f"UserKnownHostsFile={root}/lab/.vagrant/known_hosts",
        f"vagrant@{host}",
    ]
    subprocess.run(
        [*base, "sudo tee /usr/local/sbin/flowlab-agent >/dev/null"],
        input=source,
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    subprocess.run(
        [*base, "sudo systemctl restart flowlab-agent"],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    return peer["name"]


if __name__ == "__main__":
    with ThreadPoolExecutor(max_workers=4) as pool:
        for name in pool.map(deploy, enumerate(resolve_peers(), 1)):
            print("Updated", name)
