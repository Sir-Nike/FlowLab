"""Synthetic packet fixtures for functional tests, never a CICIDS benchmark."""

import numpy as np

from .packets import Packet

SCENARIOS = {
    "BENIGN": "Normal conversation",
    "DoS": "High-rate single-source traffic",
    "PortScan": "Short connection probes",
    "BruteForce": "Repeated authentication-like exchanges",
}


def generate(label="BENIGN", seed=42, count=30, source="192.168.56.11", target="192.168.56.12"):
    if label not in SCENARIOS:
        raise ValueError("Unknown scenario")
    rng = np.random.default_rng(seed)
    packets = []
    for i in range(count):
        origin = f"fixture-{seed}-{i}"
        start = seed * 1000 + i * 3.2
        port = 10000 + i
        dport = int(rng.integers(20, 1000)) if label == "PortScan" else int(rng.choice([8080, 443, 22]))
        n = {
            "BENIGN": int(rng.integers(10, 45)),
            "DoS": int(rng.integers(60, 140)),
            "PortScan": int(rng.integers(1, 4)),
            "BruteForce": int(rng.integers(12, 30)),
        }[label]
        interval = {"BENIGN": 0.03, "DoS": 0.0003, "PortScan": 0.01, "BruteForce": 0.008}[label]
        now = start
        for j in range(n):
            now += float(rng.exponential(interval))
            reverse = label in {"BENIGN", "BruteForce"} and j % 2 == 1
            length = (
                int(rng.integers(100, 1400))
                if label == "BENIGN"
                else (int(rng.integers(40, 130)) if label == "BruteForce" else int(rng.integers(0, 70)))
            )
            flags = 2 if label == "PortScan" else (24 if length else 16)
            packets.append(
                Packet(
                    now,
                    target if reverse else source,
                    source if reverse else target,
                    dport if reverse else port,
                    port if reverse else dport,
                    6,
                    length,
                    flags,
                    origin,
                )
            )
    return sorted(packets, key=lambda p: p.time)


def write_pcap(packets, path):
    from scapy.all import IP, TCP, UDP, Ether, PcapWriter, Raw

    with PcapWriter(str(path), sync=True) as writer:
        for p in packets:
            layer = (
                TCP(sport=p.sport, dport=p.dport, flags=p.flags)
                if p.protocol == 6
                else UDP(sport=p.sport, dport=p.dport)
            )
            raw = Ether() / IP(src=p.src, dst=p.dst) / layer / Raw(b"x" * p.length)
            raw.time = p.time
            writer.write(raw)
