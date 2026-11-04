"""Versioned bidirectional flow measurement, independent of scenario labels.

Lengths are transport payload bytes; timestamps and IATs use seconds.
Retransmissions are counted as observed packets. IP fragments are excluded.
This schema is deliberately NOT advertised as CICFlowMeter compatible.
"""

import math
import heapq
from dataclasses import asdict, dataclass
from hashlib import sha256

import numpy as np

SCHEMA = "flowlab-payload-v1"
FEATURES = [
    "protocol",
    "duration",
    "fwd_packets",
    "bwd_packets",
    "fwd_bytes",
    "bwd_bytes",
    "length_mean",
    "length_std",
    "length_min",
    "length_max",
    "iat_mean",
    "iat_std",
    "iat_max",
    "packets_per_second",
    "bytes_per_second",
    "syn_count",
    "ack_count",
    "rst_count",
    "fin_count",
    "psh_count",
    "bwd_fwd_ratio",
]


@dataclass
class Packet:
    time: float
    src: str
    dst: str
    sport: int
    dport: int
    protocol: int
    length: int
    flags: int = 0
    origin: str = ""

    @property
    def key(self):
        return (self.protocol, *sorted(((self.src, self.sport), (self.dst, self.dport))))

    def to_dict(self):
        return asdict(self)


def decode(raw):
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
    from scapy.packet import Padding

    ip = raw.getlayer(IP) or raw.getlayer(IPv6)
    if ip is None or (IP in raw and (ip.frag or ip.flags.MF)) or IPv6ExtHdrFragment in raw:
        return None
    transport = raw.getlayer(TCP) or raw.getlayer(UDP)
    if transport is None:
        return None
    payload_length = len(bytes(transport.payload))
    if Padding in transport.payload:
        payload_length -= len(bytes(transport.payload.getlayer(Padding)))
    return Packet(
        float(raw.time),
        ip.src,
        ip.dst,
        int(transport.sport),
        int(transport.dport),
        6 if TCP in raw else 17,
        max(0, payload_length),
        int(transport.flags) if TCP in raw else 0,
    )


def read_pcap(path, limit=250_000):
    from scapy.all import PcapReader

    packets, skipped = [], 0
    with PcapReader(str(path)) as reader:
        for index, raw in enumerate(reader):
            if index >= limit:
                raise ValueError(f"Capture exceeds {limit:,} packets; split it before import")
            packet = decode(raw)
            if packet is None:
                skipped += 1
            else:
                packets.append(packet)
    packets.sort(key=lambda x: x.time)
    return packets, skipped


class Flow:
    def __init__(self, packet, serial):
        self.first = packet
        self.last_time = packet.time
        self.id = sha256(f"{packet.key}:{packet.time:.9f}:{serial}".encode()).hexdigest()[:16]
        self.packets = []
        self.finished = False
        self.fin_directions = set()

    def add(self, packet, store=True):
        if store:
            self.packets.append(packet)
        self.last_time = max(self.last_time, packet.time)
        forward = (packet.src, packet.sport) == (self.first.src, self.first.sport)
        if packet.flags & 1:
            self.fin_directions.add(forward)
        self.finished = bool(packet.flags & 4) or (
            len(self.fin_directions) == 2 and bool(packet.flags & 16) and not bool(packet.flags & 1)
        )

    def record(self, reason="eof"):
        ps = self.packets
        fwd = [p for p in ps if (p.src, p.sport) == (self.first.src, self.first.sport)]
        bwd = [p for p in ps if (p.src, p.sport) != (self.first.src, self.first.sport)]
        lengths = np.array([p.length for p in ps], dtype=float)
        iat = np.diff([p.time for p in ps])
        duration = self.last_time - self.first.time

        def flags(bit):
            return sum(bool(p.flags & bit) for p in ps)

        features = [
            self.first.protocol,
            duration,
            len(fwd),
            len(bwd),
            sum(p.length for p in fwd),
            sum(p.length for p in bwd),
            lengths.mean(),
            lengths.std(),
            lengths.min(),
            lengths.max(),
            iat.mean() if len(iat) else 0,
            iat.std() if len(iat) else 0,
            iat.max() if len(iat) else 0,
            len(ps) / duration if duration else 0,
            lengths.sum() / duration if duration else 0,
            flags(2),
            flags(16),
            flags(4),
            flags(1),
            flags(8),
            len(bwd) / max(len(fwd), 1),
        ]
        return {
            "id": self.id,
            "src": self.first.src,
            "dst": self.first.dst,
            "sport": self.first.sport,
            "dport": self.first.dport,
            "protocol": self.first.protocol,
            "start": self.first.time,
            "end": self.last_time,
            "packet_count": len(ps),
            "bytes": int(lengths.sum()),
            "origins": sorted({p.origin for p in ps if p.origin}),
            "reason": reason,
            "features": dict(zip(FEATURES, map(float, features))),
        }


class FlowMeter:
    def __init__(self, idle=30.0, active=120.0, prefix=None):
        self.idle, self.active, self.prefix = idle, active, prefix
        self.flows, self.serial = {}, 0
        self.emitted = set()
        self.deadlines = []

    def expire(self, now):
        output = []
        while self.deadlines and self.deadlines[0][0] <= now:
            _, flow_id, key = heapq.heappop(self.deadlines)
            flow = self.flows.get(key)
            if flow is None or flow.id != flow_id:
                continue
            if now - flow.last_time < self.idle and now - flow.first.time < self.active:
                continue
            reason = "idle" if now - flow.last_time >= self.idle else "active"
            if flow.id not in self.emitted:
                output.append(flow.record(reason))
            self.emitted.discard(flow.id)
            del self.flows[key]
        return output

    def push(self, packet):
        output = self.expire(packet.time)
        flow = self.flows.get(packet.key)
        if flow is None:
            self.serial += 1
            flow = self.flows[packet.key] = Flow(packet, self.serial)
        flow.add(packet, store=flow.id not in self.emitted)
        heapq.heappush(
            self.deadlines,
            (min(flow.last_time + self.idle, flow.first.time + self.active), flow.id, packet.key),
        )
        if self.prefix and len(flow.packets) >= self.prefix and flow.id not in self.emitted:
            output.append(flow.record("prefix"))
            self.emitted.add(flow.id)
        if flow.finished:
            if flow.id not in self.emitted:
                output.append(flow.record("tcp_close"))
            self.emitted.discard(flow.id)
            del self.flows[packet.key]
        return output

    def flush(self):
        output = [f.record() for f in self.flows.values() if f.id not in self.emitted]
        self.flows.clear()
        self.emitted.clear()
        self.deadlines.clear()
        return output


def extract(packets, prefix=None):
    meter = FlowMeter(prefix=prefix)
    output = []
    for packet in packets:
        output.extend(meter.push(packet))
    output.extend(meter.flush())
    return output


def apply_loss(packets, rate, kind="random", seed=42, burst_length=4):
    if not math.isfinite(rate) or not 0 <= rate <= 1:
        raise ValueError("Loss must be between 0 and 1")
    if kind not in {"random", "burst"}:
        raise ValueError("Loss kind must be random or burst")
    rng = np.random.default_rng(seed)
    kept = []
    bad = bool(rng.random() < rate)
    q = 1 / burst_length
    enter = min(1, rate * q / max(1 - rate, 1e-12))
    for packet in packets:
        drop = rng.random() < rate if kind == "random" else bad
        if not drop:
            kept.append(packet)
        if kind == "burst":
            bad = (rng.random() >= q) if bad else (rng.random() < enter)
            if rate == 1:
                bad = True
    return kept
