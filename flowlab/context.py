"""Causal destination context shared by offline training and online inference.

Only previously observed packets contribute. Addresses group observations but
never enter classifier inputs. Windows are half-open (t-window, t].
"""

from collections import Counter, defaultdict, deque
import math
from .packets import FEATURES, FlowMeter

SCHEMA = "flowlab-context-v2"
CONTEXT_FEATURES = [
    f"ctx_{name}_{window}s"
    for window in (1, 5)
    for name in (
        "sources",
        "packet_rate",
        "byte_rate",
        "connections",
        "source_share",
        "syn_fraction",
        "response_ratio",
    )
]
ALL_FEATURES = FEATURES + CONTEXT_FEATURES


class Window:
    def __init__(self, seconds, limit):
        self.seconds, self.limit = seconds, limit
        self.events = deque()
        self.sources = defaultdict(Counter)
        self.connections = defaultdict(Counter)
        self.packets, self.bytes, self.syn, self.outbound = Counter(), Counter(), Counter(), Counter()

    @staticmethod
    def change(counter, key, amount):
        counter[key] += amount
        if not counter[key]:
            del counter[key]

    def update(self, p, sign):
        target = p.dst
        self.change(self.sources[target], p.src, sign)
        self.change(self.connections[target], p.key, sign)
        self.change(self.packets, target, sign)
        self.change(self.bytes, target, sign * p.length)
        self.change(self.syn, target, sign * bool(p.flags & 2))
        self.change(self.outbound, p.src, sign)
        if not self.sources[target]:
            del self.sources[target]
        if not self.connections[target]:
            del self.connections[target]

    def advance(self, now):
        while self.events and self.events[0].time <= now - self.seconds:
            self.update(self.events.popleft(), -1)

    def add(self, packet):
        if len(self.events) >= self.limit:
            raise ValueError(
                "Context buffer capacity exceeded; reduce traffic or increase the explicit limit"
            )
        self.events.append(packet)
        self.update(packet, 1)

    def features(self, target, source):
        n = self.packets[target]
        window = self.seconds
        return {
            f"ctx_sources_{window}s": len(self.sources.get(target, {})),
            f"ctx_packet_rate_{window}s": n / window,
            f"ctx_byte_rate_{window}s": self.bytes[target] / window,
            f"ctx_connections_{window}s": len(self.connections.get(target, {})),
            f"ctx_source_share_{window}s": self.sources.get(target, {}).get(source, 0) / n if n else 0,
            f"ctx_syn_fraction_{window}s": self.syn[target] / n if n else 0,
            f"ctx_response_ratio_{window}s": self.outbound[target] / n if n else 0,
        }


class ContextMeter:
    def __init__(self, prefix=10, max_packets=250000):
        self.meter = FlowMeter(prefix=prefix)
        self.windows = [Window(seconds, max_packets) for seconds in (1, 5)]
        self.latest = float("-inf")

    def _enrich(self, flows, now):
        for flow in flows:
            for window in self.windows:
                flow["features"].update(window.features(flow["dst"], flow["src"]))
            flow["context"] = {
                "target": flow["dst"],
                "observed_until": now,
                "windows_seconds": [1, 5],
                "note": "Counts describe observed traffic, not proof of malicious coordination.",
            }
            flow["decision_time"] = now
        return flows

    def push(self, packet):
        if not math.isfinite(packet.time) or packet.time < self.latest:
            raise ValueError("Context packets must arrive in nondecreasing timestamp order")
        for window in self.windows:
            window.advance(packet.time)
        expired = self._enrich(self.meter.expire(packet.time), packet.time)
        self.latest = packet.time
        for window in self.windows:
            window.add(packet)
        return expired + self._enrich(self.meter.push(packet), packet.time)

    def flush(self):
        return self._enrich(self.meter.flush(), self.latest)


def extract_context(packets, prefix=10):
    meter = ContextMeter(prefix=prefix)
    output = []
    for packet in packets:
        output.extend(meter.push(packet))
    output.extend(meter.flush())
    return output
