import numpy as np
from flowlab.context import ContextMeter, ALL_FEATURES, extract_context
from flowlab.packets import Packet
from flowlab.ml import selective_decision, HierarchicalClassifier


def packet(t, source="a", port=1):
    return Packet(t, source, "target", port, 80, 17, 100)


def test_context_is_causal_and_shared_between_stream_and_batch():
    packets = [packet(0), packet(0.1), packet(0.2, "b", 2), packet(0.3, "c", 3), packet(0.4, "c", 3)]
    meter = ContextMeter(prefix=2)
    first = meter.push(packets[0]) + meter.push(packets[1])
    assert first[0]["features"]["ctx_sources_1s"] == 1
    frozen = dict(first[0]["features"])
    rest = []
    for p in packets[2:]:
        rest += meter.push(p)
    rest += meter.flush()
    assert first[0]["features"] == frozen
    assert any(f["features"]["ctx_sources_1s"] == 3 for f in rest)
    stream = first + rest
    batch = extract_context(packets, prefix=2)
    assert [f["features"] for f in stream] == [f["features"] for f in batch]
    assert set(batch[0]["features"]) == set(ALL_FEATURES)
    assert not any(value == "a" for value in batch[0]["features"].values())


def test_context_windows_expire_and_do_not_read_future_packets():
    records = extract_context([packet(0), packet(0.1), packet(6, "b", 2), packet(6.1, "b", 2)], prefix=2)
    assert records[-1]["features"]["ctx_sources_5s"] == 1
    import pytest

    meter = ContextMeter(prefix=2)
    meter.push(packet(1))
    with pytest.raises(ValueError, match="timestamp order"):
        meter.push(packet(0.5))


def test_policy_separates_binary_uncertainty_from_attack_type():
    meta = dict(classes=["BENIGN", "DoS", "DDoS"], hierarchical=True, threshold=0.99)
    ambiguous = selective_decision(meta, np.array([0.05, 0.48, 0.47]))
    assert ambiguous["prediction"] == "ATTACK_UNCERTAIN"
    assert not ambiguous["block_eligible"]
    assert selective_decision(meta, np.array([0.7, 0.2, 0.1]))["prediction"] == "UNCERTAIN"
    assert selective_decision(meta, np.array([0.95, 0.03, 0.02]))["prediction"] == "BENIGN"
    meta["threshold"] = 0.9
    assert selective_decision(meta, np.array([0.01, 0.98, 0.01]))["block_eligible"]
    assert selective_decision(meta, np.array([0.05, 0.48, 0.47]))["block_eligible"]


def test_hierarchical_probabilities_preserve_binary_gate():
    class Fixed:
        def __init__(self, p):
            self.p = p

        def predict_proba(self, x):
            return np.tile(self.p, (len(x), 1))

    model = HierarchicalClassifier(
        Fixed([0.1, 0.9]), Fixed([0.4, 0.6]), ["BENIGN", "DDoS", "DoS"], ["DDoS", "DoS"]
    )
    p = model.predict_proba([[0]])
    assert np.allclose(p, [[0.1, 0.36, 0.54]])
    assert np.allclose(p.sum(1), 1)


def test_rolling_counters_match_independent_history_queries():
    rng = np.random.default_rng(91)
    packets = []
    now = 0.0
    for i in range(300):
        now += float(rng.uniform(0.001, 0.1))
        packets.append(Packet(now, str(i % 5), "target", i % 20, 80, 17, int(rng.integers(0, 1500))))
    for record in extract_context(packets, prefix=3):
        now = record["context"]["observed_until"]
        for width in [1, 5]:
            history = [p for p in packets if now - width < p.time <= now]
            assert record["features"][f"ctx_sources_{width}s"] == len({p.src for p in history})
            assert record["features"][f"ctx_connections_{width}s"] == len({p.key for p in history})
            assert np.isclose(
                record["features"][f"ctx_byte_rate_{width}s"], sum(p.length for p in history) / width
            )


def test_original_pcapng_slicer_preserves_packets_and_times(tmp_path):
    from scapy.all import Ether, IP, UDP, Raw, PcapNgWriter
    from scripts.prepare_cic_prefix import slice_windows
    from flowlab.packets import read_pcap

    source = tmp_path / "original.pcap"
    with PcapNgWriter(str(source)) as writer:
        for timestamp in [100.25, 102.5, 101.25]:
            p = Ether() / IP(src="192.0.2.1", dst="192.0.2.2") / UDP(sport=100, dport=200) / Raw(b"preserved")
            p.time = timestamp
            writer.write(p)
    windows = [dict(start=100, end=101.5, path="selected.pcap")]
    slice_windows(source, windows, tmp_path)
    packets, skipped = read_pcap(tmp_path / "selected.pcap")
    assert skipped == 0 and len(packets) == 2
    assert np.allclose([p.time for p in packets], [100.25, 101.25])
    assert all(p.length == 9 for p in packets)
