import pytest

from flowlab.experiments import identify_originals
from flowlab.fixtures import generate, write_pcap
from flowlab.packets import Packet, apply_loss, extract, read_pcap


def pkt(t=0, reverse=False, flags=16):
    return Packet(
        t,
        "10.0.0.2" if reverse else "10.0.0.1",
        "10.0.0.1" if reverse else "10.0.0.2",
        80 if reverse else 1234,
        1234 if reverse else 80,
        6,
        100,
        flags,
    )


def test_bidirectional_units_and_flags():
    flows = extract([pkt(0, flags=2), pkt(0.2, True), pkt(0.5, flags=4)])
    assert len(flows) == 1
    f = flows[0]["features"]
    assert f["duration"] == 0.5
    assert f["fwd_packets"] == 2 and f["bwd_packets"] == 1
    assert f["fwd_bytes"] == 200 and f["bwd_bytes"] == 100
    assert f["syn_count"] == 1 and f["rst_count"] == 1
    assert f["packets_per_second"] == 6
    assert f["iat_mean"] == 0.25


def test_timeouts_and_connection_reuse():
    flows = extract([pkt(0), pkt(31), pkt(32, flags=4), pkt(33)])
    assert len(flows) == 3
    assert [f["reason"] for f in flows] == ["idle", "tcp_close", "eof"]
    assert len({f["id"] for f in flows}) == 3


def test_tcp_last_ack_does_not_create_phantom_flow():
    flows = extract(
        [
            pkt(0, flags=2),
            pkt(0.1, reverse=True, flags=18),
            pkt(0.2),
            pkt(0.3, flags=17),
            pkt(0.4, reverse=True, flags=17),
            pkt(0.5),
        ]
    )
    assert len(flows) == 1
    assert flows[0]["packet_count"] == 6


def test_prefix_only_one_decision_and_short_flow_fallback():
    flows = extract([pkt(i * 0.1) for i in range(12)], prefix=5)
    assert len(flows) == 1 and flows[0]["packet_count"] == 5
    short = extract([pkt(0), pkt(0.1, flags=4)], prefix=10)
    assert len(short) == 1 and short[0]["packet_count"] == 2


def test_loss_seed_and_stationary_rate():
    packets = [pkt(i * 0.001) for i in range(50000)]
    for kind in ["random", "burst"]:
        a = apply_loss(packets, 0.1, kind, 42)
        b = apply_loss(packets, 0.1, kind, 42)
        assert [p.time for p in a] == [p.time for p in b]
        assert abs((1 - len(a) / len(packets)) - 0.1) < 0.015
        assert len(apply_loss(packets, 0, kind)) == len(packets)
        assert not apply_loss(packets, 1, kind)
    with pytest.raises(ValueError):
        apply_loss(packets, float("nan"))


def test_pcap_round_trip_and_identity(tmp_path):
    packets = generate("BENIGN", count=3)
    path = tmp_path / "test.pcap"
    write_pcap(packets, path)
    decoded, skipped = read_pcap(path)
    assert skipped == 0 and len(decoded) == len(packets)
    assert abs(decoded[0].time - packets[0].time) < 1e-5
    assert decoded[0].length == packets[0].length
    originals = identify_originals(decoded)
    assert len({p.origin for p in originals}) == 3
    assert len({o for f in extract(originals, prefix=10) for o in f["origins"]}) == 3
