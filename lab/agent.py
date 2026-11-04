#!/usr/bin/env python3
"""Root agent inside disposable FlowLab VMs. No arbitrary shell or target input."""

import collections
import hmac
import json
import os
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

LAB_IPS = {f"192.168.56.{i}" for i in range(11, 15)}
TOKEN = Path(os.environ.get("FLOWLAB_TOKEN_FILE", "/etc/flowlab-token")).read_text().strip()
LOCK = threading.RLock()
PACKETS = collections.deque(maxlen=100000)
SEQ = 0
COUNTERS = {"http_requests": 0, "udp_datagrams": 0, "udp_payload_bytes": 0}
RUNNING = threading.Event()
STOP = threading.Event()
LAST_CONTACT = time.monotonic()
SNIFFER = None
CAPTURE_PATH = Path("/var/lib/flowlab/observed.pcap")
WRITER = None
CAPTURE_LIMITED = False
SELF = os.environ.get("FLOWLAB_IP", "192.168.56.11")
INTERFACE = os.environ.get("FLOWLAB_INTERFACE", "eth1")


def command(args, optional=False):
    result = subprocess.run(args, capture_output=True, text=True, timeout=8)
    if result.returncode and not optional:
        raise ValueError(result.stderr.strip() or "Network command failed")
    return result.stdout


def reset():
    global WRITER, CAPTURE_LIMITED
    from scapy.utils import PcapWriter

    command(["tc", "qdisc", "del", "dev", INTERFACE, "root"], optional=True)
    command(["nft", "delete", "table", "inet", "flowlab"], optional=True)
    command(["nft", "add", "table", "inet", "flowlab"])
    command(
        [
            "nft",
            "add",
            "chain",
            "inet",
            "flowlab",
            "input",
            "{ type filter hook input priority -10; policy accept; }",
        ]
    )
    command(
        [
            "nft",
            "add",
            "chain",
            "inet",
            "flowlab",
            "output",
            "{ type filter hook output priority -10; policy accept; }",
        ]
    )
    with LOCK:
        if WRITER is not None:
            WRITER.close()
        CAPTURE_PATH.parent.mkdir(parents=True, exist_ok=True)
        WRITER = PcapWriter(str(CAPTURE_PATH), sync=True)
        CAPTURE_LIMITED = False
        PACKETS.clear()
        for key in COUNTERS:
            COUNTERS[key] = 0


def collect(raw):
    global SEQ, CAPTURE_LIMITED
    from scapy.layers.inet import IP, TCP, UDP
    from scapy.packet import Padding

    ip = raw.getlayer(IP)
    transport = raw.getlayer(TCP) or raw.getlayer(UDP)
    if (
        ip is None
        or transport is None
        or ip.src not in LAB_IPS
        or ip.dst not in LAB_IPS
        or ip.frag
        or ip.flags.MF
    ):
        return
    payload_length = len(bytes(transport.payload))
    if Padding in transport.payload:
        payload_length -= len(bytes(transport.payload.getlayer(Padding)))
    packet = {
        "time": float(raw.time),
        "src": ip.src,
        "dst": ip.dst,
        "sport": int(transport.sport),
        "dport": int(transport.dport),
        "protocol": 6 if TCP in raw else 17,
        "length": max(0, payload_length),
        "flags": int(transport.flags) if TCP in raw else 0,
    }
    with LOCK:
        if WRITER is not None:
            if CAPTURE_PATH.stat().st_size < 64 * 1024 * 1024:
                WRITER.write(raw)
            else:
                CAPTURE_LIMITED = True
        SEQ += 1
        PACKETS.append((SEQ, packet))


def traffic(target, scenario, duration, rate):
    RUNNING.set()
    try:
        end = time.monotonic() + duration
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((SELF, 0))
        i = 0
        while time.monotonic() < end and not STOP.is_set():
            i += 1
            try:
                if scenario == "DoS":
                    if i % 50 == 0:
                        sock.close()
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.bind((SELF, 0))
                    sock.sendto(b"FlowLab bounded load" * 4, (target, 8081))
                elif scenario == "PortScan":
                    probe = socket.socket()
                    probe.settimeout(0.1)
                    probe.bind((SELF, 0))
                    probe.connect_ex((target, 8000 + i % 32))
                    probe.close()
                else:
                    url = f"http://{target}:8080/" + ("auth" if scenario == "BruteForce" else "")
                    # Explicitly bypass host/environment HTTP proxies in the isolated lab.
                    urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=0.5).read()
                    if scenario == "BENIGN" and i % 3 == 0:
                        sock.sendto(b"benign:" + b"normal data" * 20, (target, 8081))
            except (OSError, urllib.error.URLError):
                pass
            time.sleep(1 / (rate if scenario != "BENIGN" else min(rate, 8)))
        sock.close()
    finally:
        RUNNING.clear()


class Service(BaseHTTPRequestHandler):
    def do_GET(self):
        with LOCK:
            COUNTERS["http_requests"] += 1
        self.send_response(401 if self.path == "/auth" else 200)
        body = b"FlowLab lab service\n" * (2 if self.path == "/auth" else 60)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


def udp_service():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((SELF, 8081))
    while True:
        data, address = sock.recvfrom(2048)
        if address[0] in LAB_IPS:
            with LOCK:
                COUNTERS["udp_datagrams"] += 1
                COUNTERS["udp_payload_bytes"] += len(data)
            if data.startswith(b"benign:"):
                sock.sendto(b"benign response", address)


class Agent(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def respond(self, status, data):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def authorized(self):
        global LAST_CONTACT
        valid = len(TOKEN) >= 32 and hmac.compare_digest(
            self.headers.get("Authorization", ""), "Bearer " + TOKEN
        )
        if valid:
            LAST_CONTACT = time.monotonic()
        return valid

    def do_GET(self):
        if not self.authorized():
            return self.respond(401, {"detail": "Invalid agent token"})
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/health":
            return self.respond(
                200,
                {
                    "ip": SELF,
                    "interface": INTERFACE,
                    "capture": "running" if SNIFFER and SNIFFER.running else "stopped",
                    "scenario_running": RUNNING.is_set(),
                },
            )
        if parsed.path == "/counters":
            with LOCK:
                result = dict(COUNTERS)
            result["firewall"] = json.loads(command(["nft", "-j", "list", "table", "inet", "flowlab"]))
            result["qdiscs"] = json.loads(command(["tc", "-j", "-s", "qdisc", "show", "dev", INTERFACE]))
            result["capture_limited"] = CAPTURE_LIMITED
            return self.respond(200, result)
        if parsed.path == "/capture":
            with LOCK:
                body = CAPTURE_PATH.read_bytes() if CAPTURE_PATH.exists() else b""
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path == "/packets":
            after = int(urllib.parse.parse_qs(parsed.query).get("after", ["0"])[0])
            with LOCK:
                overrun = bool(PACKETS and after and after < PACKETS[0][0] - 1)
                # Cursor only advances to the last returned item; no silent truncation.
                selected = [(seq, p) for seq, p in PACKETS if seq > after][:10000]
                result = {
                    "cursor": selected[-1][0] if selected else after,
                    "packets": [p for _, p in selected],
                    "overrun": overrun,
                }
            return self.respond(200, result)
        self.respond(404, {"detail": "Unknown route"})

    def do_POST(self):
        if not self.authorized():
            return self.respond(401, {"detail": "Invalid agent token"})
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 4096:
                raise ValueError("Invalid request length")
            data = json.loads(self.rfile.read(size))
            if self.path == "/stop":
                STOP.set()
                for _ in range(30):
                    if not RUNNING.is_set():
                        break
                    time.sleep(0.05)
                return self.respond(200, {"stopped": not RUNNING.is_set()})
            if self.path == "/reset":
                if RUNNING.is_set():
                    raise ValueError("Wait for the current traffic scenario to finish")
                reset()
                return self.respond(200, {"reset": True})
            if self.path == "/loss":
                rate, kind, seed = float(data["rate"]), data["kind"], int(data["seed"])
                if not 0 <= rate <= 0.1 or kind not in ["random", "burst"] or not 0 <= seed <= 1000000:
                    raise ValueError("Invalid loss parameters")
                if not rate:
                    command(["tc", "qdisc", "del", "dev", INTERFACE, "root"], optional=True)
                else:
                    params = (
                        ["random", f"{rate * 100:.6f}%"]
                        if kind == "random"
                        else ["gemodel", f"{rate * 0.25 / (1 - rate) * 100:.6f}%", "25%", "100%", "0%"]
                    )
                    args = [
                        "tc",
                        "qdisc",
                        "replace",
                        "dev",
                        INTERFACE,
                        "root",
                        "netem",
                        "loss",
                        *params,
                        "seed",
                        str(seed),
                    ]
                    try:
                        command(args)
                        seeded = True
                    except ValueError as exc:
                        if "seed" not in str(exc).lower():
                            raise
                        command(args[:-2])
                        seeded = False
                return self.respond(
                    200,
                    {
                        "rate": rate,
                        "kind": kind,
                        "seed_requested": seed,
                        "seed_applied": seeded if rate else True,
                        "note": "Live RNG seeding is unsupported by this guest tc version"
                        if rate and not seeded
                        else "",
                    },
                )
            if self.path == "/scenario":
                target, scenario = data["target"], data["scenario"]
                duration, rate = int(data["duration"]), int(data["rate"])
                if (
                    target not in LAB_IPS
                    or target == SELF
                    or scenario not in ["BENIGN", "DoS", "PortScan", "BruteForce"]
                    or not 1 <= duration <= 30
                    or not 1 <= rate <= 500
                ):
                    raise ValueError("Scenario outside lab limits")
                if RUNNING.is_set():
                    raise ValueError("Scenario already active")
                STOP.clear()
                RUNNING.set()
                threading.Thread(target=traffic, args=(target, scenario, duration, rate), daemon=True).start()
                return self.respond(200, {"started": True, "target": target})
            if self.path == "/block":
                src, dst, sport, dport, protocol = (
                    data["src"],
                    data["dst"],
                    int(data["sport"]),
                    int(data["dport"]),
                    int(data["protocol"]),
                )
                if (
                    src not in LAB_IPS
                    or dst not in LAB_IPS
                    or SELF not in [src, dst]
                    or protocol not in [6, 17]
                    or not 0 <= sport <= 65535
                    or not 0 <= dport <= 65535
                ):
                    raise ValueError("Connection outside lab")
                proto = "tcp" if protocol == 6 else "udp"
                for a, b, sp, dp in [(src, dst, sport, dport), (dst, src, dport, sport)]:
                    chain = "input" if b == SELF else "output"
                    command(
                        [
                            "nft",
                            "add",
                            "rule",
                            "inet",
                            "flowlab",
                            chain,
                            "ip",
                            "saddr",
                            a,
                            "ip",
                            "daddr",
                            b,
                            proto,
                            "sport",
                            str(sp),
                            proto,
                            "dport",
                            str(dp),
                            "counter",
                            "drop",
                        ]
                    )
                return self.respond(
                    200,
                    {
                        "installed_at": time.time(),
                        "src": src,
                        "dst": dst,
                        "sport": sport,
                        "dport": dport,
                        "protocol": protocol,
                    },
                )
            self.respond(404, {"detail": "Unknown route"})
        except Exception as exc:
            self.respond(400, {"detail": str(exc)})


def main():
    global SNIFFER
    if os.geteuid() != 0 or SELF not in LAB_IPS or len(TOKEN) < 32:
        raise SystemExit("Agent requires VM root, configured lab IP, and a 32+ character token")
    # Import the registered Ethernet/IP dissectors before starting the L2 socket.
    from scapy.all import AsyncSniffer

    reset()
    SNIFFER = AsyncSniffer(iface=INTERFACE, prn=collect, store=False)
    SNIFFER.start()

    def watchdog():
        global LAST_CONTACT
        while True:
            time.sleep(5)
            if time.monotonic() - LAST_CONTACT > 60:
                STOP.set()
                if not RUNNING.is_set():
                    reset()
                    LAST_CONTACT = time.monotonic()

    threading.Thread(target=watchdog, daemon=True).start()
    threading.Thread(target=ThreadingHTTPServer((SELF, 8080), Service).serve_forever, daemon=True).start()
    threading.Thread(target=udp_service, daemon=True).start()
    # NAT forwarding exposes the control port only on host loopback.
    ThreadingHTTPServer(("0.0.0.0", 9100), Agent).serve_forever()


if __name__ == "__main__":
    main()
