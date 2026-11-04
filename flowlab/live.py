"""Host side of the opt-in VM agent integration; never invokes host sudo."""

import os
import shutil
import subprocess
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import store

from .config import ROOT, DATA
from .ml import load_model, predict
from .packets import SCHEMA, FlowMeter, Packet, read_pcap

explanations = ThreadPoolExecutor(max_workers=1, thread_name_prefix="flowlab-explain")

PEERS = [
    {"id": f"peer-{i}", "name": name, "ip": f"192.168.56.{10 + i}", "url": f"http://127.0.0.1:{9100 + i}"}
    for i, name in enumerate(["Atlas", "Birch", "Cedar", "Delta"], start=1)
]


def resolve_peers():
    """Discover only our four named libvirt guests; never accept a user-supplied control URL."""
    output = [dict(peer) for peer in PEERS]
    if not shutil.which("virsh"):
        return output
    for i, peer in enumerate(output, start=1):
        try:
            result = subprocess.run(
                ["virsh", "-c", "qemu:///system", "domifaddr", f"lab_flowlab{i}"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            for line in result.stdout.splitlines():
                parts = line.split()
                if len(parts) == 4 and parts[2] == "ipv4":
                    address = ipaddress.ip_interface(parts[3]).ip
                    if address in ipaddress.ip_network("192.168.121.0/24"):
                        peer["url"] = f"http://{address}:9100"
                        peer["control_ip"] = str(address)
                        break
        except (OSError, ValueError, subprocess.TimeoutExpired):
            continue
    return output


def token():
    path = ROOT / "lab/token"
    return os.environ.get("FLOWLAB_AGENT_TOKEN") or (path.read_text().strip() if path.exists() else "")


def client():
    return httpx.Client(timeout=3, trust_env=False, headers={"Authorization": f"Bearer {token()}"})


def peers():
    output = []
    with client() as c:
        for peer in resolve_peers():
            item = {**peer, "online": False, "status": "VM agent unavailable"}
            if token():
                try:
                    response = c.get(peer["url"] + "/health")
                    response.raise_for_status()
                    health = response.json()
                    item.update(online=True, status="Connected VM", health=health)
                except (httpx.HTTPError, ValueError):
                    pass
            output.append(item)
    return output


def run_live(request, progress=lambda _: None):
    resolved = resolve_peers()
    src = next(p for p in resolved if p["ip"] == request["src"])
    dst = next(p for p in resolved if p["ip"] == request["dst"])
    bundle = load_model(request["model_id"])
    meta = bundle["metadata"]
    if meta["schema"] != SCHEMA or not meta.get("prefix"):
        raise ValueError("Live prevention requires a compatible prefix model")
    if not token():
        raise ValueError("VM agents are not provisioned. Follow lab/README.md")
    meter = FlowMeter(prefix=meta["prefix"])
    decisions, blocks, observations = [], [], 0
    run_id = store.add(
        "live_run", {"request": request, "status": "running", "model_synthetic": meta["synthetic"]}
    )["id"]
    with client() as c:

        def call(peer, path, data=None):
            response = (
                c.post(peer["url"] + path, json=data or {}) if data is not None else c.get(peer["url"] + path)
            )
            response.raise_for_status()
            return response.json()

        try:
            for peer in (src, dst):
                health = call(peer, "/health")
                if health.get("capture") != "running":
                    raise ValueError(f"Capture is not running on {peer['name']}")
                call(peer, "/reset", {})
            loss_configuration = call(
                src,
                "/loss",
                {"rate": request["loss_rate"], "kind": request["loss_kind"], "seed": request["seed"]},
            )
            duration = request.get("duration", 8)
            call(
                src,
                "/scenario",
                {
                    "target": dst["ip"],
                    "scenario": request["scenario"],
                    "duration": duration,
                    "rate": request.get("rate", 100),
                },
            )
            cursor = 0
            stop = time.monotonic() + duration + 2
            while time.monotonic() < stop:
                batch = call(dst, f"/packets?after={cursor}")
                if batch["overrun"]:
                    raise ValueError("VM capture buffer overran; reduce traffic rate")
                cursor = batch["cursor"]
                for item in batch["packets"]:
                    p = Packet(**item)
                    if {p.src, p.dst} != {src["ip"], dst["ip"]}:
                        continue
                    observations += 1
                    records = meter.push(p)
                    for flow in records:
                        decision = predict(bundle, [flow["features"]])[0]
                        enforced = False
                        action = "allow" if decision["prediction"] == "BENIGN" else "alert"
                        if (
                            request.get("enforce")
                            and decision["prediction"] != "BENIGN"
                            and decision["attack_score"] >= meta["threshold"]
                        ):
                            # Block only the specific connection, in both directions, at the observer VM.
                            before = call(dst, "/counters")
                            install_start = time.perf_counter()
                            install = call(
                                dst,
                                "/block",
                                {k: flow[k] for k in ["src", "dst", "sport", "dport", "protocol"]},
                            )
                            install["installation_ms"] = 1000 * (time.perf_counter() - install_start)
                            install["application_counters_before_block"] = {
                                k: v
                                for k, v in before.items()
                                if k in {"http_requests", "udp_datagrams", "udp_payload_bytes"}
                            }
                            blocks.append(install)
                            enforced, action = True, "block confirmed"
                        record = store.add(
                            "decision",
                            {
                                **flow,
                                **decision,
                                "policy": action,
                                "enforced": enforced,
                                "synthetic": meta["synthetic"],
                                "run_id": run_id,
                                "model_id": meta["id"],
                            },
                        )
                        decisions.append(record)
                        if len(decisions) <= 2:

                            def explain_later(record_id=record["id"], values=flow["features"]):
                                try:
                                    explanation = predict(bundle, [values], explain=True)[0]["explanation"]
                                    store.update(record_id, explanation=explanation)
                                except Exception as exc:
                                    store.update(record_id, explanation_error=str(exc))

                            explanations.submit(explain_later)
                progress(
                    f"Live capture: {observations} packets; {len(decisions)} decisions; {len(blocks)} rules"
                )
                time.sleep(0.25)
            for flow in meter.flush():
                decision = predict(bundle, [flow["features"]])[0]
                decisions.append(
                    store.add(
                        "decision",
                        {
                            **flow,
                            **decision,
                            "policy": "completed after capture",
                            "enforced": False,
                            "synthetic": meta["synthetic"],
                            "run_id": run_id,
                            "model_id": meta["id"],
                        },
                    )
                )
            if observations == 0:
                raise ValueError(
                    "No TCP/UDP packets were captured; verify the destination sensor before interpreting the run"
                )
            counters = call(dst, "/counters")
            source_counters = call(src, "/counters")
            captured = []
            for peer, point in [
                (src, "source egress capture"),
                (dst, "destination before input firewall"),
            ]:
                response = c.get(peer["url"] + "/capture")
                response.raise_for_status()
                if len(response.content) > 64 * 1024 * 1024:
                    raise ValueError("VM capture exceeds the import limit")
                filename = f"{run_id}-{peer['id']}.pcap"
                capture_path = DATA / "captures" / filename
                capture_path.write_bytes(response.content)
                if not response.content:
                    capture_path.unlink(missing_ok=True)
                    continue
                raw_packets, skipped = read_pcap(capture_path)
                capture = store.add(
                    "capture",
                    {
                        "name": f"{request['scenario']}-{peer['name']}-{run_id[:8]}.pcap",
                        "filename": filename,
                        "bytes": len(response.content),
                        "packets": len(raw_packets),
                        "skipped": skipped,
                        "label": request["scenario"],
                        "endpoints": sorted({p.src for p in raw_packets} | {p.dst for p in raw_packets}),
                        "label_source": "controlled live scenario; inspect before corpus use",
                        "capture_point": point,
                        "live_run_id": run_id,
                    },
                )
                captured.append(capture["id"])
            store.update(
                run_id,
                status="complete",
                packets_observed=observations,
                decisions=len(decisions),
                blocks=blocks,
                destination_counters=counters,
                source_counters=source_counters,
                loss_configuration=loss_configuration,
                capture_ids=captured,
                note="Capture at destination after source egress loss; application counters measure delivery.",
            )
        except Exception as exc:
            store.update(run_id, status="failed", error=str(exc))
            raise
        finally:
            # Always undo this experiment's loss and temporary rules, including on inference failure.
            try:
                call(src, "/stop", {})
            except Exception:
                pass
            for peer in (src, dst):
                try:
                    call(peer, "/reset", {})
                except Exception:
                    pass
    return {"live_run_id": run_id}
