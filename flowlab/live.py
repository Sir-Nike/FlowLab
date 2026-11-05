"""Host side of the opt-in VM agent integration; never invokes host sudo."""

import os
import shutil
import subprocess
import ipaddress
import time
import random
from concurrent.futures import ThreadPoolExecutor

import httpx

from . import store

from .config import ROOT, DATA
from .ml import load_model, predict
from .packets import SCHEMA, FlowMeter, Packet, read_pcap
from .context import SCHEMA as CONTEXT_SCHEMA, ContextMeter

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


def traffic_plan(request, sources):
    duration = request.get("duration", 8)
    if request["scenario"] == "Realistic":
        if duration < 8 or len(sources) != 3:
            raise ValueError("Realistic traffic requires three source peers and at least eight seconds")
        rng = random.Random(request["seed"])
        return [
            dict(source=sources[0]["ip"], scenario="BENIGN", offset=0, duration=duration, rate=8),
            *[dict(source=peer["ip"], scenario=rng.choice(["PortScan", "BruteForce", "DoS"]),
                   offset=duration * fraction, duration=1, rate=2)
              for peer, fraction in zip(sources[1:], [.3, .7])],
        ]
    return [dict(source=p["ip"], scenario="DoS" if request["scenario"] == "DDoS" else request["scenario"],
                 offset=0, duration=duration, rate=request.get("rate", 100)) for p in sources]


def run_live(request, progress=lambda _: None):
    if request["scenario"] == "DDoS" and request.get("source_count", 3) < 2:
        raise ValueError("DDoS requires at least two source peers")
    resolved = resolve_peers()
    src = next(p for p in resolved if p["ip"] == request["src"])
    dst = next(p for p in resolved if p["ip"] == request["dst"])
    others = [p for p in resolved if p["ip"] not in {src["ip"], dst["ip"]}]
    sources = [src, *others] if request["scenario"] == "Realistic" else (
        [src, *others][: request.get("source_count", 3)]
        if request["scenario"] in {"DDoS", "BenignBurst"}
        else [src]
    )
    source_ips = {p["ip"] for p in sources}
    plan = traffic_plan(request, sources)
    bundle = load_model(request["model_id"])
    meta = bundle["metadata"]
    from . import cic

    cic_mode = meta["schema"] == cic.SCHEMA
    if cic_mode and request.get("enforce"):
        raise ValueError(
            "CIC completed-flow models observe captured traffic; use a lab prefix model for prevention"
        )
    if cic_mode and not cic.available():
        raise ValueError("Install the pinned corrected CICFlowMeter first")
    if not cic_mode and (meta["schema"] not in {SCHEMA, CONTEXT_SCHEMA} or not meta.get("prefix")):
        raise ValueError("Live prevention requires a compatible prefix model")
    if not token():
        raise ValueError("VM agents are not provisioned. Follow lab/README.md")
    meter = (ContextMeter if meta["schema"] == CONTEXT_SCHEMA else FlowMeter)(prefix=meta.get("prefix"))
    decisions, blocks, observations = [], [], 0
    run_id = store.add(
        "live_run",
        {
            "request": request,
            "status": "running",
            "model_synthetic": meta["synthetic"],
            "model_dataset": meta["dataset"],
            "model_schema": meta["schema"],
        },
    )["id"]
    with client() as c:

        def call(peer, path, data=None):
            response = (
                c.post(peer["url"] + path, json=data or {}) if data is not None else c.get(peer["url"] + path)
            )
            response.raise_for_status()
            return response.json()

        try:
            for peer in [*sources, dst]:
                health = call(peer, "/health")
                if health.get("capture") != "running":
                    raise ValueError(f"Capture is not running on {peer['name']}")
                call(peer, "/reset", {})
            loss_configurations = [
                call(
                    source,
                    "/loss",
                    {"rate": request["loss_rate"], "kind": request["loss_kind"], "seed": request["seed"]},
                )
                for source in sources
            ]
            loss_configuration = loss_configurations[0]
            duration = request.get("duration", 8)
            pending = list(plan)
            store.update(run_id, traffic_plan=plan)
            cursor = 0
            started = time.monotonic()
            stop = started + duration + 2
            while time.monotonic() < stop:
                for entry in pending[:]:
                    if time.monotonic() - started >= entry["offset"]:
                        source = next(p for p in sources if p["ip"] == entry["source"])
                        call(source, "/scenario", dict(target=dst["ip"], scenario=entry["scenario"],
                             seed=request["seed"], duration=entry["duration"], rate=entry["rate"]))
                        entry["started_at"] = time.time()
                        pending.remove(entry)
                batch = call(dst, f"/packets?after={cursor}")
                if batch["overrun"]:
                    raise ValueError("VM capture buffer overran; reduce traffic rate")
                cursor = batch["cursor"]
                emitted = []
                for item in batch["packets"]:
                    p = Packet(**item)
                    if not (
                        dst["ip"] in {p.src, p.dst}
                        and (meta["schema"] == CONTEXT_SCHEMA or ({p.src, p.dst} & source_ips))
                    ):
                        continue
                    observations += 1
                    if not cic_mode:
                        emitted.extend(meter.push(p))
                predictions = predict(bundle, [f["features"] for f in emitted]) if emitted else []
                for flow, decision in zip(emitted, predictions):
                    enforced = False
                    action = "allow" if decision["prediction"] == "BENIGN" else "alert"
                    if (
                        request.get("enforce")
                        and decision["prediction"] != "BENIGN"
                        and decision.get("block_eligible", decision["attack_score"] >= meta["threshold"])
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
                            "prefix_observation_delay_ms": 1000 * (flow["end"] - flow["start"]),
                            "decision_at": time.time(),
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
            for flow in [] if cic_mode else meter.flush():
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
            source_counter_list = [{"ip": p["ip"], **call(p, "/counters")} for p in sources]
            source_counters = source_counter_list[0]
            captured = []
            for peer, point in [
                *((p, "source egress capture") for p in sources),
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
                        "label": None if request["scenario"] == "Realistic" else "BENIGN"
                        if request["scenario"] == "BenignBurst"
                        else "DoS"
                        if request["scenario"] == "HTTPDoS"
                        else request["scenario"],
                        "endpoints": sorted({p.src for p in raw_packets} | {p.dst for p in raw_packets}),
                        "label_source": "mixed controlled workload; no single capture label" if request["scenario"] == "Realistic" else "controlled live scenario; inspect before corpus use",
                        "capture_point": point,
                        "live_run_id": run_id,
                    },
                )
                captured.append(capture["id"])
            if cic_mode:
                frame = cic.extract_cic(capture_path, meta["features"])
                flows = list(cic.flow_records(frame, meta["features"]))
                predictions = predict(bundle, [f["features"] for f in flows], explain=True)
                for flow, decision in zip(flows, predictions):
                    decisions.append(
                        store.add(
                            "decision",
                            {
                                **flow,
                                **decision,
                                "policy": "completed capture observation",
                                "enforced": False,
                                "synthetic": False,
                                "run_id": run_id,
                                "model_id": meta["id"],
                            },
                        )
                    )
            store.update(
                run_id,
                status="complete",
                packets_observed=observations,
                decisions=len(decisions),
                blocks=blocks,
                destination_counters=counters,
                source_counters=source_counters,
                source_counter_list=source_counter_list,
                sources=sorted(source_ips),
                loss_configurations=loss_configurations,
                loss_configuration=loss_configuration,
                capture_ids=captured,
                traffic_plan=plan,
                note="Capture at destination after source egress loss; application counters measure delivery.",
            )
        except Exception as exc:
            store.update(run_id, status="failed", error=str(exc))
            raise
        finally:
            # Always undo this experiment's loss and temporary rules, including on inference failure.
            for source in sources:
                try:
                    call(source, "/stop", {})
                except Exception:
                    pass
            for peer in [*sources, dst]:
                try:
                    call(peer, "/reset", {})
                except Exception:
                    pass
    return {"live_run_id": run_id}
