import io
import json
import logging
import os
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal

import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, model_validator

from . import store
from .config import DATA, MODELS
from .experiments import matrix, run_scenario
from .live import PEERS, peers, run_live
from .ml import MODEL_NAMES, load_model, predict, train
from .packets import read_pcap

pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="flowlab")
job_lock = threading.Lock()
log = logging.getLogger("flowlab")


@asynccontextmanager
async def lifespan(app):
    store.initialize(recover=True)
    yield
    pool.shutdown(wait=False, cancel_futures=True)


app = FastAPI(title="FlowLab", version="0.1.0", lifespan=lifespan)


@app.middleware("http")
async def local_only(request, call_next):
    # Prevent another website from using this localhost service as a privileged controller.
    host = request.url.hostname
    if host not in {"127.0.0.1", "localhost", "::1", "testserver"}:
        return JSONResponse({"detail": "Localhost access only"}, status_code=403)
    origin = request.headers.get("origin")
    if origin and origin != str(request.base_url).rstrip("/"):
        return JSONResponse({"detail": "Cross-origin requests are disabled"}, status_code=403)
    if request.headers.get("sec-fetch-site") == "cross-site" and request.method not in {"GET", "HEAD"}:
        return JSONResponse({"detail": "Cross-site writes are disabled"}, status_code=403)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
    )
    return response


@app.exception_handler(ValueError)
async def invalid(request, exc):
    return JSONResponse({"detail": str(exc)}, status_code=400)


def submit(kind, fn, *args):
    with job_lock:
        if any(j["status"] in {"queued", "running"} for j in store.listing("job", 100)):
            raise HTTPException(409, "An experiment or training job is already active")
        job = store.add(
            "job", {"kind": kind, "status": "queued", "message": "Waiting for worker", "pid": os.getpid()}
        )

    def worker():
        store.update(job["id"], status="running")

        def progress(message):
            store.update(job["id"], message=message)

        try:
            result = fn(*args, progress=progress)
            store.update(job["id"], status="complete", message="Complete", result=result)
        except Exception as exc:
            log.exception("Job failed")
            store.update(job["id"], status="failed", message=str(exc))

    pool.submit(worker)
    return job


class ScenarioRequest(BaseModel):
    source: Literal["fixture", "capture", "live"] = "fixture"
    model_id: str
    scenario: Literal["BENIGN", "DoS", "DDoS", "PortScan", "BruteForce"] = "BENIGN"
    src: str = "192.168.56.11"
    dst: str = "192.168.56.12"
    loss_rate: float = Field(default=0, ge=0, le=0.1, allow_inf_nan=False)
    loss_kind: Literal["random", "burst"] = "random"
    seed: int = Field(default=42, ge=0, le=1000000)
    capture_id: str | None = None
    enforce: bool = False
    duration: int = Field(default=8, ge=1, le=30)
    rate: int = Field(default=100, ge=1, le=500)

    @model_validator(mode="after")
    def validate_peers(self):
        ips = {p["ip"] for p in PEERS}
        if self.src not in ips or self.dst not in ips or self.src == self.dst:
            raise ValueError("Choose two different lab peers")
        if self.scenario == "DDoS" and self.source == "fixture":
            raise ValueError("DDoS requires real VM traffic or a recorded capture")
        if self.source == "capture" and not self.capture_id:
            raise ValueError("Choose an imported capture")
        if self.enforce and self.source != "live":
            raise ValueError("Enforcement is available only for connected VMs")
        return self


class MatrixRequest(ScenarioRequest):
    model_ids: list[str] = Field(min_length=1, max_length=12)
    kinds: list[Literal["random", "burst"]] = ["random", "burst"]
    rates: list[float] = Field(default=[0, 0.01, 0.05, 0.1], min_length=1, max_length=4)
    seeds: list[int] = Field(default=[41, 42, 43], min_length=1, max_length=10)

    @model_validator(mode="after")
    def validate_matrix(self):
        if self.source == "live":
            raise ValueError("Run live scenarios individually; matrix compares fixed packet traces")
        if any(r not in [0, 0.01, 0.05, 0.1] for r in self.rates):
            raise ValueError("Matrix loss rates must be 0%, 1%, 5% or 10%")
        if any(s < 0 or s > 1000000 for s in self.seeds):
            raise ValueError("Invalid seed")
        if not self.kinds:
            raise ValueError("Choose at least one loss model")
        return self


@app.get("/api/status")
def status():
    store.reconcile_jobs()
    return {
        "name": "FlowLab",
        "version": "0.1.0",
        "peers": PEERS,
        "models": len(list(MODELS.glob("*.json"))),
        "jobs": store.listing("job", 10),
        "runs": [{k: v for k, v in r.items() if k != "rows"} for r in store.listing("run", 8)],
        "experiments": [
            {k: v for k, v in r.items() if k != "results"} for r in store.listing("experiment", 8)
        ],
        "live_runs": store.listing("live_run", 8),
    }


@app.get("/api/research")
def research():
    from .config import RESULTS
    from .cic import available

    output = {"exporter_available": available()}
    for key, filename in [
        ("live", "live-study.json"),
        ("transfer", "cic-transfer.json"),
        ("complete", "research-study-ready.json"),
    ]:
        path = RESULTS / filename
        output[key] = json.loads(path.read_text()) if path.exists() else None
    return output


@app.get("/api/research/{name}/export")
def research_export(name: Literal["live", "transfer"]):
    from .config import RESULTS

    path = RESULTS / ("live-study.json" if name == "live" else "cic-transfer.json")
    if not path.exists():
        raise HTTPException(404, "Study has not produced results yet")
    return FileResponse(path, filename=path.name)


@app.get("/api/models")
def models():
    return [json.loads(p.read_text()) for p in sorted(MODELS.glob("*.json"))]


@app.get("/api/datasets")
def datasets():
    return [json.loads(p.read_text()) for p in sorted(DATA.glob("*.json"))]


@app.get("/api/peers")
def peer_status():
    return peers()


@app.get("/api/decisions")
def decisions():
    return store.listing("decision", 100)


@app.get("/api/records/{record_id}")
def record(record_id: str):
    return store.get(record_id)


@app.get("/api/records/{record_id}/export")
def export(record_id: str):
    value = store.get(record_id)
    return Response(
        json.dumps(value, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="flowlab-{record_id}.json"'},
    )


@app.get("/api/runs/{run_id}/flows.csv")
def export_flows(run_id: str):
    run = store.get(run_id, "run")
    rows = [
        {
            **r["features"],
            "prediction": r["prediction"],
            "confidence": r["confidence"],
            "flow_id": r["id"],
            "src": r["src"],
            "dst": r["dst"],
        }
        for r in run["rows"]
    ]
    content = pd.DataFrame(rows).to_csv(index=False)
    return Response(
        content,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{run_id}-flows.csv"'},
    )


@app.get("/api/runs/{run_id}/capture.pcap")
def download_pcap(run_id: str):
    run = store.get(run_id, "run")
    if not run.get("pcap_available"):
        raise HTTPException(404, "No generated capture for this run")
    return FileResponse(DATA / "captures" / f"{run_id}.pcap", filename="generated-fixture.pcap")


@app.post("/api/scenarios")
def scenario(request: ScenarioRequest):
    bundle = load_model(request.model_id)
    from .cic import SCHEMA as CIC_SCHEMA, available

    cic_live = request.source == "live" and bundle["metadata"]["schema"] == CIC_SCHEMA and available()
    if not bundle["metadata"]["live_compatible"] and not cic_live:
        raise ValueError("Choose a packet-compatible model, not a CSV benchmark model")
    return submit(
        "live scenario" if request.source == "live" else "packet analysis",
        run_live if request.source == "live" else run_scenario,
        request.model_dump(),
    )


@app.post("/api/experiments")
def experiment(request: MatrixRequest):
    for model_id in request.model_ids:
        if not load_model(model_id)["metadata"]["live_compatible"]:
            raise ValueError("Matrix requires packet-compatible models")
    return submit("loss matrix", matrix, request.model_dump())


class TrainingRequest(BaseModel):
    dataset: str
    algorithms: list[Literal["logistic", "rf", "xgboost", "extra", "mlp", "tabm"]] = list(MODEL_NAMES)


@app.post("/api/train")
def training(request: TrainingRequest):
    available = {p.stem for p in DATA.glob("*.json")}
    if request.dataset not in available or not request.algorithms:
        raise ValueError("Choose a prepared dataset and at least one algorithm")

    def work(progress):
        saved = train(request.dataset, request.algorithms, progress=progress)
        return {"model_ids": [m["id"] for m in saved]}

    return submit("training", work)


@app.get("/api/captures")
def captures():
    return store.listing("capture", 100)


@app.get("/api/captures/{capture_id}/download")
def download_capture(capture_id: str):
    capture = store.get(capture_id, "capture")
    return FileResponse(DATA / "captures" / capture["filename"], filename=capture["name"])


@app.post("/api/captures")
async def upload_capture(file: UploadFile = File(...), label: str | None = None):
    from uuid import uuid4

    name = uuid4().hex + ".pcap"
    path = DATA / "captures" / name
    total = 0
    try:
        with path.open("wb") as target:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > 64 * 1024 * 1024:
                    raise ValueError("Capture limit is 64 MiB; split large captures first")
                target.write(chunk)
        # Decode off the event loop, using a bounded parser.
        import asyncio

        packets, skipped = await asyncio.to_thread(read_pcap, path)
        if not packets:
            raise ValueError("No supported unfragmented TCP/UDP packets found")
        if label and len(label) > 100:
            raise ValueError("Label is too long")
        return store.add(
            "capture",
            {
                "name": Path(file.filename or "capture.pcap").name,
                "filename": name,
                "bytes": total,
                "packets": len(packets),
                "skipped": skipped,
                "label": label,
                "label_source": "user declared homogeneous capture" if label else "unlabelled",
                "endpoints": sorted({p.src for p in packets} | {p.dst for p in packets})[:100],
            },
        )
    except Exception as exc:
        path.unlink(missing_ok=True)
        if isinstance(exc, ValueError):
            raise
        raise ValueError("Invalid PCAP or PCAPNG capture") from exc


@app.post("/api/predict-csv/{model_id}")
async def predict_csv(model_id: str, file: UploadFile = File(...)):
    contents = await file.read(16 * 1024 * 1024 + 1)
    if len(contents) > 16 * 1024 * 1024:
        raise ValueError("CSV limit is 16 MiB")
    bundle = load_model(model_id)
    try:
        frame = pd.read_csv(io.BytesIO(contents), nrows=10001)
    except Exception as exc:
        raise ValueError("Invalid CSV") from exc
    frame.columns = frame.columns.str.strip()
    if len(frame) > 10000 or frame.empty:
        raise ValueError("CSV must contain 1 to 10000 rows")
    result = predict(bundle, frame.to_dict("records"))
    record = store.add(
        "csv_prediction",
        {"model_id": model_id, "rows": result, "source": Path(file.filename or "input.csv").name},
    )
    return {"record_id": record["id"], "rows": len(result), "predictions": result[:100]}


static = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=static), name="static")


@app.get("/")
def index():
    return FileResponse(static / "index.html")
