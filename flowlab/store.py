import json
import os
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from .config import RESULTS

_lock = threading.RLock()


def now():
    return datetime.now(timezone.utc).isoformat()


def connect():
    db = sqlite3.connect(RESULTS / "flowlab.sqlite", timeout=30)
    db.row_factory = sqlite3.Row
    return db


def initialize(recover=False):
    with connect() as db:
        db.execute(
            "CREATE TABLE IF NOT EXISTS records (id TEXT PRIMARY KEY, kind TEXT, created TEXT, data TEXT)"
        )
        db.execute("CREATE INDEX IF NOT EXISTS kind_created ON records(kind, created)")
    # Interrupted work is never displayed as still running after restart.
    reconcile_jobs()
    for record in listing("job", 1000) if recover else []:
        if record["status"] in {"queued", "running"}:
            if record.get("pid") and process_alive(record["pid"]):
                continue
            update(record["id"], status="interrupted", message="Application stopped before completion")


def process_alive(pid):
    try:
        os.kill(int(pid), 0)
        path = Path(f"/proc/{int(pid)}/stat")
        return not path.exists() or path.read_text().split(")", 1)[1].strip()[0] != "Z"
    except (OSError, ValueError):
        return False


def reconcile_jobs():
    for job in listing("job", 100):
        if (
            job.get("external_result")
            and job["status"] in {"running", "queued"}
            and not process_alive(job["pid"])
        ):
            path = RESULTS / job["external_result"]
            if path.is_file():
                update(
                    job["id"],
                    status="complete",
                    message=job.get("completion_message", "Complete"),
                    result=json.loads(path.read_text()),
                )
            else:
                update(
                    job["id"],
                    status="failed",
                    message="External collection ended without a completion result; inspect results/lab-collection.log",
                )


def add(kind, data):
    payload = dict(data)
    if "id" in payload:
        payload["flow_id"] = payload.pop("id")
    record = {**payload, "id": uuid4().hex, "created": now()}
    with _lock, connect() as db:
        db.execute(
            "INSERT INTO records VALUES (?,?,?,?)",
            (record["id"], kind, record["created"], json.dumps(record)),
        )
    return record


def get(record_id, kind=None):
    with connect() as db:
        row = db.execute("SELECT kind,data FROM records WHERE id=?", (record_id,)).fetchone()
    if not row or (kind and row["kind"] != kind):
        raise ValueError("Record not found")
    return json.loads(row["data"])


def update(record_id, **changes):
    with _lock, connect() as db:
        row = db.execute("SELECT data FROM records WHERE id=?", (record_id,)).fetchone()
        if row is None:
            raise ValueError("Record not found")
        value = {**json.loads(row[0]), **changes}
        db.execute("UPDATE records SET data=? WHERE id=?", (json.dumps(value), record_id))
    return value


def listing(kind, limit=100):
    with connect() as db:
        rows = db.execute(
            "SELECT data FROM records WHERE kind=? ORDER BY created DESC LIMIT ?", (kind, limit)
        ).fetchall()
    return [json.loads(row[0]) for row in rows]
