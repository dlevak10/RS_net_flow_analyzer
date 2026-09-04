import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Request, status

BASE_DIR = Path(__file__).resolve().parents[3]
LOG_DIR = BASE_DIR / "logs"
NETFLOW_LOG = LOG_DIR / "netflow.jsonl"

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("")
async def ingest_netflow(request: Request):
    raw_body = await request.body()
    payload: Any

    try:
        payload = json.loads(raw_body.decode("utf-8")) if raw_body else None
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = raw_body.decode("utf-8", errors="replace")

    log_entry = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "client_ip": request.client.host if request.client else None,
        "content_type": request.headers.get("content-type"),
        "payload": payload,
    }

    LOG_DIR.mkdir(exist_ok=True)
    with NETFLOW_LOG.open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(log_entry, ensure_ascii=False, default=str) + "\n")

    return {
        "status": "accepted",
        "log_file": str(NETFLOW_LOG),
    }


@router.get("/health", status_code=status.HTTP_200_OK)
async def ingest_health():
    return {"status": "ok"}
