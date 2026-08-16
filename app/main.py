from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse

from app.api.routes import alerts, ingest, login, stats

app = FastAPI(title="NetFlow Analyzer")
BASE_DIR = Path(__file__).resolve().parent.parent

app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(login.router)


@app.get("/")
async def root():
    return FileResponse(BASE_DIR / "login.html")
