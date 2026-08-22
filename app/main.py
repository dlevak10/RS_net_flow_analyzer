from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import alerts, ingest, login, stats

app = FastAPI(title="NetFlow Analyzer")
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"

app.mount("/static", StaticFiles(directory=APP_DIR / "static"), name="static")

app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(login.router)


@app.get("/")
async def root():
    return FileResponse(APP_DIR / "templates" / "login.html")


@app.get("/dashboard.html")
async def dashboard_page():
    return FileResponse(APP_DIR / "templates" / "dashboard.html")


@app.get("/alerts.html")
async def alerts_page():
    return FileResponse(APP_DIR / "templates" / "alerts.html")


@app.get("/stats.html")
async def stats_page():
    return FileResponse(APP_DIR / "templates" / "stats.html")
