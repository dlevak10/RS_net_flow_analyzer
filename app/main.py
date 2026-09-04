from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import alerts, ingest, login, stats
from app.services.stats_calculator import calculate_flow_summary, read_flow_records

app = FastAPI(title="NetFlow Analyzer")
BASE_DIR = Path(__file__).resolve().parent.parent
APP_DIR = BASE_DIR / "app"
templates = Jinja2Templates(directory=APP_DIR / "templates")

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
async def alerts_page(request: Request):
    records = read_flow_records()
    alerts_records = [
        record for record in records
        if int(record.get("bytes") or 0) > 1000000
    ]

    return templates.TemplateResponse(
        request,
        "alerts.html",
        {"records": alerts_records},
    )


@app.get("/stats.html")
async def stats_page(request: Request):
    records = read_flow_records()
    return templates.TemplateResponse(
        request,
        "stats.html",
        {
            "records": records,
            "summary": calculate_flow_summary(records),
        },
    )
