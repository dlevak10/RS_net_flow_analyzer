from fastapi import FastAPI

from app.api.routes import alerts, ingest, login, stats

app = FastAPI(title="NetFlow Analyzer")

app.include_router(ingest.router)
app.include_router(alerts.router)
app.include_router(stats.router)
app.include_router(login.router)


@app.get("/")
async def root():
    return {"service": "netflow-analyzer", "status": "ok"}
