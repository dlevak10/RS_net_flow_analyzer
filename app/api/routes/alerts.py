from fastapi import APIRouter

from app.services.stats_calculator import read_flow_records

router = APIRouter(prefix="/alerts", tags=["alerts"])


@router.get("")
async def list_alerts():
    records = read_flow_records()
    alerts = [
        {**record, "alert": "High traffic"}
        for record in records
        if int(record.get("bytes") or 0) > 1000000
    ]
    return {"records": alerts}
