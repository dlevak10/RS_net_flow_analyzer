from fastapi import APIRouter

from app.services.stats_calculator import calculate_flow_summary, read_flow_records

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("")
async def get_stats():
    records = read_flow_records()
    return {
        "summary": calculate_flow_summary(records),
        "records": records,
    }
