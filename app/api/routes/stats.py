from fastapi import APIRouter

from app.models.netflow import create_example_records

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("")
async def get_stats():
    return create_example_records()
