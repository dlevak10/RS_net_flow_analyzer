from fastapi import APIRouter

router = APIRouter(prefix="/stats", tags=["stats"])


@router.get("")
async def get_stats():
    return {"message": "TODO: return NetFlow statistics"}
