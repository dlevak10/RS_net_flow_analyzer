from fastapi import APIRouter

router = APIRouter(prefix="/ingest", tags=["ingest"])


@router.post("")
async def ingest_netflow():
    return {"message": "Ingest NetFlow data"}
