import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import current_user
from app.models import LogEvent
from app.schemas import LogOut
from app.services.log_service import get_log as get_log_event
from app.services.log_service import list_logs as list_log_events

router = APIRouter(tags=["logs"], dependencies=[Depends(current_user)])


@router.get("/logs", response_model=list[LogOut])
async def list_logs(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[LogEvent]:
    return await list_log_events(session, limit)


@router.get("/logs/{log_id}", response_model=LogOut)
async def get_log(log_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> LogEvent:
    log = await get_log_event(session, log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log
