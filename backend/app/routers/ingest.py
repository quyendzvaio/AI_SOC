from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import verify_ingest_token
from app.models import Collector, CollectorStatus
from app.schemas import CollectorEventsIn, CollectorHeartbeatIn, CollectorOut, CollectorRegisterIn, LogOut, WebhookEventIn
from app.services.analyzer import ingest_event

router = APIRouter(tags=["ingest"], dependencies=[Depends(verify_ingest_token)])


@router.post("/collectors/register", response_model=CollectorOut, status_code=status.HTTP_201_CREATED)
async def register_collector(payload: CollectorRegisterIn, session: AsyncSession = Depends(get_session)) -> Collector:
    collector = await session.scalar(
        select(Collector).where(Collector.host_name == payload.host_name, Collector.os_type == payload.os_type)
    )
    if collector:
        collector.agent_version = payload.agent_version
        collector.status = CollectorStatus.online
        collector.last_seen_at = datetime.now(timezone.utc)
    else:
        collector = Collector(**payload.model_dump(), status=CollectorStatus.online)
        session.add(collector)
    await session.commit()
    await session.refresh(collector)
    return collector


@router.post("/collectors/heartbeat", response_model=CollectorOut)
async def heartbeat(payload: CollectorHeartbeatIn, session: AsyncSession = Depends(get_session)) -> Collector:
    collector = await session.get(Collector, payload.collector_id)
    if not collector:
        raise HTTPException(status_code=404, detail="Collector not found")
    collector.status = payload.status
    collector.last_seen_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(collector)
    return collector


@router.post("/collectors/events", response_model=list[LogOut], status_code=status.HTTP_202_ACCEPTED)
async def collector_events(payload: CollectorEventsIn, session: AsyncSession = Depends(get_session)) -> list:
    collector = await session.get(Collector, payload.collector_id)
    if not collector:
        raise HTTPException(status_code=404, detail="Collector not found")
    logs = []
    for event in payload.events:
        log, _alert = await ingest_event(session, event, collector_id=collector.id)
        logs.append(log)
    collector.status = CollectorStatus.online
    collector.last_seen_at = datetime.now(timezone.utc)
    await session.commit()
    return logs


@router.post("/ingest/webhook", response_model=LogOut, status_code=status.HTTP_202_ACCEPTED)
async def webhook_event(payload: WebhookEventIn, session: AsyncSession = Depends(get_session)):
    log, _alert = await ingest_event(session, payload)
    await session.commit()
    await session.refresh(log)
    return log


@router.post("/ingest/email/test")
async def email_ingest_test() -> dict[str, str]:
    return {"status": "ok", "message": "email ingest configuration endpoint is reachable"}
