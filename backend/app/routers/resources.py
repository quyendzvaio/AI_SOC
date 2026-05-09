import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import current_user
from app.models import AiQuery, Alert, AlertTag, EmailMessage, Incident, IncidentAlert, LogEvent, Notification, Tag, User
from app.schemas import (
    AlertOut,
    AlertPatchIn,
    AssistantQueryIn,
    AssistantQueryOut,
    EmailMessageOut,
    IncidentIn,
    IncidentOut,
    LogOut,
    NotificationOut,
    TagIn,
)

router = APIRouter(dependencies=[Depends(current_user)])


@router.get("/logs", response_model=list[LogOut])
async def list_logs(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[LogEvent]:
    result = await session.execute(select(LogEvent).order_by(desc(LogEvent.received_at)).limit(min(limit, 200)))
    return list(result.scalars())


@router.get("/logs/{log_id}", response_model=LogOut)
async def get_log(log_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> LogEvent:
    log = await session.get(LogEvent, log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")
    return log


@router.get("/alerts", response_model=list[AlertOut])
async def list_alerts(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[Alert]:
    result = await session.execute(select(Alert).order_by(desc(Alert.detected_at)).limit(min(limit, 200)))
    return list(result.scalars())


@router.get("/alerts/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> Alert:
    alert = await session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
async def patch_alert(alert_id: uuid.UUID, payload: AlertPatchIn, session: AsyncSession = Depends(get_session)) -> Alert:
    alert = await get_alert(alert_id, session)
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(alert, field, value)
    await session.commit()
    await session.refresh(alert)
    return alert


@router.post("/alerts/{alert_id}/tags")
async def add_alert_tag(alert_id: uuid.UUID, payload: TagIn, session: AsyncSession = Depends(get_session)) -> dict[str, str]:
    alert = await session.get(Alert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    tag = await session.scalar(select(Tag).where(Tag.name == payload.name))
    if not tag:
        tag = Tag(name=payload.name, color=payload.color)
        session.add(tag)
        await session.flush()
    exists = await session.get(AlertTag, {"alert_id": alert_id, "tag_id": tag.id})
    if not exists:
        session.add(AlertTag(alert_id=alert_id, tag_id=tag.id))
    await session.commit()
    return {"status": "ok"}


@router.get("/incidents", response_model=list[IncidentOut])
async def list_incidents(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[Incident]:
    result = await session.execute(select(Incident).order_by(desc(Incident.created_at)).limit(min(limit, 200)))
    return list(result.scalars())


@router.post("/incidents", response_model=IncidentOut)
async def create_incident(payload: IncidentIn, session: AsyncSession = Depends(get_session)) -> Incident:
    incident = Incident(name=payload.name, description=payload.description, severity=payload.severity)
    session.add(incident)
    await session.flush()
    if payload.alert_id:
        session.add(IncidentAlert(incident_id=incident.id, alert_id=payload.alert_id))
    await session.commit()
    await session.refresh(incident)
    return incident


@router.post("/assistant/query", response_model=AssistantQueryOut)
async def assistant_query(
    payload: AssistantQueryIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> AssistantQueryOut:
    answer = (
        "MVP assistant is running in lightweight mode. "
        "Use alerts/log summaries and configured Threat Intel for deeper enrichment."
    )
    session.add(AiQuery(user_id=user.id, question=payload.question, response=answer))
    await session.commit()
    return AssistantQueryOut(answer=answer)


@router.get("/notifications", response_model=list[NotificationOut])
async def list_notifications(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[Notification]:
    result = await session.execute(select(Notification).order_by(desc(Notification.created_at)).limit(min(limit, 200)))
    return list(result.scalars())


@router.get("/emails", response_model=list[EmailMessageOut])
async def list_emails(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[EmailMessage]:
    result = await session.execute(select(EmailMessage).order_by(desc(EmailMessage.received_at)).limit(min(limit, 200)))
    return list(result.scalars())
