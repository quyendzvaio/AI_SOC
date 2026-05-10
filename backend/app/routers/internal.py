from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import verify_internal_token
from app.models import Alert, LogEvent, Notification, RuntimeSetting, Severity
from app.schemas import AlertOut, EnrichmentIn
from app.services.crypto import decrypt_value
from app.services.realtime import broker

router = APIRouter(prefix="/internal", tags=["internal"], dependencies=[Depends(verify_internal_token)])


@router.post("/enrichments", response_model=AlertOut)
async def apply_enrichment(payload: EnrichmentIn, session: AsyncSession = Depends(get_session)) -> Alert:
    log = await session.get(LogEvent, payload.log_id)
    if not log:
        raise HTTPException(status_code=404, detail="Log not found")

    alert = await session.scalar(select(Alert).where(Alert.log_id == payload.log_id).order_by(Alert.detected_at.desc()))
    if not alert:
        alert = Alert(
            log_id=log.id,
            severity=payload.severity or Severity.Medium,
            message=payload.message or "Enriched suspicious security event",
            ai_summary=payload.ai_summary or log.log_summary,
            rule_name=payload.rule_name or "async_enrichment",
        )
        session.add(alert)
        await session.flush()
        session.add(Notification(alert_id=alert.id, recipient="soc@example.com"))
    else:
        if payload.severity and severity_rank(payload.severity) > severity_rank(alert.severity):
            alert.severity = payload.severity
        if payload.message:
            alert.message = payload.message
        if payload.ai_summary:
            alert.ai_summary = payload.ai_summary
        if payload.rule_name:
            alert.rule_name = payload.rule_name

    if payload.enrichment:
        log.extracted_entities = {**log.extracted_entities, "enrichment": payload.enrichment}

    await session.commit()
    await session.refresh(alert)
    await broker.publish(
        {
            "type": "alert_enriched",
            "alert": {
                "id": str(alert.id),
                "log_id": str(alert.log_id),
                "severity": alert.severity.value,
                "status": alert.status.value,
                "message": alert.message,
                "ai_summary": alert.ai_summary,
                "rule_name": alert.rule_name,
            },
        }
    )
    return alert


def severity_rank(severity: Severity) -> int:
    return {
        Severity.Low: 1,
        Severity.Medium: 2,
        Severity.High: 3,
        Severity.Critical: 4,
    }[severity]


@router.get("/runtime-config")
async def internal_runtime_config(session: AsyncSession = Depends(get_session)) -> dict[str, str | None]:
    result = await session.execute(select(RuntimeSetting))
    config: dict[str, str | None] = {}
    for setting in result.scalars():
        config[setting.key] = decrypt_value(setting.value_encrypted) if setting.is_secret else setting.value_public
    return config
