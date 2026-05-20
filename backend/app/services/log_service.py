import uuid

from sqlalchemy import case, desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, LogEvent, Notification, User
from app.schemas import EventIn
from app.services.correlation_service import correlate_alert_to_incident
from app.services.detection import Analysis
from app.services.kafka import publish_security_event
from app.services.realtime import broker
from app.services.triage_service import build_triage


async def create_log_event(
    session: AsyncSession,
    event: EventIn,
    analysis: Analysis,
    collector_id: uuid.UUID | None = None,
) -> LogEvent:
    log = LogEvent(
        collector_id=collector_id,
        source_type=event.source_type,
        source=event.source,
        content_ref=event.content_ref,
        log_summary=analysis.summary,
        extracted_entities=analysis.entities | {"metadata": event.metadata},
        correlation_id=event.correlation_id or str(uuid.uuid4()),
    )
    session.add(log)
    await session.flush()
    return log


async def create_alert_for_analysis(
    session: AsyncSession,
    log: LogEvent,
    analysis: Analysis,
    notification_recipient: str | None = None,
) -> Alert | None:
    if not analysis.severity:
        return None

    alert = Alert(
        log_id=log.id,
        severity=analysis.severity,
        message=analysis.message,
        ai_summary=analysis.summary,
        rule_name=analysis.rule_name,
    )
    session.add(alert)
    await session.flush()

    log.extracted_entities = {**(log.extracted_entities or {}), "triage": build_triage(alert, log.extracted_entities or {})}
    await correlate_alert_to_incident(session, alert, log)

    recipient = notification_recipient or await first_admin_email(session)
    if recipient:
        session.add(Notification(alert_id=alert.id, recipient=recipient))
    return alert


async def publish_ingest_events(log: LogEvent, alert: Alert | None, event: EventIn, collector_id: uuid.UUID | None = None) -> None:
    await broker.publish(
        {
            "type": "log",
            "log": {
                "id": str(log.id),
                "source_type": log.source_type.value,
                "source": log.source,
                "log_summary": log.log_summary,
                "extracted_entities": log.extracted_entities,
                "correlation_id": log.correlation_id,
                "received_at": log.received_at.isoformat() if log.received_at else None,
            },
            "alert": {
                "id": str(alert.id),
                "severity": alert.severity.value,
                "status": alert.status.value,
                "message": alert.message,
                "ai_summary": alert.ai_summary,
                "rule_name": alert.rule_name,
            }
            if alert
            else None,
        }
    )

    await publish_security_event(
        {
            "log_id": str(log.id),
            "collector_id": str(collector_id) if collector_id else None,
            "source_type": event.source_type.value,
            "source": event.source,
            "content": event.content,
            "log_summary": log.log_summary,
            "extracted_entities": log.extracted_entities,
            "correlation_id": log.correlation_id,
            "initial_alert_id": str(alert.id) if alert else None,
        }
    )


async def list_logs(session: AsyncSession, limit: int = 50) -> list[LogEvent]:
    result = await session.execute(select(LogEvent).order_by(desc(LogEvent.received_at)).limit(min(limit, 200)))
    return list(result.scalars())


async def get_log(session: AsyncSession, log_id: uuid.UUID) -> LogEvent | None:
    return await session.get(LogEvent, log_id)


async def first_admin_email(session: AsyncSession) -> str | None:
    result = await session.execute(
        select(
            case(
                (
                    (User.notification_email.isnot(None)) & (User.is_notification_email_verified.is_(True)),
                    User.notification_email,
                ),
                else_=User.email,
            )
        )
        .where(User.is_email_verified.is_(True))
        .limit(1)
    )
    return result.scalar_one_or_none()
