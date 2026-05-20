import uuid

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models import Alert, LogEvent, SourceType
from app.schemas import EventIn
from app.services.detection import Analysis, analyze_event, extract_entities, summarize
from app.services.email_service import persist_email_message
from app.services.log_service import create_alert_for_analysis, create_log_event, first_admin_email, publish_ingest_events


async def ingest_event(
    session: AsyncSession,
    event: EventIn,
    collector_id: uuid.UUID | None = None,
    notification_recipient: str | None = None,
) -> tuple[LogEvent, Alert | None]:
    if event.source_type == SourceType.email and event.correlation_id:
        existing = await session.scalar(
            select(LogEvent).where(LogEvent.source_type == SourceType.email, LogEvent.correlation_id == event.correlation_id)
        )
        if existing:
            return existing, None

    analysis = analyze_event(event)
    log = await create_log_event(session, event, analysis, collector_id)
    await persist_email_message(session, event, analysis, log.id)
    alert = await create_alert_for_analysis(session, log, analysis, notification_recipient)
    await publish_ingest_events(log, alert, event, collector_id)
    return log, alert


__all__ = [
    "Analysis",
    "analyze_event",
    "extract_entities",
    "first_admin_email",
    "ingest_event",
    "summarize",
]
