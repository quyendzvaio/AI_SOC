import re
import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, EmailMessage, LogEvent, Notification, Severity, SourceType, User
from app.schemas import EventIn
from app.services.kafka import publish_security_event
from app.services.realtime import broker

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")

CRITICAL_TERMS = ("ransomware", "mimikatz", "credential dumping", "reverse shell", "c2", "exfiltration")
HIGH_TERMS = ("failed password", "brute force", "malware", "powershell encodedcommand", "sudo", "privilege escalation")
MEDIUM_TERMS = ("denied", "blocked", "suspicious", "phishing", "unauthorized", "invalid user")


@dataclass(frozen=True)
class Analysis:
    severity: Severity | None
    message: str
    summary: str
    entities: dict
    rule_name: str | None


def summarize(content: str, limit: int = 500) -> str:
    compact = " ".join(content.replace("\x00", " ").split())
    masked = EMAIL_RE.sub("[email]", compact)
    return masked[:limit] + ("..." if len(masked) > limit else "")


def extract_entities(content: str) -> dict:
    return {
        "ips": sorted(set(IP_RE.findall(content)))[:25],
        "domains": sorted(set(DOMAIN_RE.findall(content)))[:25],
        "hashes": sorted(set(HASH_RE.findall(content)))[:25],
        "emails": sorted(set(EMAIL_RE.findall(content)))[:25],
    }


def analyze_event(event: EventIn) -> Analysis:
    content_lower = event.content.lower()
    entities = extract_entities(event.content)
    summary = summarize(event.content)

    if any(term in content_lower for term in CRITICAL_TERMS):
        return Analysis(Severity.Critical, "Critical suspicious activity detected", summary, entities, "critical_keyword")
    if any(term in content_lower for term in HIGH_TERMS):
        return Analysis(Severity.High, "High-risk security event detected", summary, entities, "high_risk_keyword")
    if any(term in content_lower for term in MEDIUM_TERMS) or entities["ips"] or entities["hashes"]:
        return Analysis(Severity.Medium, "Suspicious security event detected", summary, entities, "indicator_or_medium_keyword")
    if event.source_type == SourceType.email and (entities["domains"] or "attachment" in content_lower):
        return Analysis(Severity.Low, "Email event contains inspectable indicators", summary, entities, "email_indicator")
    return Analysis(None, "No alert threshold reached", summary, entities, None)


async def ingest_event(
    session: AsyncSession,
    event: EventIn,
    collector_id: uuid.UUID | None = None,
    notification_recipient: str | None = None,
) -> tuple[LogEvent, Alert | None]:
    analysis = analyze_event(event)
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

    if event.source_type == SourceType.email:
        metadata = event.metadata or {}
        message_id = str(metadata.get("message_id") or event.correlation_id or log.id)
        exists = await session.scalar(select(EmailMessage).where(EmailMessage.message_id == message_id))
        if not exists:
            session.add(
                EmailMessage(
                    message_id=message_id,
                    mailbox=str(metadata.get("mailbox") or event.source),
                    sender=str(metadata.get("sender") or ""),
                    recipients=metadata.get("recipients") or [],
                    subject=str(metadata.get("subject") or event.source),
                    body_summary=analysis.summary,
                    attachment_metadata=metadata.get("attachments") or [],
                )
            )

    alert: Alert | None = None
    if analysis.severity:
        alert = Alert(
            log_id=log.id,
            severity=analysis.severity,
            message=analysis.message,
            ai_summary=analysis.summary,
            rule_name=analysis.rule_name,
        )
        session.add(alert)
        await session.flush()
        recipient = notification_recipient or await first_admin_email(session)
        if recipient:
            session.add(Notification(alert_id=alert.id, recipient=recipient))

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
    return log, alert


async def first_admin_email(session: AsyncSession) -> str | None:
    result = await session.execute(select(User.email).where(User.is_email_verified.is_(True)).limit(1))
    return result.scalar_one_or_none()
