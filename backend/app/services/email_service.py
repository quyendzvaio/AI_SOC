from email.utils import getaddresses

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import EmailMessage, SourceType
from app.schemas import EventIn
from app.services.detection import Analysis
from app.services.runtime_config import load_runtime_config


def normalize_email_values(*values: object) -> set[str]:
    raw: list[str] = []
    for value in values:
        if not value:
            continue
        if isinstance(value, list):
            raw.extend(str(item) for item in value if item)
        else:
            raw.append(str(value))
    parsed = {addr.lower() for _name, addr in getaddresses(raw) if addr}
    direct = {item.strip().lower() for item in raw if "@" in item and "," not in item}
    return parsed | direct


async def persist_email_message(session: AsyncSession, event: EventIn, analysis: Analysis, fallback_message_id: object) -> None:
    if event.source_type != SourceType.email:
        return

    metadata = event.metadata or {}
    message_id = str(metadata.get("message_id") or event.correlation_id or fallback_message_id)
    exists = await session.scalar(select(EmailMessage).where(EmailMessage.message_id == message_id))
    if exists:
        return

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


async def list_emails(session: AsyncSession, limit: int = 50) -> list[EmailMessage]:
    result = await session.execute(select(EmailMessage).order_by(desc(EmailMessage.received_at)).limit(min(limit, 200)))
    return list(result.scalars())


async def list_mailbox_email_feed(session: AsyncSession, limit: int = 100) -> list[EmailMessage]:
    config = await load_runtime_config(session)
    imap_user = (config.get("imap_user") or "").lower()
    verified_user = (config.get("imap_user_verified") or "").lower()
    if not imap_user or verified_user != imap_user:
        return []

    scan_limit = min(max(limit * 10, 1000), 2000)
    result = await session.execute(select(EmailMessage).order_by(desc(EmailMessage.received_at)).limit(scan_limit))
    matched: list[EmailMessage] = []
    for mail in result.scalars():
        addresses = normalize_email_values(mail.sender, mail.recipients, mail.mailbox)
        if imap_user in addresses:
            matched.append(mail)
    return matched[: min(limit, 200)]
