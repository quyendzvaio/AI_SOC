from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import current_user
from app.models import EmailMessage
from app.schemas import EmailMessageOut
from app.services.email_service import list_emails as list_email_messages
from app.services.email_service import list_mailbox_email_feed

router = APIRouter(tags=["emails"], dependencies=[Depends(current_user)])


@router.get("/emails", response_model=list[EmailMessageOut])
async def list_emails(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[EmailMessage]:
    return await list_email_messages(session, limit)


@router.get("/emails/mailbox", response_model=list[EmailMessageOut])
async def list_mailbox_emails_feed(
    limit: int = 100,
    session: AsyncSession = Depends(get_session),
) -> list[EmailMessage]:
    return await list_mailbox_email_feed(session, limit)
