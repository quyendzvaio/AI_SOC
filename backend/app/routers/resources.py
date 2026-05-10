import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import current_user
from app.models import AiQuery, Alert, AlertTag, EmailMessage, Incident, IncidentAlert, LogEvent, MonitoredEmail, Notification, RuntimeSetting, Tag, User
from app.schemas import (
    AlertOut,
    AlertPatchIn,
    AssistantQueryIn,
    AssistantQueryOut,
    DeviceConsentIn,
    DeviceConsentOut,
    EmailMessageOut,
    IncidentIn,
    IncidentOut,
    LogOut,
    MonitoredEmailIn,
    MonitoredEmailOut,
    NotificationOut,
    RuntimeConfigIn,
    RuntimeConfigOut,
    TagIn,
    UserOut,
    UserSettingsIn,
    VerifyMonitoredEmailIn,
    VerifyNotificationEmailIn,
)
from app.services.crypto import decrypt_value, encrypt_value, mask_secret
from app.services.smtp_mail import send_smtp_email

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


@router.get("/emails/monitored", response_model=list[EmailMessageOut])
async def list_monitored_emails_feed(
    limit: int = 100,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[EmailMessage]:
    monitored_rows = await session.execute(
        select(MonitoredEmail).where(MonitoredEmail.user_id == user.id, MonitoredEmail.is_verified.is_(True))
    )
    monitored_set = {row.email.lower() for row in monitored_rows.scalars()}
    if not monitored_set:
        return []
    result = await session.execute(select(EmailMessage).order_by(desc(EmailMessage.received_at)).limit(min(limit, 500)))
    matched: list[EmailMessage] = []
    for mail in result.scalars():
        sender = (mail.sender or "").lower()
        recipients = [str(item).lower() for item in (mail.recipients or [])]
        if sender in monitored_set or any(item in monitored_set for item in recipients):
            matched.append(mail)
    return matched[: min(limit, 200)]


@router.get("/me", response_model=UserOut)
async def get_me(user: User = Depends(current_user)) -> UserOut:
    from app.routers.auth import user_out
    return user_out(user)


@router.get("/settings/device-consent", response_model=DeviceConsentOut)
async def get_device_consent(user: User = Depends(current_user)) -> DeviceConsentOut:
    return DeviceConsentOut(granted=bool(user.device_log_consent_granted_at), granted_at=user.device_log_consent_granted_at)


@router.post("/settings/device-consent", response_model=DeviceConsentOut)
async def update_device_consent(
    payload: DeviceConsentIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> DeviceConsentOut:
    from datetime import datetime, timezone

    user.device_log_consent_granted_at = datetime.now(timezone.utc) if payload.granted else None
    await session.commit()
    await session.refresh(user)
    return DeviceConsentOut(granted=bool(user.device_log_consent_granted_at), granted_at=user.device_log_consent_granted_at)


CONFIG_KEYS = {
    "llm_base_url": False,
    "llm_model": False,
    "llm_api_key": True,
    "abuseipdb_api_key": True,
    "virustotal_api_key": True,
    "nvd_api_key": True,
}


@router.get("/settings/runtime-config", response_model=RuntimeConfigOut)
async def get_runtime_config(session: AsyncSession = Depends(get_session)) -> RuntimeConfigOut:
    result = await session.execute(select(RuntimeSetting).where(RuntimeSetting.key.in_(CONFIG_KEYS.keys())))
    values: dict[str, str | None] = {}
    for setting in result.scalars():
        values[setting.key] = mask_secret(decrypt_value(setting.value_encrypted)) if setting.is_secret else setting.value_public
    return RuntimeConfigOut(**values)


@router.post("/settings/runtime-config", response_model=RuntimeConfigOut)
async def update_runtime_config(
    payload: RuntimeConfigIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> RuntimeConfigOut:
    for key, value in payload.model_dump(exclude_unset=True).items():
        if key not in CONFIG_KEYS:
            continue
        setting = await session.get(RuntimeSetting, key)
        if not setting:
            setting = RuntimeSetting(key=key, is_secret=CONFIG_KEYS[key])
            session.add(setting)
        setting.updated_by = user.id
        if CONFIG_KEYS[key]:
            if value and "..." not in value and value != "****":
                setting.value_encrypted = encrypt_value(value)
        else:
            setting.value_public = value
    await session.commit()
    return await get_runtime_config(session)


@router.post("/settings/monitored-email", response_model=MonitoredEmailOut)
async def request_monitored_email(
    payload: MonitoredEmailIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> MonitoredEmailOut:
    from datetime import datetime, timedelta, timezone
    from app.core.config import get_settings
    from app.core.security import generate_otp, hash_otp
    from app.models import OtpPurpose, OtpToken

    email_str = str(payload.email).lower()
    monitored = await session.scalar(select(MonitoredEmail).where(MonitoredEmail.user_id == user.id, MonitoredEmail.email == email_str))
    if not monitored:
        monitored = MonitoredEmail(user_id=user.id, email=email_str, provider="smtp_auth")
        session.add(monitored)
        await session.flush()
    monitored.is_verified = False
    monitored.verified_at = None
    otp = generate_otp()
    session.add(
        OtpToken(
            user_id=user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.verify_monitored_email,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=get_settings().otp_ttl_minutes),
        )
    )
    await session.commit()
    try:
        send_smtp_email(
            email_str,
            "[AI-SOC] OTP xác nhận email theo dõi",
            f"OTP xác nhận quyền theo dõi email là: {otp}",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gửi OTP email theo dõi thất bại: {str(exc)}") from exc
    return MonitoredEmailOut(
        id=monitored.id,
        email=monitored.email,
        is_verified=False,
        otp_required=True,
        message=f"Đã gửi email xác nhận quyền theo dõi đến {email_str}.",
    )


@router.post("/settings/monitored-email/verify", response_model=MonitoredEmailOut)
async def verify_monitored_email(
    payload: VerifyMonitoredEmailIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> MonitoredEmailOut:
    from datetime import datetime, timezone
    from app.core.security import verify_otp
    from app.models import OtpPurpose, OtpToken

    email_str = str(payload.email).lower()
    monitored = await session.scalar(
        select(MonitoredEmail).where(MonitoredEmail.user_id == user.id, MonitoredEmail.email == email_str)
    )
    if not monitored:
        raise HTTPException(status_code=400, detail="Email theo dõi chưa được đăng ký")
    token = await session.scalar(
        select(OtpToken)
        .where(OtpToken.user_id == user.id, OtpToken.purpose == OtpPurpose.verify_monitored_email, OtpToken.consumed_at.is_(None))
        .order_by(OtpToken.expires_at.desc())
    )
    now = datetime.now(timezone.utc)
    if not token or token.expires_at < now or not verify_otp(payload.otp, token.otp_hash):
        raise HTTPException(status_code=400, detail="Mã xác nhận không hợp lệ hoặc đã hết hạn")
    token.consumed_at = now
    monitored.is_verified = True
    monitored.verified_at = now
    await session.commit()
    return MonitoredEmailOut(id=monitored.id, email=monitored.email, is_verified=True, otp_required=False, message="Email theo dõi đã được xác nhận")


@router.get("/settings/monitored-email", response_model=list[MonitoredEmailOut])
async def list_monitored_emails(user: User = Depends(current_user), session: AsyncSession = Depends(get_session)) -> list[MonitoredEmail]:
    result = await session.execute(select(MonitoredEmail).where(MonitoredEmail.user_id == user.id).order_by(desc(MonitoredEmail.created_at)))
    return list(result.scalars())


@router.post("/settings/notification-email")
async def request_notification_email(
    payload: UserSettingsIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Step 1: User submits notification email → system sends OTP to that email."""
    from datetime import datetime, timedelta, timezone
    from app.core.config import get_settings
    from app.core.security import generate_otp, hash_otp
    from app.models import OtpPurpose, OtpToken

    email_str = str(payload.notification_email).lower()

    # Save email as pending (not yet verified)
    user.notification_email = email_str
    user.is_notification_email_verified = False

    # Generate OTP
    otp = generate_otp()
    session.add(
        OtpToken(
            user_id=user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.verify_notification_email,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=get_settings().otp_ttl_minutes),
        )
    )
    await session.commit()
    await session.refresh(user)

    try:
        send_smtp_email(
            email_str,
            "[AI-SOC] OTP xác nhận email nhận cảnh báo",
            f"OTP xác nhận email nhận cảnh báo là: {otp}",
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gửi OTP email cảnh báo thất bại: {str(exc)}") from exc
    return {
        "notification_email": user.notification_email,
        "is_notification_email_verified": False,
        "otp_required": True,
        "message": f"Mã xác nhận đã được gửi đến {email_str}. Vui lòng kiểm tra email.",
    }


@router.post("/settings/notification-email/verify")
async def verify_notification_email(
    payload: VerifyNotificationEmailIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Step 2: User enters OTP from their email → system verifies and activates."""
    from datetime import datetime, timezone
    from app.core.security import verify_otp
    from app.models import OtpPurpose, OtpToken

    if not user.notification_email:
        raise HTTPException(status_code=400, detail="Chưa có email thông báo nào được đăng ký")

    # Find the latest unused OTP for this purpose
    token = await session.scalar(
        select(OtpToken)
        .where(
            OtpToken.user_id == user.id,
            OtpToken.purpose == OtpPurpose.verify_notification_email,
            OtpToken.consumed_at.is_(None),
        )
        .order_by(OtpToken.expires_at.desc())
    )

    now = datetime.now(timezone.utc)
    if not token or token.expires_at < now or not verify_otp(payload.otp, token.otp_hash):
        raise HTTPException(status_code=400, detail="Mã OTP không hợp lệ hoặc đã hết hạn")

    # Mark OTP consumed and email as verified
    token.consumed_at = now
    user.is_notification_email_verified = True
    await session.commit()
    await session.refresh(user)

    return {
        "notification_email": user.notification_email,
        "is_notification_email_verified": True,
        "otp_required": False,
        "message": f"Email {user.notification_email} đã được xác nhận thành công! Bạn sẽ nhận thông báo alert tại đây.",
    }


@router.delete("/settings/notification-email")
async def remove_notification_email(
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Remove notification email and revoke monitoring permission."""
    user.notification_email = None
    user.is_notification_email_verified = False
    await session.commit()
    return {"message": "Đã xóa email thông báo", "notification_email": None, "is_notification_email_verified": False}


class AiQueryOut(AssistantQueryOut):
    id: str
    question: str
    asked_at: str


@router.get("/assistant/history")
async def assistant_history(
    limit: int = 50,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> list[dict]:
    result = await session.execute(
        select(AiQuery)
        .where(AiQuery.user_id == user.id)
        .order_by(desc(AiQuery.asked_at))
        .limit(min(limit, 100))
    )
    return [
        {
            "id": str(q.id),
            "question": q.question,
            "answer": q.response,
            "asked_at": q.asked_at.isoformat() if q.asked_at else None,
        }
        for q in result.scalars()
    ]
