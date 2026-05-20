import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db import get_session
from app.deps import current_user
from app.models import AiQuery, Alert, AlertTag, GeneratedRule, Incident, IncidentAlert, LogEvent, Notification, RuntimeSetting, Tag, User
from app.schemas import (
    AlertOut,
    AlertPatchIn,
    AnalystFeedbackIn,
    AnalystFeedbackOut,
    AssistantQueryIn,
    AssistantQueryOut,
    DeviceConsentIn,
    DeviceConsentOut,
    ImapEmailOtpIn,
    ImapEmailOut,
    IncidentIn,
    IncidentOut,
    KnowledgeSearchOut,
    NotificationOut,
    RuleSuggestionOut,
    RuntimeConfigIn,
    RuntimeConfigOut,
    SocMetricsOut,
    TagIn,
    TriageOut,
    UserOut,
    UserSettingsIn,
    VerifyImapEmailIn,
    VerifyNotificationEmailIn,
)
from app.services.crypto import decrypt_value, encrypt_value, mask_secret
from app.services.smtp_mail import send_smtp_email
from app.services.assistant_live import answer_question
from app.services.feedback_service import create_feedback
from app.services.knowledge_base import retrieve_knowledge
from app.services.metrics_service import soc_metrics
from app.services.runtime_config import load_runtime_config
from app.services.rule_suggestion_service import suggest_rule_for_alert
from app.services.triage_service import alert_triage_out

router = APIRouter(dependencies=[Depends(current_user)])


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


@router.get("/alerts/{alert_id}/triage", response_model=TriageOut)
async def get_alert_triage(alert_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> dict:
    alert = await get_alert(alert_id, session)
    log = await session.get(LogEvent, alert.log_id)
    triage = ((log.extracted_entities or {}).get("triage") if log else None) or {}
    return alert_triage_out(alert.id, triage)


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


@router.get("/metrics/soc", response_model=SocMetricsOut)
async def get_soc_metrics(session: AsyncSession = Depends(get_session)) -> dict:
    return await soc_metrics(session)


@router.get("/knowledge/search", response_model=list[KnowledgeSearchOut])
async def search_knowledge(q: str, limit: int = 6) -> list[dict]:
    return retrieve_knowledge(q, top_k=min(limit, 20))


@router.post("/feedback", response_model=AnalystFeedbackOut)
async def submit_feedback(
    payload: AnalystFeedbackIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
):
    try:
        return await create_feedback(
            session,
            user,
            payload.alert_id,
            payload.verdict,
            payload.corrected_severity,
            payload.corrected_mitre,
            payload.notes,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/rules/suggest/{alert_id}", response_model=RuleSuggestionOut)
async def suggest_rule(alert_id: uuid.UUID, session: AsyncSession = Depends(get_session)) -> GeneratedRule:
    try:
        return await suggest_rule_for_alert(session, alert_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@router.post("/assistant/query", response_model=AssistantQueryOut)
async def assistant_query(
    payload: AssistantQueryIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> AssistantQueryOut:
    try:
        answer = await answer_question(session, payload.question)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"AI assistant failed: {str(exc)}") from exc
    session.add(AiQuery(user_id=user.id, question=payload.question, response=answer))
    await session.commit()
    return AssistantQueryOut(answer=answer)


@router.get("/notifications", response_model=list[NotificationOut])
async def list_notifications(limit: int = 50, session: AsyncSession = Depends(get_session)) -> list[Notification]:
    result = await session.execute(select(Notification).order_by(desc(Notification.created_at)).limit(min(limit, 200)))
    return list(result.scalars())


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
    "smtp_host": False,
    "smtp_port": False,
    "smtp_username": False,
    "smtp_password": True,
    "smtp_from": False,
    "imap_host": False,
    "imap_port": False,
    "imap_user": False,
    "imap_password": True,
    "imap_folder": False,
    "imap_backfill_limit": False,
    "imap_user_verified": False,
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
        if key not in CONFIG_KEYS or key == "imap_user_verified":
            continue
        if key == "imap_user":
            current = await session.get(RuntimeSetting, "imap_user")
            current_value = current.value_public if current else None
            if (value or None) != current_value:
                verified = await session.get(RuntimeSetting, "imap_user_verified")
                if verified:
                    verified.value_public = None
                    verified.updated_by = user.id
        setting = await session.get(RuntimeSetting, key)
        if not setting:
            setting = RuntimeSetting(key=key, is_secret=CONFIG_KEYS[key])
            session.add(setting)
        setting.updated_by = user.id
        if CONFIG_KEYS[key]:
            if value == "":
                setting.value_encrypted = None
            elif value and "..." not in value and value != "****":
                setting.value_encrypted = encrypt_value(value)
        else:
            setting.value_public = value or None
    await session.commit()
    return await get_runtime_config(session)


@router.post("/settings/imap-email/otp", response_model=ImapEmailOut)
async def request_imap_email_otp(
    payload: ImapEmailOtpIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> ImapEmailOut:
    from datetime import datetime, timedelta, timezone
    from app.core.config import get_settings
    from app.core.security import generate_otp, hash_otp
    from app.models import OtpPurpose, OtpToken

    email_str = str(payload.imap_user).lower()
    imap_user = await session.get(RuntimeSetting, "imap_user")
    if not imap_user:
        imap_user = RuntimeSetting(key="imap_user", is_secret=False)
        session.add(imap_user)
    imap_user.value_public = email_str
    imap_user.updated_by = user.id

    verified = await session.get(RuntimeSetting, "imap_user_verified")
    if not verified:
        verified = RuntimeSetting(key="imap_user_verified", is_secret=False)
        session.add(verified)
    verified.value_public = None
    verified.updated_by = user.id

    otp = generate_otp()
    session.add(
        OtpToken(
            user_id=user.id,
            otp_hash=hash_otp(otp),
            purpose=OtpPurpose.verify_imap_email,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=get_settings().otp_ttl_minutes),
        )
    )
    await session.commit()
    try:
        config = await load_runtime_config(session)
        send_smtp_email(
            email_str,
            "[AI-SOC] OTP xác nhận mailbox IMAP",
            f"OTP xác nhận quyền đọc mailbox IMAP là: {otp}",
            config,
        )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Gửi OTP mailbox IMAP thất bại: {str(exc)}") from exc
    return ImapEmailOut(
        imap_user=email_str,
        is_verified=False,
        otp_required=True,
        message=f"Đã gửi OTP xác nhận quyền đọc mailbox IMAP đến {email_str}.",
    )


@router.post("/settings/imap-email/verify", response_model=ImapEmailOut)
async def verify_imap_email(
    payload: VerifyImapEmailIn,
    user: User = Depends(current_user),
    session: AsyncSession = Depends(get_session),
) -> ImapEmailOut:
    from datetime import datetime, timezone
    from app.core.security import verify_otp
    from app.models import OtpPurpose, OtpToken

    email_str = str(payload.imap_user).lower()
    imap_user = await session.get(RuntimeSetting, "imap_user")
    if not imap_user or imap_user.value_public != email_str:
        raise HTTPException(status_code=400, detail="IMAP User chưa khớp với mailbox đang cấu hình")
    token = await session.scalar(
        select(OtpToken)
        .where(OtpToken.user_id == user.id, OtpToken.purpose == OtpPurpose.verify_imap_email, OtpToken.consumed_at.is_(None))
        .order_by(OtpToken.expires_at.desc())
    )
    now = datetime.now(timezone.utc)
    if not token or token.expires_at < now or not verify_otp(payload.otp, token.otp_hash):
        raise HTTPException(status_code=400, detail="Mã xác nhận không hợp lệ hoặc đã hết hạn")
    token.consumed_at = now
    verified = await session.get(RuntimeSetting, "imap_user_verified")
    if not verified:
        verified = RuntimeSetting(key="imap_user_verified", is_secret=False)
        session.add(verified)
    verified.value_public = email_str
    verified.updated_by = user.id
    await session.commit()
    return ImapEmailOut(imap_user=email_str, is_verified=True, otp_required=False, message="Mailbox IMAP đã được xác nhận")


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
        config = await load_runtime_config(session)
        send_smtp_email(
            email_str,
            "[AI-SOC] OTP xác nhận email nhận cảnh báo",
            f"OTP xác nhận email nhận cảnh báo là: {otp}",
            config,
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
    """Remove notification email and revoke alert delivery permission."""
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
