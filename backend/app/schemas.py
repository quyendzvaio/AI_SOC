import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, EmailStr, Field

from app.models import CollectorOS, CollectorStatus, Severity, SourceType, WorkStatus


class ApiModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class UserOut(ApiModel):
    id: uuid.UUID
    email: EmailStr
    role: str
    is_email_verified: bool
    notification_email: str | None = None
    is_notification_email_verified: bool = False


class RegisterIn(ApiModel):
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)


class LoginIn(ApiModel):
    email: EmailStr
    password: str


class VerifyOtpIn(ApiModel):
    email: EmailStr
    otp: str = Field(min_length=6, max_length=6)
    purpose: str = "register"


class ResendOtpIn(ApiModel):
    email: EmailStr
    purpose: str = "register"


class AuthOut(ApiModel):
    token: str | None = None
    user: UserOut
    otp_required: bool = False


class CollectorRegisterIn(ApiModel):
    host_name: str = Field(min_length=1, max_length=255)
    os_type: CollectorOS
    agent_version: str = Field(default="0.1.0", max_length=64)


class CollectorOut(ApiModel):
    id: uuid.UUID
    host_name: str
    os_type: CollectorOS
    agent_version: str
    status: CollectorStatus
    last_seen_at: datetime


class CollectorHeartbeatIn(ApiModel):
    collector_id: uuid.UUID
    status: CollectorStatus = CollectorStatus.online


class EventIn(ApiModel):
    source_type: SourceType
    source: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1)
    correlation_id: str | None = Field(default=None, max_length=128)
    content_ref: str | None = None
    received_at: datetime | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class CollectorEventsIn(ApiModel):
    collector_id: uuid.UUID
    events: list[EventIn] = Field(min_length=1, max_length=200)


class WebhookEventIn(EventIn):
    source_type: SourceType = SourceType.webhook


class LogOut(ApiModel):
    id: uuid.UUID
    source_type: SourceType
    source: str
    log_summary: str
    extracted_entities: dict[str, Any]
    correlation_id: str
    received_at: datetime


class AlertOut(ApiModel):
    id: uuid.UUID
    log_id: uuid.UUID
    severity: Severity
    status: WorkStatus
    message: str
    ai_summary: str
    rule_name: str | None
    detected_at: datetime


class AlertPatchIn(ApiModel):
    severity: Severity | None = None
    status: WorkStatus | None = None
    message: str | None = Field(default=None, max_length=512)


class TagIn(ApiModel):
    name: str = Field(min_length=1, max_length=64)
    color: str = Field(default="#2563EB", max_length=32)


class IncidentIn(ApiModel):
    name: str = Field(min_length=1, max_length=255)
    description: str = ""
    severity: Severity = Severity.Medium
    alert_id: uuid.UUID | None = None


class IncidentOut(ApiModel):
    id: uuid.UUID
    name: str
    description: str
    severity: Severity
    status: WorkStatus
    created_at: datetime


class AssistantQueryIn(ApiModel):
    question: str = Field(min_length=1)
    context: dict[str, Any] = Field(default_factory=dict)


class AssistantQueryOut(ApiModel):
    answer: str


class UserSettingsIn(ApiModel):
    notification_email: EmailStr


class VerifyNotificationEmailIn(ApiModel):
    otp: str = Field(min_length=6, max_length=6)


class ImapEmailOtpIn(ApiModel):
    imap_user: EmailStr


class VerifyImapEmailIn(ApiModel):
    imap_user: EmailStr
    otp: str = Field(min_length=6, max_length=6)


class NotificationEmailOut(ApiModel):
    notification_email: str | None = None
    is_notification_email_verified: bool = False
    otp_required: bool = False
    dev_otp: str | None = None
    message: str | None = None


class DeviceConsentIn(ApiModel):
    granted: bool


class DeviceConsentOut(ApiModel):
    granted: bool
    granted_at: datetime | None = None


class RuntimeConfigIn(ApiModel):
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    nvd_api_key: str | None = None
    smtp_host: str | None = None
    smtp_port: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    imap_host: str | None = None
    imap_port: str | None = None
    imap_user: str | None = None
    imap_password: str | None = None
    imap_folder: str | None = None
    imap_backfill_limit: str | None = None


class RuntimeConfigOut(ApiModel):
    llm_base_url: str | None = None
    llm_model: str | None = None
    llm_api_key: str | None = None
    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None
    nvd_api_key: str | None = None
    smtp_host: str | None = None
    smtp_port: str | None = None
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    imap_host: str | None = None
    imap_port: str | None = None
    imap_user: str | None = None
    imap_password: str | None = None
    imap_folder: str | None = None
    imap_backfill_limit: str | None = None
    imap_user_verified: str | None = None


class ImapEmailOut(ApiModel):
    imap_user: str | None = None
    is_verified: bool = False
    otp_required: bool = False
    dev_otp: str | None = None
    message: str | None = None


class NotificationOut(ApiModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    channel: str
    recipient: str
    status: str
    created_at: datetime


class EmailMessageOut(ApiModel):
    id: uuid.UUID
    message_id: str
    mailbox: str
    sender: str
    recipients: list[Any]
    subject: str
    body_summary: str
    attachment_metadata: list[Any]
    received_at: datetime


class EnrichmentIn(ApiModel):
    log_id: uuid.UUID
    severity: Severity | None = None
    message: str | None = Field(default=None, max_length=512)
    ai_summary: str | None = None
    rule_name: str | None = Field(default=None, max_length=255)
    enrichment: dict[str, Any] = Field(default_factory=dict)


class TriageOut(ApiModel):
    alert_id: uuid.UUID
    risk_score: float
    confidence: float
    priority: str
    mitre_techniques: list[str] = Field(default_factory=list)
    threat_labels: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class AnalystFeedbackIn(ApiModel):
    alert_id: uuid.UUID
    verdict: str = Field(pattern="^(true_positive|false_positive|false_negative|severity_wrong|mitre_wrong)$")
    corrected_severity: Severity | None = None
    corrected_mitre: list[str] = Field(default_factory=list)
    notes: str = Field(default="", max_length=2000)


class AnalystFeedbackOut(ApiModel):
    id: uuid.UUID
    alert_id: uuid.UUID
    verdict: str
    corrected_severity: Severity | None = None
    corrected_mitre: list[str] = Field(default_factory=list)
    notes: str
    created_at: datetime


class RuleSuggestionOut(ApiModel):
    id: uuid.UUID
    source_alert_id: uuid.UUID | None = None
    name: str
    rule_type: str
    rule_body: dict[str, Any]
    backtest_summary: dict[str, Any]
    status: str
    created_at: datetime


class KnowledgeSearchOut(ApiModel):
    title: str
    source: str
    text: str
    score: float


class SocMetricsOut(ApiModel):
    total_logs: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    total_incidents: int
    feedback_count: int
    true_positive_feedback: int
    false_positive_feedback: int
    generated_rules: int
    top_mitre: list[dict[str, Any]]
