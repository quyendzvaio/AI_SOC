import enum
import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, Enum, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import Base


class UserRole(str, enum.Enum):
    soc_analyst = "soc_analyst"
    admin = "admin"


class OtpPurpose(str, enum.Enum):
    register = "register"
    login = "login"
    reset_password = "reset_password"
    verify_notification_email = "verify_notification_email"
    verify_imap_email = "verify_imap_email"


class CollectorOS(str, enum.Enum):
    windows = "windows"
    ubuntu = "ubuntu"


class CollectorStatus(str, enum.Enum):
    online = "online"
    offline = "offline"
    degraded = "degraded"


class SourceType(str, enum.Enum):
    windows_agent = "windows_agent"
    ubuntu_agent = "ubuntu_agent"
    email = "email"
    webhook = "webhook"


class Severity(str, enum.Enum):
    Low = "Low"
    Medium = "Medium"
    High = "High"
    Critical = "Critical"


class WorkStatus(str, enum.Enum):
    open = "open"
    investigating = "investigating"
    resolved = "resolved"
    false_positive = "false_positive"


class NotificationStatus(str, enum.Enum):
    queued = "queued"
    sent = "sent"
    failed = "failed"


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    firebase_uid: Mapped[str | None] = mapped_column(String(128), unique=True, nullable=True)
    auth_provider: Mapped[str] = mapped_column(String(32), default="local")
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.soc_analyst)
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    notification_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_notification_email_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    device_log_consent_granted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(Integer, default=0)
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class OtpToken(Base):
    __tablename__ = "otp_tokens"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    otp_hash: Mapped[str] = mapped_column(String(255))
    purpose: Mapped[OtpPurpose] = mapped_column(Enum(OtpPurpose))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user: Mapped[User] = relationship()


class Collector(Base):
    __tablename__ = "collectors"
    __table_args__ = (UniqueConstraint("host_name", "os_type", name="uq_collector_host_os"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    host_name: Mapped[str] = mapped_column(String(255), index=True)
    os_type: Mapped[CollectorOS] = mapped_column(Enum(CollectorOS))
    agent_version: Mapped[str] = mapped_column(String(64))
    status: Mapped[CollectorStatus] = mapped_column(Enum(CollectorStatus), default=CollectorStatus.online)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class LogEvent(Base):
    __tablename__ = "logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    collector_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("collectors.id"), nullable=True)
    source_type: Mapped[SourceType] = mapped_column(Enum(SourceType), index=True)
    source: Mapped[str] = mapped_column(String(255), index=True)
    content_ref: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    log_summary: Mapped[str] = mapped_column(Text)
    extracted_entities: Mapped[dict] = mapped_column(JSONB, default=dict)
    correlation_id: Mapped[str] = mapped_column(String(128), index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    log_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("logs.id", ondelete="CASCADE"), index=True)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), index=True)
    status: Mapped[WorkStatus] = mapped_column(Enum(WorkStatus), default=WorkStatus.open, index=True)
    message: Mapped[str] = mapped_column(String(512))
    ai_summary: Mapped[str] = mapped_column(Text)
    rule_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), index=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    log: Mapped[LogEvent] = relationship()


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity), default=Severity.Medium)
    status: Mapped[WorkStatus] = mapped_column(Enum(WorkStatus), default=WorkStatus.open)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IncidentAlert(Base):
    __tablename__ = "incident_alerts"

    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)


class Tag(Base):
    __tablename__ = "tags"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    color: Mapped[str] = mapped_column(String(32), default="#2563EB")


class AlertTag(Base):
    __tablename__ = "alert_tags"

    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), primary_key=True)
    tag_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)


class IncidentTag(Base):
    __tablename__ = "incident_tags"

    incident_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"), primary_key=True)
    tag_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tags.id", ondelete="CASCADE"), primary_key=True)


class EmailMessage(Base):
    __tablename__ = "email_messages"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    message_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    mailbox: Mapped[str] = mapped_column(String(255))
    sender: Mapped[str] = mapped_column(String(255))
    recipients: Mapped[list] = mapped_column(JSONB, default=list)
    subject: Mapped[str] = mapped_column(String(512))
    body_summary: Mapped[str] = mapped_column(Text)
    attachment_metadata: Mapped[list] = mapped_column(JSONB, default=list)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class IntelSource(Base):
    __tablename__ = "intel_sources"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True)
    type: Mapped[str] = mapped_column(String(64))
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    config_encrypted: Mapped[dict] = mapped_column(JSONB, default=dict)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class RuntimeSetting(Base):
    __tablename__ = "runtime_settings"

    key: Mapped[str] = mapped_column(String(128), primary_key=True)
    value_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    value_public: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_secret: Mapped[bool] = mapped_column(Boolean, default=True)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    channel: Mapped[str] = mapped_column(String(32), default="email")
    recipient: Mapped[str] = mapped_column(String(255))
    status: Mapped[NotificationStatus] = mapped_column(Enum(NotificationStatus), default=NotificationStatus.queued)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class AiQuery(Base):
    __tablename__ = "ai_queries"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    question: Mapped[str] = mapped_column(Text)
    response: Mapped[str] = mapped_column(Text)
    asked_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AnalystFeedback(Base):
    __tablename__ = "analyst_feedback"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    alert_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("alerts.id", ondelete="CASCADE"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    verdict: Mapped[str] = mapped_column(String(64), index=True)
    corrected_severity: Mapped[Severity | None] = mapped_column(Enum(Severity), nullable=True)
    corrected_mitre: Mapped[list] = mapped_column(JSONB, default=list)
    notes: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class GeneratedRule(Base):
    __tablename__ = "generated_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    source_alert_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("alerts.id", ondelete="SET NULL"), nullable=True, index=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    rule_type: Mapped[str] = mapped_column(String(64), default="sigma")
    rule_body: Mapped[dict] = mapped_column(JSONB, default=dict)
    backtest_summary: Mapped[dict] = mapped_column(JSONB, default=dict)
    status: Mapped[str] = mapped_column(String(32), default="draft", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
