import smtplib
from email.message import EmailMessage

from app.core.config import get_settings


def normalize_secret(value: str | None) -> str:
    return (value or "").strip()


def normalize_smtp_password(host: str, password: str | None) -> str:
    normalized = normalize_secret(password)
    if host.endswith("gmail.com"):
        return normalized.replace(" ", "")
    return normalized


def smtp_ready(config: dict[str, str | None] | None = None) -> bool:
    settings = get_settings()
    config = config or {}
    username = normalize_secret(config.get("smtp_username") or settings.smtp_username)
    host = normalize_secret(config.get("smtp_host") or settings.smtp_host)
    password = normalize_smtp_password(host, config.get("smtp_password") or settings.smtp_password)
    return bool(username and password)


def send_smtp_email(to_email: str, subject: str, body_text: str, config: dict[str, str | None] | None = None) -> None:
    settings = get_settings()
    config = config or {}
    host = normalize_secret(config.get("smtp_host") or settings.smtp_host)
    port = int(config.get("smtp_port") or settings.smtp_port)
    username = normalize_secret(config.get("smtp_username") or settings.smtp_username)
    password = normalize_smtp_password(host, config.get("smtp_password") or settings.smtp_password)
    from_email = normalize_secret(config.get("smtp_from") or settings.smtp_from or username)

    if not (username and password):
        raise RuntimeError("SMTP chưa cấu hình: cần SMTP_USERNAME và SMTP_PASSWORD")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(body_text)

    with smtplib.SMTP_SSL(host, port, timeout=20) as server:
        server.login(username, password)
        server.send_message(msg)
