import smtplib
from email.message import EmailMessage

from app.core.config import get_settings


def smtp_ready() -> bool:
    settings = get_settings()
    return bool(settings.smtp_username and settings.smtp_password)


def send_smtp_email(to_email: str, subject: str, body_text: str) -> None:
    settings = get_settings()
    if not smtp_ready():
        raise RuntimeError("SMTP chưa cấu hình: cần SMTP_USERNAME và SMTP_PASSWORD")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.smtp_from or settings.smtp_username
    msg["To"] = to_email
    msg.set_content(body_text)

    with smtplib.SMTP_SSL(settings.smtp_host, settings.smtp_port, timeout=20) as server:
        server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(msg)
