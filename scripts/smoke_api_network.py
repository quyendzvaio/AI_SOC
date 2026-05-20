import base64
import hashlib
import hmac
import json
import os
import subprocess
import time
import uuid

import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
API_BASE = os.getenv("AI_SOC_API_BASE", "http://127.0.0.1:8000")
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-secret-before-prod")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "local-ingest-token")


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_jwt(user_id: str) -> str:
    now = int(time.time())
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(
        json.dumps(
            {"sub": user_id, "iat": now, "exp": now + 3600, "role": "soc_analyst"},
            separators=(",", ":"),
        ).encode()
    )
    signing_input = f"{header}.{payload}".encode()
    signature = b64url(hmac.new(JWT_SECRET.encode(), signing_input, hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"


def seed_user() -> tuple[str, str]:
    user_id = str(uuid.uuid4())
    email = f"smoke-{int(time.time())}@example.com"
    sql = (
        "INSERT INTO users "
        "(id,email,password_hash,auth_provider,role,is_email_verified,is_notification_email_verified,failed_login_count,created_at) "
        f"VALUES ('{user_id}','{email}','smoke-hash','local','soc_analyst',true,false,0,now());"
    )
    subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "aisoc", "-d", "aisoc", "-c", sql],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return user_id, sign_jwt(user_id)


def seed_verified_imap_user(user_id: str, email: str) -> None:
    sql = (
        "INSERT INTO runtime_settings (key,value_public,is_secret,updated_by,updated_at) VALUES "
        f"('imap_user','{email}',false,'{user_id}',now()),"
        f"('imap_user_verified','{email}',false,'{user_id}',now()) "
        "ON CONFLICT (key) DO UPDATE SET value_public=excluded.value_public, updated_by=excluded.updated_by, updated_at=now();"
    )
    subprocess.run(
        ["docker", "compose", "exec", "-T", "postgres", "psql", "-U", "aisoc", "-d", "aisoc", "-c", sql],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


def main() -> None:
    health = requests.get(f"{API_BASE}/healthz", timeout=10)
    health.raise_for_status()

    user_id, token = seed_user()
    auth = {"Authorization": f"Bearer {token}"}
    seed_verified_imap_user(user_id, "smoke@example.com")
    collector = requests.post(
        f"{API_BASE}/collectors/register",
        headers={"X-Ingest-Token": INGEST_TOKEN},
        json={"host_name": f"smoke-host-{int(time.time())}", "os_type": "ubuntu", "agent_version": "smoke"},
        timeout=10,
    )
    collector.raise_for_status()
    collector_id = collector.json()["id"]

    payload = {
        "collector_id": collector_id,
        "events": [
            {
                "source_type": "ubuntu_agent",
                "source": "auth.log",
                "content": "100 failed SSH login attempts from IP 45.21.90.2 within 3 minutes",
                "correlation_id": f"smoke-log-{uuid.uuid4()}",
                "metadata": {"smoke": True},
            },
            {
                "source_type": "email",
                "source": "mailbox",
                "content": "Subject: Reset your bank account password immediately Click here: http://fake-bank-login-security.ru Attachment: invoice.exe",
                "correlation_id": f"smoke-mail-{uuid.uuid4()}",
                "metadata": {
                    "message_id": f"smoke-mail-{uuid.uuid4()}",
                    "mailbox": "smoke@example.com",
                    "sender": "security@fake-bank-login-security.ru",
                    "recipients": ["smoke@example.com"],
                    "subject": "Reset your bank account password immediately",
                    "attachments": [{"filename": "invoice.exe"}],
                },
            },
        ],
    }
    ingest = requests.post(
        f"{API_BASE}/collectors/events",
        headers={"X-Ingest-Token": INGEST_TOKEN},
        json=payload,
        timeout=15,
    )
    ingest.raise_for_status()

    logs = requests.get(f"{API_BASE}/logs?limit=20", headers=auth, timeout=10)
    alerts = requests.get(f"{API_BASE}/alerts?limit=20", headers=auth, timeout=10)
    emails = requests.get(f"{API_BASE}/emails?limit=20", headers=auth, timeout=10)
    mailbox_emails = requests.get(f"{API_BASE}/emails/mailbox?limit=20", headers=auth, timeout=10)
    metrics = requests.get(f"{API_BASE}/metrics/soc", headers=auth, timeout=10)
    knowledge = requests.get(f"{API_BASE}/knowledge/search", headers=auth, params={"q": "brute force T1110 MFA"}, timeout=10)
    for response in (logs, alerts, emails, mailbox_emails, metrics, knowledge):
        response.raise_for_status()

    high_alerts = [a for a in alerts.json() if a["severity"] in {"High", "Critical"}]
    assert len(logs.json()) >= 2, "expected logs after ingest"
    assert len(high_alerts) >= 2, "expected high alerts after ingest"
    assert any("fake-bank-login-security.ru" in mail["body_summary"] for mail in emails.json()), "expected ingested email"
    assert any("fake-bank-login-security.ru" in mail["body_summary"] for mail in mailbox_emails.json()), "expected IMAP mailbox email feed"
    assert any("T1110" in item["text"] for item in knowledge.json()), "expected MITRE T1110 knowledge"
    alert_id = high_alerts[0]["id"]
    triage = requests.get(f"{API_BASE}/alerts/{alert_id}/triage", headers=auth, timeout=10)
    triage.raise_for_status()
    assert triage.json()["priority"] in {"P1", "P2", "P3"}, "expected triage priority"
    feedback = requests.post(
        f"{API_BASE}/feedback",
        headers=auth,
        json={"alert_id": alert_id, "verdict": "true_positive", "notes": "smoke validation"},
        timeout=10,
    )
    feedback.raise_for_status()
    rule = requests.post(f"{API_BASE}/rules/suggest/{alert_id}", headers=auth, timeout=10)
    rule.raise_for_status()
    print(
        json.dumps(
            {
                "health": health.status_code,
                "logs": len(logs.json()),
                "alerts": len(alerts.json()),
                "high_alerts": len(high_alerts),
                "emails": len(emails.json()),
                "mailbox_emails": len(mailbox_emails.json()),
                "metrics_alerts": metrics.json()["total_alerts"],
                "knowledge_hits": len(knowledge.json()),
                "triage_priority": triage.json()["priority"],
                "feedback": feedback.json()["verdict"],
                "rule_status": rule.json()["status"],
            }
        )
    )


if __name__ == "__main__":
    main()
