from app.models import Severity
from app.schemas import EventIn
from app.services.detection import analyze_event


CASES = [
    ("User john logged in successfully from internal IP 192.168.1.5", "ubuntu_agent", None),
    ("100 failed SSH login attempts from IP 45.21.90.2 within 3 minutes", "ubuntu_agent", Severity.High),
    ("Admin login from Russia at 03:12 AM after multiple failed attempts", "webhook", Severity.High),
    ("Downloaded suspicious.exe from unknown domain", "windows_agent", Severity.High),
    ("GET /login.php?id=' OR 1=1 --", "webhook", Severity.High),
    (
        "Subject: Reset your bank account password immediately Click here to verify your account: http://fake-bank-login-security.ru",
        "email",
        Severity.High,
    ),
    ("Congratulations! You won an iPhone!", "email", Severity.Medium),
    ("Attachment: invoice.exe", "email", Severity.High),
]


for content, source_type, expected in CASES:
    analysis = analyze_event(EventIn(source_type=source_type, source="qa", content=content))
    assert analysis.severity == expected, {
        "content": content,
        "expected": expected.value if expected else None,
        "actual": analysis.severity.value if analysis.severity else None,
        "rule": analysis.rule_name,
    }

print("container detection smoke passed")
