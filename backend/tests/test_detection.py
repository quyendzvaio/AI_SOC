import unittest

from app.models import Severity
from app.schemas import EventIn
from app.services.detection import analyze_event


class DetectionTest(unittest.TestCase):
    def assert_detection(
        self,
        content: str,
        source_type: str,
        expected_severity: Severity | None,
        expected_rule: str | None = None,
        metadata: dict | None = None,
    ) -> None:
        analysis = analyze_event(
            EventIn(
                source_type=source_type,
                source="qa",
                content=content,
                metadata=metadata or {},
            )
        )
        self.assertEqual(analysis.severity, expected_severity)
        if expected_rule:
            self.assertEqual(analysis.rule_name, expected_rule)

    def test_normal_internal_login_is_not_alerted(self) -> None:
        self.assert_detection(
            "User john logged in successfully from internal IP 192.168.1.5",
            "ubuntu_agent",
            None,
        )

    def test_brute_force_maps_to_high_and_mitre_t1110(self) -> None:
        analysis = analyze_event(
            EventIn(
                source_type="ubuntu_agent",
                source="auth.log",
                content="100 failed SSH login attempts from IP 45.21.90.2 within 3 minutes",
            )
        )
        self.assertEqual(analysis.severity, Severity.High)
        self.assertEqual(analysis.rule_name, "auth_brute_force_t1110")
        self.assertIn("T1110", analysis.entities["mitre_techniques"])
        self.assertIn("enable MFA", analysis.entities["recommendations"])

    def test_suspicious_country_admin_login_is_high(self) -> None:
        self.assert_detection(
            "Admin login from Russia at 03:12 AM after multiple failed attempts",
            "webhook",
            Severity.High,
            "suspicious_admin_geo_login_t1078",
            {"geo": "RU"},
        )

    def test_malware_download_is_high(self) -> None:
        self.assert_detection(
            "Downloaded suspicious.exe from unknown domain",
            "windows_agent",
            Severity.High,
            "malware_executable_delivery",
        )

    def test_sql_injection_is_high(self) -> None:
        self.assert_detection(
            "GET /login.php?id=' OR 1=1 --",
            "webhook",
            Severity.High,
            "web_sql_injection_t1190",
        )

    def test_phishing_email_is_high(self) -> None:
        self.assert_detection(
            "Subject: Reset your bank account password immediately\nClick here to verify your account: http://fake-bank-login-security.ru",
            "email",
            Severity.High,
            "email_phishing_link_t1566_002",
            {
                "sender": "security@fake-bank-login-security.ru",
                "subject": "Reset your bank account password immediately",
            },
        )

    def test_spam_email_is_medium(self) -> None:
        self.assert_detection(
            "Congratulations! You won an iPhone!",
            "email",
            Severity.Medium,
            "email_spam_scam",
        )

    def test_malware_attachment_is_high(self) -> None:
        self.assert_detection(
            "Attachment: invoice.exe",
            "email",
            Severity.High,
            "malware_executable_delivery",
            {"attachments": [{"filename": "invoice.exe"}]},
        )


if __name__ == "__main__":
    unittest.main()
