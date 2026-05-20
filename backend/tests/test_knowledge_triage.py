import unittest
from uuid import uuid4

from app.models import Alert, Severity, WorkStatus
from app.services.knowledge_base import retrieve_knowledge
from app.services.triage_service import build_triage


class KnowledgeTriageTest(unittest.TestCase):
    def test_retrieve_mitre_bruteforce_context(self) -> None:
        docs = retrieve_knowledge("brute force ssh T1110 enable MFA", top_k=3)
        joined = " ".join(doc["text"] for doc in docs)
        self.assertTrue(any(doc["source"] == "mitre_attack" for doc in docs))
        self.assertIn("T1110", joined)
        self.assertIn("MFA", joined)

    def test_triage_uses_severity_mitre_and_iocs(self) -> None:
        alert = Alert(
            id=uuid4(),
            log_id=uuid4(),
            severity=Severity.High,
            status=WorkStatus.open,
            message="Brute force authentication activity detected",
            ai_summary="100 failed SSH login attempts",
            rule_name="auth_brute_force_t1110",
        )
        triage = build_triage(
            alert,
            {
                "public_ips": ["45.21.90.2"],
                "mitre_techniques": ["T1110"],
                "threat_labels": ["brute_force"],
                "recommendations": ["enable MFA"],
                "confidence": 0.92,
            },
        )
        self.assertEqual(triage["priority"], "P2")
        self.assertGreaterEqual(triage["risk_score"], 0.85)
        self.assertIn("T1110", triage["mitre_techniques"])


if __name__ == "__main__":
    unittest.main()
