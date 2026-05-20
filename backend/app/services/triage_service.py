import uuid

from app.models import Alert, Severity

SEVERITY_WEIGHT = {
    Severity.Low: 0.25,
    Severity.Medium: 0.5,
    Severity.High: 0.78,
    Severity.Critical: 0.95,
}


def build_triage(alert: Alert, extracted_entities: dict) -> dict:
    labels = list(extracted_entities.get("threat_labels") or [])
    mitre = list(extracted_entities.get("mitre_techniques") or [])
    recommendations = list(extracted_entities.get("recommendations") or [])
    confidence = float(extracted_entities.get("confidence") or 0.5)
    ioc_count = len(extracted_entities.get("public_ips") or []) + len(extracted_entities.get("domains") or []) + len(extracted_entities.get("hashes") or [])
    score = min(1.0, SEVERITY_WEIGHT[alert.severity] + min(ioc_count, 5) * 0.025 + (0.06 if mitre else 0.0))
    priority = "P1" if score >= 0.9 else "P2" if score >= 0.75 else "P3" if score >= 0.5 else "P4"
    return {
        "alert_id": str(alert.id),
        "risk_score": round(score, 3),
        "confidence": round(confidence, 3),
        "priority": priority,
        "mitre_techniques": mitre,
        "threat_labels": labels,
        "recommendations": recommendations,
    }


def alert_triage_out(alert_id: uuid.UUID, triage: dict) -> dict:
    return {
        "alert_id": alert_id,
        "risk_score": float(triage.get("risk_score") or 0),
        "confidence": float(triage.get("confidence") or 0),
        "priority": str(triage.get("priority") or "P4"),
        "mitre_techniques": list(triage.get("mitre_techniques") or []),
        "threat_labels": list(triage.get("threat_labels") or []),
        "recommendations": list(triage.get("recommendations") or []),
    }
