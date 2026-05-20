from datetime import timedelta

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, Incident, IncidentAlert, LogEvent, Severity, WorkStatus


def _incident_key(entities: dict) -> str | None:
    labels = entities.get("threat_labels") or []
    mitre = entities.get("mitre_techniques") or []
    domains = entities.get("domains") or []
    ips = entities.get("public_ips") or entities.get("ips") or []
    if domains:
        return f"domain:{domains[0]}"
    if ips:
        return f"ip:{ips[0]}"
    if mitre:
        return f"mitre:{mitre[0]}"
    if labels:
        return f"label:{labels[0]}"
    return None


async def correlate_alert_to_incident(session: AsyncSession, alert: Alert, log: LogEvent) -> Incident | None:
    entities = log.extracted_entities or {}
    key = _incident_key(entities)
    if not key:
        return None

    since = alert.detected_at - timedelta(hours=6) if alert.detected_at else None
    query = select(Incident).where(Incident.status != WorkStatus.resolved).order_by(desc(Incident.created_at)).limit(30)
    incidents = list((await session.execute(query)).scalars())
    target: Incident | None = None
    for incident in incidents:
        if key in incident.description and (not since or incident.created_at >= since):
            target = incident
            break

    if not target:
        target = Incident(
            name=f"Correlated incident {key}",
            description=f"Auto-correlated by {key}. Related MITRE={entities.get('mitre_techniques') or []}; labels={entities.get('threat_labels') or []}",
            severity=alert.severity if alert.severity in {Severity.High, Severity.Critical} else Severity.Medium,
        )
        session.add(target)
        await session.flush()
    elif severity_rank(alert.severity) > severity_rank(target.severity):
        target.severity = alert.severity

    exists = await session.get(IncidentAlert, {"incident_id": target.id, "alert_id": alert.id})
    if not exists:
        session.add(IncidentAlert(incident_id=target.id, alert_id=alert.id))
    return target


def severity_rank(severity: Severity) -> int:
    return {Severity.Low: 1, Severity.Medium: 2, Severity.High: 3, Severity.Critical: 4}[severity]
