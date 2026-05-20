import re

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, GeneratedRule, LogEvent


def _sigma_selection(log: LogEvent, alert: Alert) -> dict:
    entities = log.extracted_entities or {}
    labels = entities.get("threat_labels") or []
    mitre = entities.get("mitre_techniques") or []
    domains = entities.get("domains") or []
    ips = entities.get("public_ips") or []
    keywords = []
    if alert.rule_name:
        keywords.append(alert.rule_name)
    keywords.extend(labels[:3])
    if domains:
        keywords.append(domains[0])
    if ips:
        keywords.append(ips[0])
    if not keywords:
        keywords = re.findall(r"[A-Za-z0-9_.-]{4,}", log.log_summary)[:4]
    return {
        "selection": {
            "keywords": keywords,
            "source": log.source,
            "source_type": log.source_type.value,
        },
        "condition": "selection",
        "fields": ["source", "source_type", "log_summary", "extracted_entities"],
        "tags": [f"attack.{item.lower()}" for item in mitre],
    }


async def suggest_rule_for_alert(session: AsyncSession, alert_id) -> GeneratedRule:
    alert = await session.get(Alert, alert_id)
    if not alert:
        raise ValueError("Alert not found")
    log = await session.get(LogEvent, alert.log_id)
    if not log:
        raise ValueError("Log not found")
    name = f"ai_soc_{alert.rule_name or alert.severity.value.lower()}_{str(alert.id)[:8]}"
    rule_body = {
        "title": name,
        "id": str(alert.id),
        "status": "experimental",
        "description": f"Generated from alert {alert.id}: {alert.message}",
        "logsource": {"product": "ai_soc", "service": log.source_type.value},
        "detection": _sigma_selection(log, alert),
        "level": alert.severity.value.lower(),
    }
    backtest = await backtest_rule(session, rule_body)
    generated = GeneratedRule(source_alert_id=alert.id, name=name, rule_type="sigma", rule_body=rule_body, backtest_summary=backtest)
    session.add(generated)
    await session.commit()
    await session.refresh(generated)
    return generated


async def backtest_rule(session: AsyncSession, rule_body: dict) -> dict:
    keywords = [str(item).lower() for item in rule_body.get("detection", {}).get("selection", {}).get("keywords", [])]
    total = await session.scalar(select(func.count()).select_from(LogEvent)) or 0
    if not keywords:
        return {"tested_logs": int(total), "matches": 0, "estimated_precision": 0.0}
    rows = await session.execute(select(LogEvent).order_by(LogEvent.received_at.desc()).limit(500))
    matches = 0
    for log in rows.scalars():
        text = f"{log.source} {log.source_type.value} {log.log_summary} {log.extracted_entities}".lower()
        if any(keyword in text for keyword in keywords):
            matches += 1
    estimated_precision = 0.8 if matches <= 10 else 0.55
    return {"tested_logs": min(int(total), 500), "matches": matches, "estimated_precision": estimated_precision}
