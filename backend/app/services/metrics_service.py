from collections import Counter

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, AnalystFeedback, GeneratedRule, Incident, LogEvent, Severity, WorkStatus
from app.services.feedback_service import feedback_counts


async def soc_metrics(session: AsyncSession) -> dict:
    total_logs = int(await session.scalar(select(func.count()).select_from(LogEvent)) or 0)
    total_alerts = int(await session.scalar(select(func.count()).select_from(Alert)) or 0)
    open_alerts = int(await session.scalar(select(func.count()).select_from(Alert).where(Alert.status == WorkStatus.open)) or 0)
    critical_alerts = int(await session.scalar(select(func.count()).select_from(Alert).where(Alert.severity == Severity.Critical)) or 0)
    high_alerts = int(await session.scalar(select(func.count()).select_from(Alert).where(Alert.severity == Severity.High)) or 0)
    total_incidents = int(await session.scalar(select(func.count()).select_from(Incident)) or 0)
    generated_rules = int(await session.scalar(select(func.count()).select_from(GeneratedRule)) or 0)
    feedback = await feedback_counts(session)

    rows = await session.execute(select(LogEvent.extracted_entities).order_by(LogEvent.received_at.desc()).limit(500))
    counter: Counter[str] = Counter()
    for entities in rows.scalars():
        for technique in (entities or {}).get("mitre_techniques") or []:
            counter[str(technique)] += 1

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "open_alerts": open_alerts,
        "critical_alerts": critical_alerts,
        "high_alerts": high_alerts,
        "total_incidents": total_incidents,
        "generated_rules": generated_rules,
        "top_mitre": [{"technique": key, "count": value} for key, value in counter.most_common(8)],
        **feedback,
    }
