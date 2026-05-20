from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, AnalystFeedback, Severity, User


async def create_feedback(
    session: AsyncSession,
    user: User,
    alert_id,
    verdict: str,
    corrected_severity: Severity | None,
    corrected_mitre: list[str],
    notes: str,
) -> AnalystFeedback:
    alert = await session.get(Alert, alert_id)
    if not alert:
        raise ValueError("Alert not found")
    feedback = AnalystFeedback(
        alert_id=alert.id,
        user_id=user.id,
        verdict=verdict,
        corrected_severity=corrected_severity,
        corrected_mitre=corrected_mitre,
        notes=notes,
    )
    session.add(feedback)
    if corrected_severity and verdict == "severity_wrong":
        alert.severity = corrected_severity
    await session.commit()
    await session.refresh(feedback)
    return feedback


async def feedback_counts(session: AsyncSession) -> dict[str, int]:
    result = await session.execute(select(AnalystFeedback.verdict, func.count()).group_by(AnalystFeedback.verdict))
    counts = {row[0]: int(row[1]) for row in result.all()}
    return {
        "feedback_count": sum(counts.values()),
        "true_positive_feedback": counts.get("true_positive", 0),
        "false_positive_feedback": counts.get("false_positive", 0),
    }
