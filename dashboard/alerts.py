"""Security alert dashboard metrics."""

from datetime import UTC, datetime
from typing import Any


def parse_alert_date(alert: dict[str, Any]) -> datetime:
    """Return a timezone-aware alert timestamp for sorting."""
    value = (
        alert.get("created_at")
        or alert.get("timestamp")
        or alert.get("detected_at")
    )

    if not isinstance(value, str):
        return datetime.min.replace(tzinfo=UTC)

    try:
        parsed = datetime.fromisoformat(
            value.replace("Z", "+00:00")
        )
    except ValueError:
        return datetime.min.replace(tzinfo=UTC)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def get_recent_alerts(
    data: dict[str, Any],
    limit: int = 5,
) -> list[dict[str, Any]]:
    """Return the most recent valid security alerts."""
    if not isinstance(data, dict):
        return []

    alerts = data.get("alerts", [])

    if not isinstance(alerts, list):
        return []

    valid_alerts = [
        alert
        for alert in alerts
        if isinstance(alert, dict)
    ]

    valid_alerts.sort(
        key=parse_alert_date,
        reverse=True,
    )

    return valid_alerts[: max(limit, 0)]