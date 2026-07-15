"""
Security alert dashboard metrics.

This module handles security alerts
from the dashboard sample data.
"""

from datetime import datetime


def get_recent_alerts(data, limit=5):
    """
    Return the most recent security alerts.

    Handles:
    - Missing alerts key
    - Empty alert list
    - Invalid alert data types
    - Invalid dates

    Args:
        data (dict): Dashboard sample data
        limit (int): Maximum number of alerts to return

    Returns:
        list: Sorted list of recent alerts
    """

    if not isinstance(data, dict):
        return [
            {
                "message": "No security alerts available"
            }
        ]

    alerts = data.get("alerts", [])

    if not isinstance(alerts, list) or len(alerts) == 0:
        return [
            {
                "message": "No security alerts available"
            }
        ]

    def parse_date(alert):
        try:
            return datetime.fromisoformat(
                alert.get("created_at", "").replace("Z", "+00:00")
            )
        except (ValueError, TypeError, AttributeError):
            return datetime.min

    sorted_alerts = sorted(
        alerts,
        key=parse_date,
        reverse=True
    )

    return sorted_alerts[:limit]