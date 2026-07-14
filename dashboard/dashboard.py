from datetime import UTC, datetime
from typing import Any

from flask import Blueprint, render_template


dashboard_blueprint = Blueprint("dashboard", __name__)


def get_dashboard_placeholders() -> dict[str, Any]:
    """
    Return placeholder dashboard values.

    Feature branches will replace these placeholders with data from the
    helpdesk system, asset inventory, vulnerability scanner, and log analyzer.
    """
    return {
        "summary": {
            "total_assets": 0,
            "open_tickets": 0,
            "total_vulnerabilities": 0,
            "open_remediations": 0,
            "security_alerts": 0,
            "risk_score": 0,
        },
        "severity_metrics": [
            {"name": "Critical", "count": 0, "css_class": "critical"},
            {"name": "High", "count": 0, "css_class": "high"},
            {"name": "Medium", "count": 0, "css_class": "medium"},
            {"name": "Low", "count": 0, "css_class": "low"},
        ],
        "vulnerable_assets": [],
        "latest_scans": [],
        "recent_alerts": [],
        "last_updated": datetime.now(UTC).isoformat(),
    }


@dashboard_blueprint.get("/")
@dashboard_blueprint.get("/dashboard")
def dashboard() -> str:
    context = get_dashboard_placeholders()
    return render_template("dashboard.html", **context)


@dashboard_blueprint.get("/health")
def health() -> dict[str, str]:
    return {"status": "healthy", "service": "it-security-dashboard"}
