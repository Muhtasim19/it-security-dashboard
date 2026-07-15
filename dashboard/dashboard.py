import json
from datetime import UTC, datetime
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, render_template

from dashboard.alerts import get_recent_alerts
from dashboard.asset_metrics import get_total_assets
from dashboard.risk_score import calculate_risk_score
from dashboard.ticket_metrics import (
    get_latest_scans,
    get_open_helpdesk_tickets,
    get_open_remediation_tickets,
)
from dashboard.vulnerability_metrics import build_vulnerability_context


dashboard_blueprint = Blueprint("dashboard", __name__)

DATA_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "sample_data.json"
)


def load_dashboard_data() -> dict[str, Any]:
    """Load and validate dashboard data from the shared JSON file."""
    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (FileNotFoundError, JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    return data


def count_security_alerts(data: dict[str, Any]) -> int:
    """Return the total number of valid security alerts."""
    alerts = data.get("alerts", [])

    if not isinstance(alerts, list):
        return 0

    return sum(
        1
        for alert in alerts
        if isinstance(alert, dict)
    )


def format_latest_scans(
    scans: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Normalize scan fields for the dashboard template."""
    formatted_scans = []

    for scan in scans:
        if not isinstance(scan, dict):
            continue

        formatted_scans.append(
            {
                "target": str(
                    scan.get("target")
                    or scan.get("asset_name")
                    or scan.get("hostname")
                    or scan.get("ip_address")
                    or "Unknown target"
                ),
                "scan_time": str(
                    scan.get("scan_time")
                    or scan.get("scan_date")
                    or scan.get("created_at")
                    or "Unknown time"
                ),
                "status": str(
                    scan.get("status")
                    or "Completed"
                ),
            }
        )

    return formatted_scans


def format_recent_alerts(
    alerts: list[dict[str, Any]],
) -> list[dict[str, str]]:
    """Normalize alert fields for the dashboard template."""
    formatted_alerts = []

    for alert in alerts:
        if not isinstance(alert, dict):
            continue

        message = alert.get("message")

        if (
            message == "No security alerts available"
            and len(alert) == 1
        ):
            continue

        formatted_alerts.append(
            {
                "title": str(
                    alert.get("title")
                    or alert.get("message")
                    or alert.get("rule")
                    or "Security alert"
                ),
                "timestamp": str(
                    alert.get("timestamp")
                    or alert.get("created_at")
                    or alert.get("detected_at")
                    or "Unknown time"
                ),
                "severity": str(
                    alert.get("severity")
                    or "Info"
                ),
            }
        )

    return formatted_alerts


def get_dashboard_context() -> dict[str, Any]:
    """Build all values required by the dashboard template."""
    data = load_dashboard_data()

    vulnerability_context = build_vulnerability_context(data)
    risk_context = calculate_risk_score(data)

    latest_scans = format_latest_scans(
        get_latest_scans(data)
    )

    recent_alerts = format_recent_alerts(
        get_recent_alerts(data)
    )

    return {
        "summary": {
            "total_assets": get_total_assets(data),
            "open_tickets": get_open_helpdesk_tickets(data),
            "total_vulnerabilities": (
                vulnerability_context["total_vulnerabilities"]
            ),
            "open_remediations": (
                get_open_remediation_tickets(data)
            ),
            "security_alerts": count_security_alerts(data),
            "risk_score": risk_context["score"],
        },
        "severity_metrics": (
            vulnerability_context["severity_metrics"]
        ),
        "vulnerable_assets": (
            vulnerability_context["vulnerable_assets"]
        ),
        "risk": risk_context,
        "latest_scans": latest_scans,
        "recent_alerts": recent_alerts,
        "last_updated": datetime.now(UTC).isoformat(),
    }


@dashboard_blueprint.get("/")
@dashboard_blueprint.get("/dashboard")
def dashboard() -> str:
    return render_template(
        "dashboard.html",
        **get_dashboard_context(),
    )


@dashboard_blueprint.get("/api/vulnerabilities/metrics")
def vulnerability_metrics_api():
    """Return vulnerability metrics as JSON."""
    data = load_dashboard_data()
    return jsonify(build_vulnerability_context(data))


@dashboard_blueprint.get("/api/risk-score")
def risk_score_api():
    """Return the current security risk calculation."""
    data = load_dashboard_data()
    return jsonify(calculate_risk_score(data))


@dashboard_blueprint.get("/api/dashboard/summary")
def dashboard_summary_api():
    """Return the integrated dashboard summary."""
    context = get_dashboard_context()

    return jsonify(
        {
            "summary": context["summary"],
            "latest_scans": context["latest_scans"],
            "recent_alerts": context["recent_alerts"],
            "last_updated": context["last_updated"],
        }
    )


@dashboard_blueprint.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "it-security-dashboard",
    }