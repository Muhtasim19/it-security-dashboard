import json
from datetime import UTC, datetime
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from flask import Blueprint, jsonify, render_template

from dashboard.vulnerability_metrics import build_vulnerability_context


dashboard_blueprint = Blueprint("dashboard", __name__)

DATA_FILE = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "sample_data.json"
)


def load_dashboard_data() -> dict[str, Any]:
    """
    Load shared demonstration data.

    An empty or temporarily incomplete sample-data file returns an empty
    dictionary so feature branches can be developed independently.
    """
    try:
        with DATA_FILE.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except (FileNotFoundError, JSONDecodeError):
        return {}

    if not isinstance(data, dict):
        return {}

    return data


def get_dashboard_context() -> dict[str, Any]:
    """Build the complete context used by the dashboard template."""
    data = load_dashboard_data()
    vulnerability_context = build_vulnerability_context(data)

    return {
        "summary": {
            "total_assets": 0,
            "open_tickets": 0,
            "total_vulnerabilities": (
                vulnerability_context["total_vulnerabilities"]
            ),
            "open_remediations": 0,
            "security_alerts": 0,
            "risk_score": 0,
        },
        "severity_metrics": (
            vulnerability_context["severity_metrics"]
        ),
        "vulnerable_assets": (
            vulnerability_context["vulnerable_assets"]
        ),
        "latest_scans": [],
        "recent_alerts": [],
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


@dashboard_blueprint.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "it-security-dashboard",
    }