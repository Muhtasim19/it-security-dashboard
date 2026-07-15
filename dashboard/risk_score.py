from datetime import UTC, datetime
from typing import Any

from dashboard.vulnerability_metrics import (
    extract_vulnerabilities,
    normalize_severity,
)


SEVERITY_POINTS = {
    "critical": 25,
    "high": 15,
    "medium": 7,
    "low": 2,
    "unknown": 0,
}

ASSET_CRITICALITY_BONUS = {
    "critical": 5,
    "high": 3,
    "medium": 1,
    "low": 0,
    "unknown": 0,
}

KNOWN_EXPLOITED_BONUS = 10
INTERNET_EXPOSURE_BONUS = 5
OVERDUE_REMEDIATION_BONUS = 5


def _normalize_text(value: Any) -> str:
    """Return a normalized lowercase string."""
    return str(value or "").strip().lower()


def _is_truthy(value: Any) -> bool:
    """Interpret common Boolean-like values."""
    if isinstance(value, bool):
        return value

    return _normalize_text(value) in {
        "true",
        "yes",
        "1",
        "enabled",
    }


def _build_asset_index(
    data: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Create an index for matching findings to assets."""
    index: dict[str, dict[str, Any]] = {}

    assets = data.get("assets", [])

    if not isinstance(assets, list):
        return index

    for asset in assets:
        if not isinstance(asset, dict):
            continue

        identifiers = {
            asset.get("id"),
            asset.get("asset_id"),
            asset.get("name"),
            asset.get("hostname"),
            asset.get("ip_address"),
        }

        for identifier in identifiers:
            if identifier is not None:
                index[str(identifier)] = asset

    return index


def _find_asset(
    vulnerability: dict[str, Any],
    asset_index: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    """Find the asset associated with a vulnerability."""
    identifiers = [
        vulnerability.get("asset_id"),
        vulnerability.get("asset_name"),
        vulnerability.get("hostname"),
        vulnerability.get("target"),
        vulnerability.get("ip_address"),
    ]

    for identifier in identifiers:
        if identifier is None:
            continue

        matching_asset = asset_index.get(str(identifier))

        if matching_asset:
            return matching_asset

    return {}


def _is_known_exploited(vulnerability: dict[str, Any]) -> bool:
    """Check whether a finding is marked as actively exploited."""
    boolean_fields = (
        "known_exploited",
        "actively_exploited",
        "cisa_kev",
        "kev",
    )

    if any(
        _is_truthy(vulnerability.get(field))
        for field in boolean_fields
    ):
        return True

    exploitation_status = _normalize_text(
        vulnerability.get("exploitation_status")
    )

    return exploitation_status in {
        "known exploited",
        "actively exploited",
        "exploited",
    }


def _is_internet_exposed(
    vulnerability: dict[str, Any],
    asset: dict[str, Any],
) -> bool:
    """Check whether a finding belongs to an internet-facing asset."""
    boolean_fields = (
        "internet_exposed",
        "public_facing",
        "externally_accessible",
    )

    for record in (vulnerability, asset):
        if any(
            _is_truthy(record.get(field))
            for field in boolean_fields
        ):
            return True

        exposure = _normalize_text(
            record.get("exposure")
            or record.get("network_zone")
        )

        if exposure in {
            "public",
            "external",
            "internet",
            "internet-facing",
            "dmz",
        }:
            return True

    return False


def _parse_datetime(value: Any) -> datetime | None:
    """Parse an ISO-8601 date safely."""
    if not value:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(value).replace("Z", "+00:00")
        )
    except ValueError:
        return None

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)

    return parsed.astimezone(UTC)


def _is_remediation_overdue(
    vulnerability: dict[str, Any],
    reference_time: datetime,
) -> bool:
    """Check whether an open finding has passed its remediation deadline."""
    deadline = (
        vulnerability.get("remediation_due")
        or vulnerability.get("remediation_due_date")
        or vulnerability.get("due_date")
    )

    parsed_deadline = _parse_datetime(deadline)

    if parsed_deadline is None:
        return False

    return parsed_deadline < reference_time


def _get_asset_criticality(
    vulnerability: dict[str, Any],
    asset: dict[str, Any],
) -> str:
    """Return the criticality assigned to the affected asset."""
    criticality = _normalize_text(
        asset.get("criticality")
        or asset.get("asset_criticality")
        or vulnerability.get("asset_criticality")
    )

    aliases = {
        "mission critical": "critical",
        "mission-critical": "critical",
        "important": "high",
        "normal": "medium",
    }

    criticality = aliases.get(criticality, criticality)

    if criticality not in ASSET_CRITICALITY_BONUS:
        return "unknown"

    return criticality


def _risk_level(
    score: int,
    vulnerability_count: int,
) -> tuple[str, str]:
    """Convert a numeric score into a display level and CSS class."""
    if vulnerability_count == 0:
        return "No data", "no-data"

    if score >= 70:
        return "Critical", "critical"

    if score >= 40:
        return "High", "high"

    if score >= 20:
        return "Moderate", "moderate"

    return "Low", "low"


def _risk_description(level: str) -> str:
    """Return a user-facing explanation for a risk level."""
    descriptions = {
        "Critical": (
            "Immediate remediation is recommended. The environment has "
            "significant exposure from severe or high-priority findings."
        ),
        "High": (
            "Prioritize critical and high-severity findings, especially on "
            "important or externally accessible assets."
        ),
        "Moderate": (
            "Security exposure is manageable, but outstanding findings "
            "should be scheduled for remediation."
        ),
        "Low": (
            "Current exposure is relatively low. Continue monitoring and "
            "remediating findings through the normal workflow."
        ),
        "No data": (
            "The score will be calculated after vulnerability scan data "
            "is imported."
        ),
    }

    return descriptions[level]


def calculate_risk_score(
    data: dict[str, Any],
    reference_time: datetime | None = None,
) -> dict[str, Any]:
    """
    Calculate an organization-wide risk score between 0 and 100.

    The score is based on open vulnerabilities and additional risk factors.
    """
    vulnerabilities = extract_vulnerabilities(data)
    asset_index = _build_asset_index(data)

    now = reference_time or datetime.now(UTC)

    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)

    now = now.astimezone(UTC)

    factors = {
        "severity_points": 0,
        "known_exploited_bonus": 0,
        "internet_exposure_bonus": 0,
        "critical_asset_bonus": 0,
        "overdue_remediation_bonus": 0,
    }

    for vulnerability in vulnerabilities:
        severity = normalize_severity(
            vulnerability.get("severity")
        )

        factors["severity_points"] += SEVERITY_POINTS[severity]

        asset = _find_asset(vulnerability, asset_index)

        if _is_known_exploited(vulnerability):
            factors[
                "known_exploited_bonus"
            ] += KNOWN_EXPLOITED_BONUS

        if _is_internet_exposed(vulnerability, asset):
            factors[
                "internet_exposure_bonus"
            ] += INTERNET_EXPOSURE_BONUS

        criticality = _get_asset_criticality(
            vulnerability,
            asset,
        )

        factors[
            "critical_asset_bonus"
        ] += ASSET_CRITICALITY_BONUS[criticality]

        if _is_remediation_overdue(vulnerability, now):
            factors[
                "overdue_remediation_bonus"
            ] += OVERDUE_REMEDIATION_BONUS

    raw_score = sum(factors.values())
    score = min(100, max(0, raw_score))

    level, css_class = _risk_level(
        score,
        len(vulnerabilities),
    )

    return {
        "score": score,
        "raw_score": raw_score,
        "level": level,
        "css_class": css_class,
        "description": _risk_description(level),
        "open_vulnerabilities": len(vulnerabilities),
        "factors": factors,
        "calculated_at": now.isoformat(),
    }