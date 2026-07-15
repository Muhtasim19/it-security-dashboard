"""
Ticket and scan related dashboard metrics.

This module calculates:
- Open helpdesk tickets
- Open remediation tickets
- Latest vulnerability scans

from dashboard sample data.
"""


from datetime import datetime


def get_open_helpdesk_tickets(data):
    """
    Return the number of open helpdesk tickets.

    Counts only tickets where:
    - ticket_type is Helpdesk
    - status is not Resolved or Closed
    """

    if not isinstance(data, dict):
        return 0

    tickets = data.get("tickets", [])

    if not isinstance(tickets, list):
        return 0

    closed_statuses = {"Resolved", "Closed"}

    count = 0

    for ticket in tickets:
        if not isinstance(ticket, dict):
            continue

        if ticket.get("ticket_type") != "Helpdesk":
            continue

        if ticket.get("status") not in closed_statuses:
            count += 1

    return count


def get_open_remediation_tickets(data):
    """
    Return the number of open remediation tickets.

    Counts only tickets where:
    - ticket_type is Remediation
    - status is not Resolved or Closed
    """

    if not isinstance(data, dict):
        return 0

    tickets = data.get("tickets", [])

    if not isinstance(tickets, list):
        return 0

    closed_statuses = {"Resolved", "Closed"}

    count = 0

    for ticket in tickets:
        if not isinstance(ticket, dict):
            continue

        if ticket.get("ticket_type") != "Remediation":
            continue

        if ticket.get("status") not in closed_statuses:
            count += 1

    return count


def get_latest_scans(data, limit=5):
    """
    Return latest scans sorted by scan date.

    Handles:
    - Missing scans
    - Empty scans
    - Invalid dates
    - Missing scan_date values

    Returns newest scans first.
    """

    if not isinstance(data, dict):
        return []

    scans = data.get("scans", [])

    if not isinstance(scans, list):
        return []

    valid_scans = []

    for scan in scans:
        if not isinstance(scan, dict):
            continue

        scan_date = scan.get("scan_date")

        if not isinstance(scan_date, str):
            continue

        try:
            datetime.fromisoformat(scan_date.replace("Z", "+00:00"))
            valid_scans.append(scan)
        except ValueError:
            continue

    valid_scans.sort(
        key=lambda scan: scan["scan_date"],
        reverse=True
    )

    return valid_scans[:limit]