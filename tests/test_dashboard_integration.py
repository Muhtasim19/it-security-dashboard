import unittest
from unittest.mock import patch

from dashboard.dashboard import get_dashboard_context


class DashboardIntegrationTests(unittest.TestCase):
    def test_all_metrics_are_connected(self) -> None:
        sample_data = {
            "assets": [
                {
                    "id": "asset-001",
                    "name": "web-server",
                    "ip_address": "10.0.0.10",
                    "criticality": "critical",
                },
                {
                    "id": "asset-002",
                    "name": "employee-laptop",
                    "ip_address": "10.0.0.20",
                    "criticality": "medium",
                },
            ],
            "tickets": [
                {
                    "ticket_type": "Helpdesk",
                    "status": "Open",
                },
                {
                    "ticket_type": "Helpdesk",
                    "status": "Resolved",
                },
                {
                    "ticket_type": "Remediation",
                    "status": "In Progress",
                },
            ],
            "vulnerabilities": [
                {
                    "asset_id": "asset-001",
                    "severity": "critical",
                    "status": "open",
                },
                {
                    "asset_id": "asset-002",
                    "severity": "medium",
                    "status": "open",
                },
            ],
            "scans": [
                {
                    "target": "10.0.0.10",
                    "scan_date": "2026-07-15T10:00:00Z",
                    "status": "Completed",
                }
            ],
            "alerts": [
                {
                    "message": "Repeated SSH login failures",
                    "severity": "High",
                    "created_at": "2026-07-15T11:00:00Z",
                }
            ],
        }

        with patch(
            "dashboard.dashboard.load_dashboard_data",
            return_value=sample_data,
        ):
            context = get_dashboard_context()

        summary = context["summary"]

        self.assertEqual(summary["total_assets"], 2)
        self.assertEqual(summary["open_tickets"], 1)
        self.assertEqual(summary["open_remediations"], 1)
        self.assertEqual(summary["security_alerts"], 1)
        self.assertEqual(summary["total_vulnerabilities"], 2)

        self.assertEqual(
            context["latest_scans"][0]["target"],
            "10.0.0.10",
        )

        self.assertEqual(
            context["recent_alerts"][0]["severity"],
            "High",
        )


if __name__ == "__main__":
    unittest.main()