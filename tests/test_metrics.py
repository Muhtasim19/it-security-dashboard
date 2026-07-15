import unittest

from dashboard.vulnerability_metrics import (
    calculate_severity_metrics,
    calculate_total_vulnerabilities,
    extract_vulnerabilities,
    get_most_vulnerable_assets,
    normalize_severity,
)


class VulnerabilityMetricsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.sample_data = {
            "assets": [
                {
                    "id": "asset-001",
                    "name": "web-server-01",
                    "ip_address": "10.0.0.10",
                },
                {
                    "id": "asset-002",
                    "name": "employee-laptop-01",
                    "ip_address": "10.0.0.25",
                },
            ],
            "vulnerabilities": [
                {
                    "id": "VULN-001",
                    "asset_id": "asset-001",
                    "severity": "critical",
                    "status": "open",
                },
                {
                    "id": "VULN-002",
                    "asset_id": "asset-001",
                    "severity": "high",
                    "status": "open",
                },
                {
                    "id": "VULN-003",
                    "asset_id": "asset-001",
                    "severity": "medium",
                    "status": "fixed",
                },
                {
                    "id": "VULN-004",
                    "asset_id": "asset-002",
                    "severity": "medium",
                    "status": "open",
                },
                {
                    "id": "VULN-005",
                    "asset_id": "asset-002",
                    "severity": "low",
                    "status": "open",
                },
            ],
        }

    def test_normalize_severity_aliases(self) -> None:
        self.assertEqual(normalize_severity("Crit"), "critical")
        self.assertEqual(normalize_severity("Moderate"), "medium")
        self.assertEqual(normalize_severity("Info"), "low")
        self.assertEqual(normalize_severity("Unexpected"), "unknown")

    def test_closed_vulnerabilities_are_excluded(self) -> None:
        vulnerabilities = extract_vulnerabilities(self.sample_data)

        self.assertEqual(len(vulnerabilities), 4)

        vulnerability_ids = {
            vulnerability["id"]
            for vulnerability in vulnerabilities
        }

        self.assertNotIn("VULN-003", vulnerability_ids)

    def test_total_open_vulnerability_count(self) -> None:
        result = calculate_total_vulnerabilities(self.sample_data)
        self.assertEqual(result, 4)

    def test_vulnerabilities_are_grouped_by_severity(self) -> None:
        metrics = calculate_severity_metrics(self.sample_data)

        counts = {
            metric["css_class"]: metric["count"]
            for metric in metrics
        }

        self.assertEqual(counts["critical"], 1)
        self.assertEqual(counts["high"], 1)
        self.assertEqual(counts["medium"], 1)
        self.assertEqual(counts["low"], 1)

    def test_assets_are_ranked_by_weighted_severity(self) -> None:
        assets = get_most_vulnerable_assets(self.sample_data)

        self.assertEqual(len(assets), 2)
        self.assertEqual(assets[0]["name"], "web-server-01")
        self.assertEqual(assets[0]["critical"], 1)
        self.assertEqual(assets[0]["high"], 1)
        self.assertEqual(assets[0]["total_findings"], 2)

        self.assertEqual(
            assets[1]["name"],
            "employee-laptop-01",
        )

    def test_nested_asset_vulnerabilities_are_supported(self) -> None:
        nested_data = {
            "assets": [
                {
                    "id": "asset-003",
                    "name": "database-server",
                    "ip_address": "10.0.0.30",
                    "vulnerabilities": [
                        {
                            "id": "VULN-006",
                            "severity": "high",
                            "status": "open",
                        }
                    ],
                }
            ]
        }

        assets = get_most_vulnerable_assets(nested_data)

        self.assertEqual(len(assets), 1)
        self.assertEqual(assets[0]["name"], "database-server")
        self.assertEqual(assets[0]["ip_address"], "10.0.0.30")
        self.assertEqual(assets[0]["high"], 1)


if __name__ == "__main__":
    unittest.main()