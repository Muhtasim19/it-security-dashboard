import unittest
from datetime import UTC, datetime

from dashboard.risk_score import calculate_risk_score


class RiskScoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.reference_time = datetime(
            2026,
            7,
            15,
            12,
            0,
            0,
            tzinfo=UTC,
        )

    def test_empty_data_returns_no_data(self) -> None:
        result = calculate_risk_score(
            {},
            reference_time=self.reference_time,
        )

        self.assertEqual(result["score"], 0)
        self.assertEqual(result["level"], "No data")
        self.assertEqual(result["css_class"], "no-data")
        self.assertEqual(result["open_vulnerabilities"], 0)

    def test_severity_points_are_calculated(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "status": "open",
                },
                {
                    "severity": "high",
                    "status": "open",
                },
                {
                    "severity": "medium",
                    "status": "open",
                },
                {
                    "severity": "low",
                    "status": "open",
                },
            ]
        }

        result = calculate_risk_score(
            data,
            reference_time=self.reference_time,
        )

        self.assertEqual(
            result["factors"]["severity_points"],
            49,
        )
        self.assertEqual(result["score"], 49)
        self.assertEqual(result["level"], "High")

    def test_closed_vulnerabilities_are_excluded(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "status": "fixed",
                },
                {
                    "severity": "medium",
                    "status": "open",
                },
            ]
        }

        result = calculate_risk_score(
            data,
            reference_time=self.reference_time,
        )

        self.assertEqual(result["open_vulnerabilities"], 1)
        self.assertEqual(result["score"], 7)
        self.assertEqual(result["level"], "Low")

    def test_additional_risk_factors_are_applied(self) -> None:
        data = {
            "assets": [
                {
                    "id": "asset-001",
                    "name": "public-server",
                    "criticality": "critical",
                    "internet_exposed": True,
                }
            ],
            "vulnerabilities": [
                {
                    "asset_id": "asset-001",
                    "severity": "high",
                    "status": "open",
                    "known_exploited": True,
                    "remediation_due": "2026-07-01T00:00:00Z",
                }
            ],
        }

        result = calculate_risk_score(
            data,
            reference_time=self.reference_time,
        )

        self.assertEqual(
            result["factors"]["severity_points"],
            15,
        )
        self.assertEqual(
            result["factors"]["known_exploited_bonus"],
            10,
        )
        self.assertEqual(
            result["factors"]["internet_exposure_bonus"],
            5,
        )
        self.assertEqual(
            result["factors"]["critical_asset_bonus"],
            5,
        )
        self.assertEqual(
            result["factors"]["overdue_remediation_bonus"],
            5,
        )

        self.assertEqual(result["score"], 40)
        self.assertEqual(result["level"], "High")

    def test_score_is_capped_at_one_hundred(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "severity": "critical",
                    "status": "open",
                    "known_exploited": True,
                    "internet_exposed": True,
                }
                for _ in range(10)
            ]
        }

        result = calculate_risk_score(
            data,
            reference_time=self.reference_time,
        )

        self.assertGreater(result["raw_score"], 100)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["level"], "Critical")


if __name__ == "__main__":
    unittest.main()