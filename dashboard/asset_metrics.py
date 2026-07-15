"""
Asset-related dashboard metrics.

This module calculates asset statistics
from the dashboard sample data.
"""


def get_total_assets(data):
    """
    Return the total number of assets.

    Handles:
    - Missing assets key
    - Empty asset list
    - Invalid asset data types

    Args:
        data (dict): Dashboard sample data

    Returns:
        int: Number of assets
    """

    if not isinstance(data, dict):
        return 0

    assets = data.get("assets", [])

    if not isinstance(assets, list):
        return 0

    return len(assets)