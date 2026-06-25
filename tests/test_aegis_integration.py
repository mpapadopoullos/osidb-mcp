"""Integration tests for AEGIS tools against a live AEGIS instance.

These tests require:
  - AEGIS_URL env var pointing to a running AEGIS instance
  - A valid Kerberos TGT (run ``kinit`` before invoking)
  - Network access to the AEGIS host (VPN)

Run with:  make livetest-aegis
    or:    pytest -m live_aegis -vv -s
"""

from __future__ import annotations

import os
import subprocess
from unittest.mock import MagicMock, patch

import pytest

from osidb_mcp.tools_aegis import (
    aegis_get_component_analysis,
    aegis_get_cve_analysis,
    aegis_get_kpi_metrics,
    aegis_run_cve_analysis,
)

pytestmark = pytest.mark.live_aegis


def _has_kerberos_tgt() -> bool:
    """Return True if klist reports a valid Kerberos TGT."""
    try:
        result = subprocess.run(
            ["klist", "-s"], capture_output=True, timeout=5
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


_skip_reason = ""
if not os.environ.get("AEGIS_URL"):
    _skip_reason = "AEGIS_URL not set"
elif not _has_kerberos_tgt():
    _skip_reason = "No valid Kerberos TGT (run kinit)"

if _skip_reason:
    pytestmark = [pytestmark, pytest.mark.skip(reason=_skip_reason)]


@pytest.fixture(autouse=True)
def _aegis_settings():
    """Ensure OSIDB MCP settings are loaded with AEGIS_URL from env."""
    from osidb_mcp.config import load_settings
    from osidb_mcp.session_holder import configure

    settings = load_settings()
    configure(settings)
    yield


# ---------------------------------------------------------------------------
# KPI metrics
# ---------------------------------------------------------------------------


class TestKpiMetrics:
    def test_returns_data(self) -> None:
        result = aegis_get_kpi_metrics(feature_name="suggest-statement")

        assert result["ok"] is True, f"Expected ok=True, got: {result}"
        data = result["result"]
        assert "suggest-statement" in data
        entry = data["suggest-statement"]
        assert "acceptance_percentage" in entry
        assert "entries" in entry

    def test_all_features(self) -> None:
        result = aegis_get_kpi_metrics(feature_name="all")

        assert result["ok"] is True, f"Expected ok=True, got: {result}"

    def test_invalid_feature_returns_error(self) -> None:
        result = aegis_get_kpi_metrics(feature_name="nonexistent-feature-xyz")

        # AEGIS may return ok with empty data or an HTTP error for unknown features;
        # either way the call must not crash.
        assert isinstance(result, dict)
        assert "ok" in result


# ---------------------------------------------------------------------------
# CVE analysis (POST-based)
# ---------------------------------------------------------------------------


MINIMAL_CVE_BODY = {
    "cve_id": "CVE-2024-21626",
    "title": "runc container breakout via fd leak",
    "comment_zero": (
        "A flaw was found in runc where an attacker could use a "
        "malicious image to create a condition where a container "
        "process could gain access to the host filesystem."
    ),
    "cve_description": "",
    "statement": "",
    "components": ["runc"],
    "references": [],
    "embargoed": False,
    "impact": "IMPORTANT",
    "cvss_scores": [],
    "affects": [],
}


class TestCveAnalysis:
    def test_run_cve_analysis_returns_suggestion(self) -> None:
        result = aegis_run_cve_analysis(
            feature_name="suggest-statement", body=MINIMAL_CVE_BODY
        )

        assert result["ok"] is True, f"Expected ok=True, got: {result}"
        data = result["result"]
        assert "suggested_statement" in data
        assert len(data["suggested_statement"]) > 0

    def test_get_cve_analysis_known_cve(self) -> None:
        """End-to-end: fetch flaw from OSIDB then call AEGIS."""
        result = aegis_get_cve_analysis(
            feature_name="suggest-statement", cve_id="CVE-2024-21626"
        )

        assert result["ok"] is True, f"Expected ok=True, got: {result}"
        data = result["result"]
        assert "suggested_statement" in data


# ---------------------------------------------------------------------------
# Component analysis (GET-based)
# ---------------------------------------------------------------------------


class TestComponentAnalysis:
    def test_returns_data(self) -> None:
        result = aegis_get_component_analysis(
            feature_name="component-intelligence", component_name="openssl"
        )

        if result.get("status_code") == 401:
            pytest.skip(
                "AEGIS component endpoint returned 401 — "
                "Kerberos delegation to OSIDB likely unsupported"
            )
        assert result["ok"] is True, f"Expected ok=True, got: {result}"
        assert result["result"] is not None

    def test_invalid_feature_rejected(self) -> None:
        """AEGIS should reject feature names not in the component enum."""
        result = aegis_get_component_analysis(
            feature_name="suggest-statement", component_name="openssl"
        )

        assert result["ok"] is False
        assert result.get("status_code") in (400, 422)


# ---------------------------------------------------------------------------
# Kerberos auth configuration
# ---------------------------------------------------------------------------


class TestKerberosAuth:
    @patch("osidb_mcp.tools_aegis.requests.request")
    def test_kerberos_delegation_enabled(self, mock_request: MagicMock) -> None:
        """Verify that live-configured AEGIS requests use delegate=True."""
        from requests_gssapi import HTTPSPNEGOAuth

        resp = MagicMock()
        resp.json.return_value = {"ok": True}
        resp.raise_for_status.return_value = None
        mock_request.return_value = resp

        aegis_run_cve_analysis(
            feature_name="suggest-statement", body=MINIMAL_CVE_BODY
        )

        call_kwargs = mock_request.call_args[1]
        auth = call_kwargs["auth"]
        assert isinstance(auth, HTTPSPNEGOAuth)
        assert auth.delegate is True
