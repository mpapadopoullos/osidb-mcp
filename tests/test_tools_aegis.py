"""Unit tests for AEGIS integration tools (no live AEGIS instance)."""

from unittest.mock import MagicMock, patch

import requests
from requests_gssapi import HTTPSPNEGOAuth

from osidb_mcp.tools_aegis import (
    aegis_get_component_analysis,
    aegis_get_cve_analysis,
    aegis_get_kpi_metrics,
    aegis_run_cve_analysis,
)

AEGIS_URL = "https://aegis.example.com"

EXPECTED_HEADERS = {
    "Origin": "https://osim.prodsec.redhat.com",
    "Referer": "https://osim.prodsec.redhat.com/",
}

SAMPLE_FLAW = {
    "cve_id": "CVE-2024-1234",
    "title": "Buffer overflow in curl",
    "comment_zero": "A buffer overflow was found in curl.",
    "cve_description": "A flaw was found in curl.",
    "statement": "",
    "components": ["curl"],
    "comments": "",
    "references": [],
    "embargoed": False,
    "impact": "IMPORTANT",
    "cvss_scores": [],
    "affects": [],
}


def _mock_settings(aegis_url: str | None = AEGIS_URL, verify_ssl: bool = True):
    settings = MagicMock()
    settings.aegis_url = aegis_url
    settings.verify_ssl = verify_ssl
    return settings


def _assert_has_cors_headers(call_kwargs: dict) -> None:
    """Verify that the request includes required Origin and Referer headers."""
    headers = call_kwargs.get("headers", {})
    assert headers.get("Origin") == EXPECTED_HEADERS["Origin"]
    assert headers.get("Referer") == EXPECTED_HEADERS["Referer"]


# ---------------------------------------------------------------------------
# aegis_get_cve_analysis (convenience wrapper: fetches flaw, then POSTs)
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
@patch("osidb_mcp.tools_read.flaw_get")
def test_get_cve_analysis_success(
    mock_flaw_get: MagicMock, mock_settings: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_flaw_get.return_value = {"ok": True, "flaw": SAMPLE_FLAW}

    resp = MagicMock()
    resp.json.return_value = {"statement": "This CVE affects..."}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-2024-1234")

    assert result["ok"] is True
    assert result["result"]["statement"] == "This CVE affects..."
    mock_flaw_get.assert_called_once_with("CVE-2024-1234")
    mock_request.assert_called_once()
    call_args = mock_request.call_args
    assert call_args[0][0] == "POST"
    assert call_args[0][1] == f"{AEGIS_URL}/api/v1/analysis/cve/suggest-statement"
    assert call_args[1]["json"]["cve_id"] == "CVE-2024-1234"
    assert call_args[1]["json"]["components"] == ["curl"]
    _assert_has_cors_headers(call_args[1])


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
@patch("osidb_mcp.tools_read.flaw_get")
def test_get_cve_analysis_uses_spnego(
    mock_flaw_get: MagicMock, mock_settings: MagicMock, mock_request: MagicMock
) -> None:
    """Verify that AEGIS requests use HTTPSPNEGOAuth directly."""
    mock_settings.return_value = _mock_settings()
    mock_flaw_get.return_value = {"ok": True, "flaw": SAMPLE_FLAW}

    resp = MagicMock()
    resp.json.return_value = {}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-2024-1234")

    call_kwargs = mock_request.call_args[1]
    assert isinstance(call_kwargs["auth"], HTTPSPNEGOAuth)
    assert call_kwargs["verify"] is True
    assert call_kwargs["timeout"] == 300.0
    _assert_has_cors_headers(call_kwargs)


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
@patch("osidb_mcp.tools_read.flaw_get")
def test_get_cve_analysis_respects_verify_ssl(
    mock_flaw_get: MagicMock, mock_settings: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings(verify_ssl=False)
    mock_flaw_get.return_value = {"ok": True, "flaw": SAMPLE_FLAW}

    resp = MagicMock()
    resp.json.return_value = {}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    aegis_get_cve_analysis(feature_name="x", cve_id="CVE-2024-1")

    call_kwargs = mock_request.call_args[1]
    assert call_kwargs["verify"] is False


@patch("osidb_mcp.tools_read.flaw_get")
def test_get_cve_analysis_flaw_fetch_failure(mock_flaw_get: MagicMock) -> None:
    """When flaw_get fails, the error propagates without calling AEGIS."""
    mock_flaw_get.return_value = {"ok": False, "error": "osidb_http_error", "status_code": 404}

    result = aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-9999-0000")

    assert result["ok"] is False
    assert result["status_code"] == 404


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
@patch("osidb_mcp.tools_read.flaw_get")
def test_get_cve_analysis_http_error(
    mock_flaw_get: MagicMock, mock_settings: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()
    mock_flaw_get.return_value = {"ok": True, "flaw": SAMPLE_FLAW}

    resp = MagicMock()
    resp.status_code = 403
    resp.text = "Forbidden"
    mock_request.side_effect = requests.HTTPError(response=resp)

    result = aegis_get_cve_analysis(feature_name="suggest-statement", cve_id="CVE-2024-1234")

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 403


# ---------------------------------------------------------------------------
# aegis_run_cve_analysis
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_run_cve_analysis_success(mock_settings: MagicMock, mock_request: MagicMock) -> None:
    mock_settings.return_value = _mock_settings()

    resp = MagicMock()
    resp.json.return_value = {"suggestion": "A buffer overflow in..."}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    body = {"cve_id": "CVE-2024-1234", "title": "Buffer overflow", "components": ["curl"]}
    result = aegis_run_cve_analysis(feature_name="suggest-statement", body=body)

    assert result["ok"] is True
    assert result["result"]["suggestion"] == "A buffer overflow in..."
    call_args = mock_request.call_args
    assert call_args[0][0] == "POST"
    assert call_args[0][1] == f"{AEGIS_URL}/api/v1/analysis/cve/suggest-statement"
    assert call_args[1]["json"] == body
    _assert_has_cors_headers(call_args[1])


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_run_cve_analysis_server_error(mock_settings: MagicMock, mock_request: MagicMock) -> None:
    mock_settings.return_value = _mock_settings()

    resp = MagicMock()
    resp.status_code = 500
    resp.text = "Internal Server Error"
    mock_request.side_effect = requests.HTTPError(response=resp)

    result = aegis_run_cve_analysis(
        feature_name="suggest-statement", body={"cve_id": "CVE-2024-1234"}
    )

    assert result["ok"] is False
    assert result["status_code"] == 500


# ---------------------------------------------------------------------------
# aegis_get_component_analysis (GET-based, query params)
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_component_analysis_success(mock_settings: MagicMock, mock_request: MagicMock) -> None:
    mock_settings.return_value = _mock_settings()

    resp = MagicMock()
    resp.json.return_value = {"component": "curl", "risk": "high"}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_component_analysis(
        feature_name="component-intelligence", component_name="curl"
    )

    assert result["ok"] is True
    assert result["result"]["component"] == "curl"
    call_args = mock_request.call_args
    assert call_args[0][0] == "GET"
    assert call_args[0][1] == f"{AEGIS_URL}/api/v1/analysis/component"
    assert call_args[1]["params"] == {
        "feature": "component-intelligence",
        "component_name": "curl",
    }
    assert "json" not in call_args[1]
    _assert_has_cors_headers(call_args[1])


# ---------------------------------------------------------------------------
# aegis_get_kpi_metrics
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_kpi_metrics_success(mock_settings: MagicMock, mock_request: MagicMock) -> None:
    mock_settings.return_value = _mock_settings()

    resp = MagicMock()
    resp.json.return_value = {"accuracy": 0.92, "coverage": 0.85}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_kpi_metrics(feature_name="suggest-statement", order="asc")

    assert result["ok"] is True
    assert result["result"]["accuracy"] == 0.92
    call_args = mock_request.call_args
    assert call_args[0][1] == f"{AEGIS_URL}/api/v1/analysis/kpi/cve"
    assert call_args[1]["params"] == {"feature": "suggest-statement", "order": "asc"}
    _assert_has_cors_headers(call_args[1])


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_get_kpi_metrics_default_order(mock_settings: MagicMock, mock_request: MagicMock) -> None:
    mock_settings.return_value = _mock_settings()

    resp = MagicMock()
    resp.json.return_value = {"accuracy": 0.90}
    resp.raise_for_status.return_value = None
    mock_request.return_value = resp

    result = aegis_get_kpi_metrics(feature_name="suggest-impact")

    assert result["ok"] is True
    call_args = mock_request.call_args
    assert call_args[1]["params"] == {"feature": "suggest-impact", "order": "desc"}


# ---------------------------------------------------------------------------
# Edge cases: not configured
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.current_settings")
def test_not_configured_returns_error(mock_settings: MagicMock) -> None:
    mock_settings.return_value = _mock_settings(aegis_url=None)

    result = aegis_run_cve_analysis(
        feature_name="suggest-statement", body={"cve_id": "CVE-2024-1234"}
    )

    assert result["ok"] is False
    assert result["error"] == "aegis_not_configured"
    assert "not configured" in result["detail"]


# ---------------------------------------------------------------------------
# Edge cases: non-JSON response
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_non_json_response_returns_raw_text(
    mock_settings: MagicMock, mock_request: MagicMock
) -> None:
    mock_settings.return_value = _mock_settings()

    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.side_effect = ValueError("No JSON")
    resp.text = "<html>Service Unavailable</html>"
    mock_request.return_value = resp

    result = aegis_run_cve_analysis(
        feature_name="suggest-statement", body={"cve_id": "CVE-2024-1234"}
    )

    assert result["ok"] is True
    assert result["result"]["raw_text"] == "<html>Service Unavailable</html>"


# ---------------------------------------------------------------------------
# Edge cases: connection error
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_connection_error(mock_settings: MagicMock, mock_request: MagicMock) -> None:
    mock_settings.return_value = _mock_settings()

    mock_request.side_effect = requests.ConnectionError("Connection refused")

    result = aegis_run_cve_analysis(
        feature_name="suggest-statement", body={"cve_id": "CVE-2024-1234"}
    )

    assert result["ok"] is False
    assert "error" in result


# ---------------------------------------------------------------------------
# Edge cases: Kerberos auth failure (401)
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_aegis.requests.request")
@patch("osidb_mcp.tools_aegis.current_settings")
def test_kerberos_auth_failure(mock_settings: MagicMock, mock_request: MagicMock) -> None:
    """401 from AEGIS when Kerberos ticket is expired/missing."""
    mock_settings.return_value = _mock_settings()

    resp = MagicMock()
    resp.status_code = 401
    resp.text = "Negotiate authentication failed"
    mock_request.side_effect = requests.HTTPError(response=resp)

    result = aegis_run_cve_analysis(
        feature_name="suggest-statement", body={"cve_id": "CVE-2024-1234"}
    )

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 401
