"""MCP tool implementations for AEGIS AI-assisted CVE analysis.

AEGIS is an internal AI/ML service that provides automated analysis
features for CVE triage (statement suggestions, component analysis, etc.).
Uses direct Kerberos/SPNEGO authentication (independent of OSIDB JWT flow).
"""

from __future__ import annotations

from typing import Any

import requests
from requests_gssapi import HTTPSPNEGOAuth

from osidb_mcp.errors import http_error_payload
from osidb_mcp.session_holder import current_settings


def _aegis_base_url() -> str | None:
    return current_settings().aegis_url


def _aegis_request(
    method: str,
    path: str,
    params: dict[str, str] | None = None,
    json_body: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Make a Kerberos-authenticated request to the AEGIS API."""
    base = _aegis_base_url()
    if not base:
        return {"ok": False, "error": "aegis_not_configured", "detail": "AEGIS_URL not configured"}

    settings = current_settings()

    kwargs: dict[str, Any] = {
        "auth": HTTPSPNEGOAuth(),
        "verify": settings.verify_ssl,
        "timeout": 300.0,
        "headers": {
            "Origin": "https://osim.prodsec.redhat.com",
            "Referer": "https://osim.prodsec.redhat.com/",
        },
    }
    if params:
        kwargs["params"] = params
    if json_body is not None:
        kwargs["json"] = json_body

    try:
        resp = requests.request(method, f"{base}{path}", **kwargs)
        resp.raise_for_status()
    except requests.RequestException as exc:
        return {"ok": False, **http_error_payload(exc)}

    try:
        data = resp.json()
    except ValueError:
        data = {"raw_text": resp.text[:4000]}

    return {"ok": True, "result": data}


def aegis_get_cve_analysis(feature_name: str, cve_id: str) -> dict[str, Any]:
    """Retrieve a cached/pre-computed AEGIS AI analysis for a CVE and feature.

    Convenience wrapper: fetches flaw data from OSIDB and submits it to the
    AEGIS ``POST /api/v1/analysis/cve/{feature_name}`` endpoint.

    Args:
        feature_name: The analysis feature to query. Valid features:
            suggest-statement, suggest-impact, suggest-cwe,
            suggest-description, suggest-affected-components,
            identify-pii, cvss-diff-explainer.
        cve_id: The CVE identifier (e.g. "CVE-2024-21626").

    Returns:
        JSON dict with ``ok`` and ``result`` containing the analysis output.
    """
    from osidb_mcp.tools_read import flaw_get

    flaw_resp = flaw_get(cve_id)
    if not flaw_resp.get("ok"):
        return flaw_resp

    flaw = flaw_resp["flaw"]
    body = {
        "cve_id": flaw.get("cve_id") or cve_id,
        "title": flaw.get("title", ""),
        "comment_zero": flaw.get("comment_zero", ""),
        "cve_description": flaw.get("cve_description", ""),
        "statement": flaw.get("statement", ""),
        "components": flaw.get("components", []),
        "comments": flaw.get("comments", ""),
        "references": flaw.get("references", []),
        "embargoed": flaw.get("embargoed", False),
        "impact": flaw.get("impact", ""),
        "cvss_scores": flaw.get("cvss_scores", []),
        "affects": flaw.get("affects", []),
    }
    return _aegis_request(
        "POST",
        f"/api/v1/analysis/cve/{feature_name}",
        json_body=body,
    )


def aegis_run_cve_analysis(feature_name: str, body: dict[str, Any]) -> dict[str, Any]:
    """Trigger a new AEGIS analysis for a CVE feature.

    Submits CVE metadata to AEGIS for AI-assisted analysis. The body should
    contain relevant flaw data for the analysis engine to process.

    Args:
        feature_name: The analysis feature to run. Valid features:
            suggest-statement, suggest-impact, suggest-cwe,
            suggest-description, suggest-affected-components,
            identify-pii, cvss-diff-explainer.
        body: JSON object with CVE metadata. Typical fields include:
            cve_id, title, comment_zero, cve_description, statement,
            components, comments, references, embargoed, impact,
            cvss_scores, affects.

    Returns:
        JSON dict with ``ok`` and ``result`` containing the analysis output.
    """
    return _aegis_request(
        "POST",
        f"/api/v1/analysis/cve/{feature_name}",
        json_body=body,
    )


def aegis_get_component_analysis(feature_name: str, component_name: str) -> dict[str, Any]:
    """Retrieve AEGIS component-level analysis for a given feature and component name.

    Queries AEGIS for analysis results scoped to a specific component.

    Args:
        feature_name: The analysis feature to query. Valid features:
            suggest-statement, suggest-impact, suggest-cwe,
            suggest-description, suggest-affected-components,
            identify-pii, cvss-diff-explainer.
        component_name: The component name to analyze.

    Returns:
        JSON dict with ``ok`` and ``result`` containing the analysis output.
    """
    return _aegis_request(
        "POST",
        f"/api/v1/analysis/component/{feature_name}",
        json_body={"component_name": component_name},
    )


def aegis_get_kpi_metrics(feature_name: str, order: str = "desc") -> dict[str, Any]:
    """Retrieve AEGIS KPI metrics for an analysis feature.

    Returns key performance indicators for a given analysis feature,
    useful for evaluating model quality and coverage.

    Args:
        feature_name: The analysis feature to get KPIs for. Valid features:
            suggest-statement, suggest-impact, suggest-cwe,
            suggest-description, suggest-affected-components,
            identify-pii, cvss-diff-explainer.
        order: Sort order for results - "asc" or "desc" (default: "desc").

    Returns:
        JSON dict with ``ok`` and ``result`` containing KPI data.
    """
    return _aegis_request(
        "GET",
        f"/api/v1/kpi/{feature_name}",
        params={"order": order},
    )
