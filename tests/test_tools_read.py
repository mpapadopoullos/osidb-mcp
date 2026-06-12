"""Unit tests for read tools (no live OSIDB)."""

from unittest.mock import MagicMock, patch

import requests

from osidb_mcp.tools_read import (
    affect_cvss_score_get,
    alert_get,
    alerts_list,
    exploits_cve_map,
    exploits_epss,
    exploits_flaw_data,
    exploits_report_date,
    exploits_report_explanations,
    flaw_acknowledgment_get,
    flaw_comment_get,
    flaw_cvss_score_get,
    flaw_label_get,
    flaw_package_version_get,
    flaw_reference_get,
    tracker_suggestions,
    workflow_get,
    workflows_list,
)


def _mock_cvss_score(uuid: str = "cvss-uuid-1"):
    score = MagicMock()
    score.uuid = uuid
    score.cvss_version = "V3"
    score.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
    score.to_dict.return_value = {
        "uuid": uuid,
        "cvss_version": "V3",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H",
    }
    return score


def _mock_subresource(uuid: str = "sub-uuid-1", **extra):
    obj = MagicMock()
    obj.uuid = uuid
    data = {"uuid": uuid, **extra}
    obj.to_dict.return_value = data
    return obj


def _mock_api_response(parsed_dict=None, status_code=200):
    r = MagicMock()
    r.status_code = status_code
    if parsed_dict is not None:
        parsed = MagicMock()
        parsed.to_dict.return_value = parsed_dict
        r.parsed = parsed
    else:
        r.parsed = None
    return r


# ---------------------------------------------------------------------------
# affect_cvss_score_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read.get_session")
def test_affect_cvss_score_get_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.cvss_scores.retrieve.return_value = _mock_cvss_score()

    result = affect_cvss_score_get(
        affect_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_score_id="cvss-uuid-1",
    )

    assert result["ok"] is True
    assert result["cvss_score"]["uuid"] == "cvss-uuid-1"
    assert result["cvss_score"]["cvss_version"] == "V3"
    session.affects.cvss_scores.retrieve.assert_called_once()


@patch("osidb_mcp.tools_read.get_session")
def test_affect_cvss_score_get_with_field_projection(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.cvss_scores.retrieve.return_value = _mock_cvss_score()

    result = affect_cvss_score_get(
        affect_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_score_id="cvss-uuid-1",
        include_fields=["vector", "score"],
    )

    assert result["ok"] is True
    _, kwargs = session.affects.cvss_scores.retrieve.call_args
    assert kwargs["include_fields"] == ["vector", "score"]


@patch("osidb_mcp.tools_read.get_session")
def test_affect_cvss_score_get_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.affects.cvss_scores.retrieve.side_effect = requests.HTTPError(response=resp)

    result = affect_cvss_score_get(
        affect_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_score_id="bad-uuid",
    )

    assert result["ok"] is False
    assert result["status_code"] == 404


def test_affect_cvss_score_get_invalid_uuid() -> None:
    result = affect_cvss_score_get(
        affect_id="not-a-uuid",
        cvss_score_id="cvss-uuid-1",
    )

    assert result["ok"] is False
    assert result["error"] == "bad_request"
    assert "UUID" in result["detail"]


# ---------------------------------------------------------------------------
# flaw_comment_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read.get_session")
def test_flaw_comment_get_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.comments.retrieve.return_value = _mock_subresource("comment-1", text="Hello")

    result = flaw_comment_get("CVE-2026-1234", "comment-1")

    assert result["ok"] is True
    assert result["comment"]["uuid"] == "comment-1"


@patch("osidb_mcp.tools_read.get_session")
def test_flaw_comment_get_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.comments.retrieve.side_effect = requests.HTTPError(response=resp)

    result = flaw_comment_get("CVE-2026-1234", "bad-id")
    assert result["ok"] is False
    assert result["status_code"] == 404


# ---------------------------------------------------------------------------
# flaw_label_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read.get_session")
def test_flaw_label_get_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.labels.retrieve.return_value = _mock_subresource("label-1", label="triage")

    result = flaw_label_get("CVE-2026-1234", "label-1")

    assert result["ok"] is True
    assert result["label"]["uuid"] == "label-1"


# ---------------------------------------------------------------------------
# flaw_acknowledgment_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read.get_session")
def test_flaw_acknowledgment_get_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.acknowledgments.retrieve.return_value = _mock_subresource("ack-1", name="Jane")

    result = flaw_acknowledgment_get("CVE-2026-1234", "ack-1")

    assert result["ok"] is True
    assert result["acknowledgment"]["uuid"] == "ack-1"


# ---------------------------------------------------------------------------
# flaw_reference_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read.get_session")
def test_flaw_reference_get_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.references.retrieve.return_value = _mock_subresource("ref-1", url="https://example.com")

    result = flaw_reference_get("CVE-2026-1234", "ref-1")

    assert result["ok"] is True
    assert result["reference"]["uuid"] == "ref-1"


# ---------------------------------------------------------------------------
# flaw_cvss_score_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read.get_session")
def test_flaw_cvss_score_get_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.cvss_scores.retrieve.return_value = _mock_cvss_score("flaw-cvss-1")

    result = flaw_cvss_score_get("CVE-2026-1234", "flaw-cvss-1")

    assert result["ok"] is True
    assert result["cvss_score"]["uuid"] == "flaw-cvss-1"


# ---------------------------------------------------------------------------
# flaw_package_version_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read.get_session")
def test_flaw_package_version_get_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.package_versions.retrieve.return_value = _mock_subresource("pv-1", package="curl")

    result = flaw_package_version_get("CVE-2026-1234", "pv-1")

    assert result["ok"] is True
    assert result["package_version"]["uuid"] == "pv-1"


# ---------------------------------------------------------------------------
# alerts_list / alert_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read._raw_api_call")
def test_alerts_list_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"results": []}}

    result = alerts_list()

    assert result["ok"] is True
    mock_raw.assert_called_once()


@patch("osidb_mcp.tools_read._raw_api_call")
def test_alert_get_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"uuid": "alert-1"}}

    result = alert_get("aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is True
    mock_raw.assert_called_once()


def test_alert_get_invalid_uuid() -> None:
    result = alert_get("not-a-uuid")

    assert result["ok"] is False
    assert result["error"] == "bad_request"


# ---------------------------------------------------------------------------
# exploits_epss tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read._raw_api_call")
def test_exploits_epss_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"results": [{"cve": "CVE-2026-1234", "epss": 0.5}]}}

    result = exploits_epss()

    assert result["ok"] is True
    mock_raw.assert_called_once()


# ---------------------------------------------------------------------------
# exploits_cve_map tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read._raw_api_call")
def test_exploits_cve_map_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"cves": ["CVE-2026-1234"]}}

    result = exploits_cve_map()

    assert result["ok"] is True
    mock_raw.assert_called_once()


# ---------------------------------------------------------------------------
# exploits_report_date tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read._raw_api_call")
def test_exploits_report_date_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"date": "2026-06-01"}}

    result = exploits_report_date("2026-06-01")

    assert result["ok"] is True


def test_exploits_report_date_invalid() -> None:
    result = exploits_report_date("not-a-date")

    assert result["ok"] is False
    assert result["error"] == "bad_request"


# ---------------------------------------------------------------------------
# exploits_report_explanations tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read._raw_api_call")
def test_exploits_report_explanations_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"explanations": []}}

    result = exploits_report_explanations()

    assert result["ok"] is True


# ---------------------------------------------------------------------------
# exploits_flaw_data tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read._raw_api_call")
def test_exploits_flaw_data_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"results": []}}

    result = exploits_flaw_data()

    assert result["ok"] is True


# ---------------------------------------------------------------------------
# workflows_list / workflow_get tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_read._raw_api_call")
def test_workflows_list_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"workflows": []}}

    result = workflows_list()

    assert result["ok"] is True


@patch("osidb_mcp.tools_read._raw_api_call")
def test_workflow_get_success(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"id": "DEFAULT", "states": []}}

    result = workflow_get("DEFAULT")

    assert result["ok"] is True


@patch("osidb_mcp.tools_read._raw_api_call")
def test_workflow_get_verbose(mock_raw: MagicMock) -> None:
    mock_raw.return_value = {"ok": True, "data": {"id": "DEFAULT", "states": []}}

    result = workflow_get("DEFAULT", verbose=True)

    assert result["ok"] is True
    _, kwargs = mock_raw.call_args
    assert kwargs["verbose"] is True


# ---------------------------------------------------------------------------
# tracker_suggestions tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_read.get_session")
def test_tracker_suggestions_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    suggestions = MagicMock()
    suggestions.to_dict.return_value = {
        "streams_components": [
            {
                "ps_update_stream": "rhel-9.4.0.z",
                "ps_component": "kernel",
                "selected": True,
                "offer": {"acked": True, "selected": True, "eus": False, "aus": False},
                "affect": {"uuid": "aff-1", "embargoed": False},
            },
            {
                "ps_update_stream": "fedora-rawhide",
                "ps_component": "kernel",
                "selected": False,
                "offer": {"acked": False, "selected": False, "eus": False, "aus": False},
                "affect": {"uuid": "aff-2", "embargoed": False},
            },
        ],
        "not_applicable": [
            {"uuid": "aff-3", "ps_module": "community-kernel"},
        ],
    }
    session.trackers.file.return_value = suggestions

    result = tracker_suggestions(flaw_id="CVE-2024-1234")

    assert result["ok"] is True
    assert result["summary"]["total_fileable"] == 2
    assert result["summary"]["recommended"] == 1
    assert result["summary"]["not_recommended"] == 1
    assert result["summary"]["not_applicable"] == 1
    session.trackers.file.assert_called_once_with(
        {"flaw_uuids": ["CVE-2024-1234"]},
        exclude_existing_trackers=True,
    )


@patch("osidb_mcp.tools_read.get_session")
def test_tracker_suggestions_exclude_existing_false(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    suggestions = MagicMock()
    suggestions.to_dict.return_value = {
        "streams_components": [],
        "not_applicable": [],
    }
    session.trackers.file.return_value = suggestions

    result = tracker_suggestions(flaw_id="CVE-2024-1234", exclude_existing_trackers=False)

    assert result["ok"] is True
    session.trackers.file.assert_called_once_with(
        {"flaw_uuids": ["CVE-2024-1234"]},
        exclude_existing_trackers=False,
    )


@patch("osidb_mcp.tools_read.get_session")
def test_tracker_suggestions_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = '{"detail": "Flaw not found"}'
    session.trackers.file.side_effect = requests.HTTPError(response=resp)

    result = tracker_suggestions(flaw_id="nonexistent-uuid")

    assert result["ok"] is False
    assert result["status_code"] == 404
