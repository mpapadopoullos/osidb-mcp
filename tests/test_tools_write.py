"""Unit tests for write tools (no live OSIDB)."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

if TYPE_CHECKING:
    from osidb_mcp.config import Settings

import requests

from osidb_mcp.tools_write import (
    affect_add,
    affect_cvss_score_add,
    affect_cvss_score_remove,
    affect_remove,
    affect_update,
    affect_update_bulk,
    affects_bulk_create,
    affects_bulk_delete,
    affects_bulk_update,
    flaw_acknowledgment_add,
    flaw_acknowledgment_remove,
    flaw_acknowledgment_update,
    flaw_comment_create,
    flaw_create,
    flaw_cvss_add,
    flaw_cvss_remove,
    flaw_cvss_update,
    flaw_incident_request,
    flaw_label_add,
    flaw_label_remove,
    flaw_package_version_add,
    flaw_package_version_remove,
    flaw_package_version_update,
    flaw_reference_add,
    flaw_reference_remove,
    flaw_reference_update,
    flaw_update,
    tracker_create,
    tracker_update,
    trackers_bulk_file,
)


def _mock_flaw(uuid: str = "aaa58a80-dd9c-43dd-ba19-61fa88a66714", cve_id: str = "CVE-2026-52719"):
    flaw = MagicMock()
    flaw.uuid = uuid
    flaw.cve_id = cve_id
    return flaw


def _mock_subresource(uuid: str):
    obj = MagicMock()
    obj.uuid = uuid
    obj.to_dict.return_value = {"uuid": uuid}
    return obj


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_create_minimal(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.create.return_value = _mock_flaw()

    result = flaw_create(
        title="Test flaw",
        comment_zero="Description",
        embargoed=True,
    )

    assert result["ok"] is True
    assert result["flaw_uuid"] == "aaa58a80-dd9c-43dd-ba19-61fa88a66714"
    assert result["cve_id"] == "CVE-2026-52719"
    assert "partial" not in result
    session.flaws.create.assert_called_once_with(
        {
            "title": "Test flaw",
            "comment_zero": "Description",
            "embargoed": True,
        }
    )


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_create_full(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.create.return_value = _mock_flaw()
    session.flaws.acknowledgments.create.return_value = _mock_subresource("ack-uuid-1")
    session.flaws.references.create.return_value = _mock_subresource("ref-uuid-1")
    session.flaws.cvss_scores.create.return_value = _mock_subresource("cvss-uuid-1")

    result = flaw_create(
        title="GStreamer: OOB read",
        comment_zero="Description text",
        embargoed=True,
        cve_id="CVE-2026-52719",
        impact="IMPORTANT",
        components=["gstreamer"],
        cve_description="Public description",
        statement="Impact statement",
        cwe_id="CWE-125",
        source="RESEARCHER",
        reported_dt="2026-05-19T00:00:00Z",
        mitigation="Avoid untrusted JPEG files",
        acknowledgments=[{"name": "JUNYI LIU", "affiliation": "", "from_upstream": False}],
        references=[
            {
                "url": "https://example.com/issue/5104",
                "description": "Upstream issue",
                "type": "UPSTREAM",
            }
        ],
        cvss_scores=[
            {
                "cvss_version": "V3",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H",
                "issuer": "RH",
            }
        ],
    )

    assert result["ok"] is True
    assert result["flaw_uuid"] == "aaa58a80-dd9c-43dd-ba19-61fa88a66714"
    assert len(result["acknowledgments"]) == 1
    assert len(result["references"]) == 1
    assert len(result["cvss_scores"]) == 1
    assert "partial" not in result

    session.flaws.create.assert_called_once()
    flaw_data = session.flaws.create.call_args[0][0]
    assert flaw_data["title"] == "GStreamer: OOB read"
    assert flaw_data["impact"] == "IMPORTANT"
    assert flaw_data["cwe_id"] == "CWE-125"

    session.flaws.acknowledgments.create.assert_called_once()
    ack_data = session.flaws.acknowledgments.create.call_args[0][0]
    assert ack_data["name"] == "JUNYI LIU"
    assert ack_data["embargoed"] is True

    session.flaws.references.create.assert_called_once()
    ref_data = session.flaws.references.create.call_args[0][0]
    assert ref_data["url"] == "https://example.com/issue/5104"
    assert ref_data["embargoed"] is True

    session.flaws.cvss_scores.create.assert_called_once()
    _, kwargs = session.flaws.cvss_scores.create.call_args
    assert kwargs["api_version"] == "v1"


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_create_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "title is required"}'
    session.flaws.create.side_effect = requests.HTTPError(response=resp)

    result = flaw_create(
        title="",
        comment_zero="Description",
        embargoed=False,
    )

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 400


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_create_partial_failure_ack(mock_get_session: MagicMock) -> None:
    """Flaw created successfully but acknowledgment creation fails."""
    session = mock_get_session.return_value
    session.flaws.create.return_value = _mock_flaw()
    session.flaws.acknowledgments.create.side_effect = requests.ConnectionError("timeout")

    result = flaw_create(
        title="Test flaw",
        comment_zero="Description",
        embargoed=True,
        acknowledgments=[{"name": "Researcher", "affiliation": "Org"}],
    )

    assert result["ok"] is True
    assert result["flaw_uuid"] == "aaa58a80-dd9c-43dd-ba19-61fa88a66714"
    assert result["partial"] is True
    assert len(result["errors"]) == 1
    assert result["errors"][0]["index"] == 0


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_create_partial_failure_cvss(mock_get_session: MagicMock) -> None:
    """Flaw and acks succeed, but one CVSS score fails."""
    session = mock_get_session.return_value
    session.flaws.create.return_value = _mock_flaw()
    session.flaws.acknowledgments.create.return_value = _mock_subresource("ack-1")

    cvss_ok = _mock_subresource("cvss-1")
    session.flaws.cvss_scores.create.side_effect = [
        cvss_ok,
        requests.ConnectionError("connection reset"),
    ]

    result = flaw_create(
        title="Test flaw",
        comment_zero="Description",
        embargoed=True,
        acknowledgments=[{"name": "R"}],
        cvss_scores=[
            {"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"},
            {
                "cvss_version": "V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N",
            },
        ],
    )

    assert result["ok"] is True
    assert result["partial"] is True
    assert len(result["cvss_scores"]) == 1
    assert len(result["errors"]) == 1
    assert result["errors"][0]["index"] == 1


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_create_no_cve_id(mock_get_session: MagicMock) -> None:
    """Flaw created without a CVE id returns empty cve_id."""
    session = mock_get_session.return_value
    flaw = _mock_flaw(cve_id="")
    session.flaws.create.return_value = flaw

    result = flaw_create(
        title="Embargoed flaw",
        comment_zero="No CVE yet",
        embargoed=True,
    )

    assert result["ok"] is True
    assert result["cve_id"] == ""
    assert result["flaw_uuid"] == "aaa58a80-dd9c-43dd-ba19-61fa88a66714"


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_create_optional_fields_omitted(mock_get_session: MagicMock) -> None:
    """Optional fields that are None should not appear in the POST body."""
    session = mock_get_session.return_value
    session.flaws.create.return_value = _mock_flaw()

    flaw_create(
        title="Minimal flaw",
        comment_zero="Desc",
        embargoed=False,
    )

    flaw_data = session.flaws.create.call_args[0][0]
    assert "cve_id" not in flaw_data
    assert "impact" not in flaw_data
    assert "components" not in flaw_data
    assert "statement" not in flaw_data
    assert "mitigation" not in flaw_data


# ---------------------------------------------------------------------------
# flaw_update tests
# ---------------------------------------------------------------------------


def _mock_flaw_full(**overrides):
    defaults = {
        "uuid": "aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        "cve_id": "CVE-2026-52719",
        "title": "Original title",
        "comment_zero": "Original comment",
        "embargoed": True,
        "impact": "MODERATE",
        "components": ["kernel"],
        "cve_description": "",
        "statement": "",
        "cwe_id": "CWE-125",
        "source": "RESEARCHER",
        "reported_dt": "2026-05-19T00:00:00Z",
        "unembargo_dt": None,
        "mitigation": "",
        "owner": None,
        "updated_dt": "2026-06-08T12:00:00Z",
    }
    defaults.update(overrides)
    flaw = MagicMock()
    for k, v in defaults.items():
        setattr(flaw, k, v)
    flaw.to_dict.return_value = {k: v for k, v in defaults.items() if v is not None}
    return flaw


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_update_single_field(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    current = _mock_flaw_full()
    session.flaws.retrieve.return_value = current
    session.flaws.update.return_value = _mock_flaw_full(impact="IMPORTANT")

    result = flaw_update(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714", impact="IMPORTANT")

    assert result["ok"] is True
    session.flaws.update.assert_called_once()
    update_data = session.flaws.update.call_args[0][1]
    assert update_data["impact"] == "IMPORTANT"
    assert update_data["title"] == "Original title"
    assert update_data["updated_dt"] == "2026-06-08T12:00:00Z"


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_update_retrieve_fails(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.side_effect = requests.ConnectionError("timeout")

    result = flaw_update(flaw_id="bad-uuid", title="New title")

    assert result["ok"] is False


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_update_put_fails(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full()
    resp = MagicMock()
    resp.status_code = 409
    resp.text = "Conflict"
    session.flaws.update.side_effect = requests.HTTPError(response=resp)

    result = flaw_update(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714", statement="New")

    assert result["ok"] is False
    assert result["status_code"] == 409


# ---------------------------------------------------------------------------
# affect_add tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_affect_add_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=True)
    bulk_result = MagicMock()
    bulk_result.to_dict.return_value = [{"uuid": "affect-uuid-1"}]
    session.affects.bulk_create.return_value = bulk_result

    result = affect_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        affects=[{"ps_update_stream": "rhel-9.4", "affectedness": "AFFECTED"}],
    )

    assert result["ok"] is True
    session.affects.bulk_create.assert_called_once()
    bulk_data = session.affects.bulk_create.call_args[0][0]
    assert bulk_data[0]["flaw"] == "aaa58a80-dd9c-43dd-ba19-61fa88a66714"
    assert bulk_data[0]["embargoed"] is True


@patch("osidb_mcp.tools_write.get_session")
def test_affect_add_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full()
    resp = MagicMock()
    resp.status_code = 400
    resp.text = "Bad request"
    session.affects.bulk_create.side_effect = requests.HTTPError(response=resp)

    result = affect_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        affects=[
            {"ps_update_stream": "rhel-9.4"},
            {"ps_update_stream": "rhel-8.10"},
        ],
    )

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# affect_remove tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.requests.delete")
@patch("osidb_mcp.tools_write.get_session")
def test_affect_remove_success(mock_get_session: MagicMock, mock_delete: MagicMock) -> None:
    client = mock_get_session.return_value.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {"Authorization": "Bearer tok"}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    delete_resp = MagicMock()
    delete_resp.raise_for_status.return_value = None
    mock_delete.return_value = delete_resp

    result = affect_remove(affect_uuids=["uuid-1", "uuid-2"])

    assert result["ok"] is True
    assert result["deleted"] == ["uuid-1", "uuid-2"]
    mock_delete.assert_called_once()
    assert mock_delete.call_args[1]["json"] == ["uuid-1", "uuid-2"]


@patch("osidb_mcp.tools_write.requests.delete")
@patch("osidb_mcp.tools_write.get_session")
def test_affect_remove_error(mock_get_session: MagicMock, mock_delete: MagicMock) -> None:
    client = mock_get_session.return_value.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    mock_delete.side_effect = requests.HTTPError(response=resp)

    result = affect_remove(affect_uuids=["bad-uuid"])

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# flaw_acknowledgment_add tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_ack_add_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=True)
    session.flaws.acknowledgments.create.return_value = _mock_subresource("ack-1")

    result = flaw_acknowledgment_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        acknowledgments=[{"name": "Jane Doe", "affiliation": "Org"}],
    )

    assert result["ok"] is True
    assert len(result["created"]) == 1
    assert "partial" not in result


@patch("osidb_mcp.tools_write.get_session")
def test_ack_add_flaw_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.retrieve.side_effect = requests.HTTPError(response=resp)

    result = flaw_acknowledgment_add(
        flaw_id="nonexistent",
        acknowledgments=[{"name": "X"}],
    )

    assert result["ok"] is False
    assert result["status_code"] == 404


# ---------------------------------------------------------------------------
# flaw_acknowledgment_remove tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_ack_remove_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.acknowledgments.delete.return_value = None

    result = flaw_acknowledgment_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        acknowledgment_id="ack-uuid-1",
    )

    assert result["ok"] is True
    assert result["deleted"] == "ack-uuid-1"


@patch("osidb_mcp.tools_write.get_session")
def test_ack_remove_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.acknowledgments.delete.side_effect = requests.HTTPError(response=resp)

    result = flaw_acknowledgment_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        acknowledgment_id="bad-uuid",
    )

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# flaw_reference_add tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_ref_add_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=False)
    session.flaws.references.create.return_value = _mock_subresource("ref-1")

    result = flaw_reference_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        references=[{"url": "https://example.com/advisory", "type": "EXTERNAL"}],
    )

    assert result["ok"] is True
    assert len(result["created"]) == 1

    ref_data = session.flaws.references.create.call_args[0][0]
    assert ref_data["embargoed"] is False


@patch("osidb_mcp.tools_write.get_session")
def test_ref_add_multiple(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full()
    session.flaws.references.create.side_effect = [
        _mock_subresource("r1"),
        _mock_subresource("r2"),
    ]

    result = flaw_reference_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        references=[
            {"url": "https://a.com"},
            {"url": "https://b.com", "type": "UPSTREAM"},
        ],
    )

    assert result["ok"] is True
    assert len(result["created"]) == 2


# ---------------------------------------------------------------------------
# flaw_reference_remove tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_ref_remove_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.references.delete.return_value = None

    result = flaw_reference_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        reference_id="ref-uuid-1",
    )

    assert result["ok"] is True
    assert result["deleted"] == "ref-uuid-1"


@patch("osidb_mcp.tools_write.get_session")
def test_ref_remove_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.references.delete.side_effect = requests.ConnectionError("fail")

    result = flaw_reference_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        reference_id="ref-uuid-1",
    )

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# affect_update tests
# ---------------------------------------------------------------------------


def _mock_affect_full(**overrides):
    defaults = {
        "uuid": "bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        "flaw": "aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        "affectedness": "NEW",
        "resolution": "",
        "impact": None,
        "ps_component": "gstreamer1-plugins-bad-free",
        "ps_module": None,
        "ps_update_stream": "rhel-9.8.z",
        "purl": "pkg:rpm/redhat/gstreamer1-plugins-bad-free@1.22.12-7.el9_8?arch=src",
        "delegated_resolution": None,
        "not_affected_justification": "",
        "embargoed": True,
        "updated_dt": "2026-06-08T14:00:00Z",
    }
    defaults.update(overrides)
    affect = MagicMock()
    for k, v in defaults.items():
        setattr(affect, k, v)
    affect.to_dict.return_value = {k: v for k, v in defaults.items() if v is not None}
    return affect


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    current = _mock_affect_full()
    session.affects.retrieve.return_value = current
    updated = _mock_affect_full(affectedness="AFFECTED", resolution="FIX")
    session.affects.update.return_value = updated

    result = affect_update(
        affect_uuid="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        affectedness="AFFECTED",
        resolution="FIX",
    )

    assert result["ok"] is True
    session.affects.update.assert_called_once()
    update_data = session.affects.update.call_args[0][1]
    assert update_data["affectedness"] == "AFFECTED"
    assert update_data["resolution"] == "FIX"
    assert update_data["ps_component"] == "gstreamer1-plugins-bad-free"
    assert update_data["updated_dt"] == "2026-06-08T14:00:00Z"


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_notaffected_with_justification(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    current = _mock_affect_full()
    session.affects.retrieve.return_value = current
    updated = _mock_affect_full(
        affectedness="NOTAFFECTED",
        not_affected_justification="COMPONENT_NOT_PRESENT",
    )
    session.affects.update.return_value = updated

    result = affect_update(
        affect_uuid="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        affectedness="NOTAFFECTED",
        not_affected_justification="COMPONENT_NOT_PRESENT",
    )

    assert result["ok"] is True
    session.affects.update.assert_called_once()
    update_data = session.affects.update.call_args[0][1]
    assert update_data["affectedness"] == "NOTAFFECTED"
    assert update_data["not_affected_justification"] == "COMPONENT_NOT_PRESENT"


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_retrieve_fails(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.retrieve.side_effect = requests.ConnectionError("timeout")

    result = affect_update(affect_uuid="bad-uuid", affectedness="AFFECTED")

    assert result["ok"] is False


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_put_fails(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.retrieve.return_value = _mock_affect_full()
    resp = MagicMock()
    resp.status_code = 409
    resp.text = "Conflict"
    session.affects.update.side_effect = requests.HTTPError(response=resp)

    result = affect_update(
        affect_uuid="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        affectedness="AFFECTED",
    )

    assert result["ok"] is False
    assert result["status_code"] == 409


# ---------------------------------------------------------------------------
# tracker_file tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_tracker_create_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    tracker_result = MagicMock()
    tracker_result.to_dict.return_value = {
        "uuid": "trk-1",
        "type": "JIRA",
        "external_system_id": "RHEL-12345",
        "ps_update_stream": "rhel-9.4.0.z",
    }
    session.trackers.create.return_value = tracker_result

    result = tracker_create(
        affect_uuids=["bbb58a80-dd9c-43dd-ba19-61fa88a66714"],
        ps_update_stream="rhel-9.4.0.z",
        embargoed=False,
    )

    assert result["ok"] is True
    assert result["tracker"]["uuid"] == "trk-1"
    session.trackers.create.assert_called_once_with(
        form_data={
            "affects": ["bbb58a80-dd9c-43dd-ba19-61fa88a66714"],
            "ps_update_stream": "rhel-9.4.0.z",
            "embargoed": False,
        }
    )


@patch("osidb_mcp.tools_write.get_session")
def test_tracker_create_with_sync_to_bz_false(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    tracker_result = MagicMock()
    tracker_result.to_dict.return_value = {"uuid": "trk-2", "type": "JIRA"}
    session.trackers.create.return_value = tracker_result

    result = tracker_create(
        affect_uuids=["bbb58a80-dd9c-43dd-ba19-61fa88a66714"],
        ps_update_stream="rhel-9.4.0.z",
        embargoed=False,
        sync_to_bz=False,
    )

    assert result["ok"] is True
    session.trackers.create.assert_called_once_with(
        form_data={
            "affects": ["bbb58a80-dd9c-43dd-ba19-61fa88a66714"],
            "ps_update_stream": "rhel-9.4.0.z",
            "embargoed": False,
            "sync_to_bz": False,
        }
    )


@patch("osidb_mcp.tools_write.get_session")
def test_tracker_create_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Invalid affect UUID"}'
    session.trackers.create.side_effect = requests.HTTPError(response=resp)

    result = tracker_create(
        affect_uuids=["bad-uuid"],
        ps_update_stream="rhel-9.4.0.z",
        embargoed=False,
    )

    assert result["ok"] is False
    assert result["status_code"] == 400


@patch("osidb_mcp.tools_write.get_session")
def test_trackers_bulk_file_dry_run(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    flaw_mock = MagicMock()
    flaw_mock.uuid = "70d80ad3-a8cf-4763-be08-799191d12860"
    session.flaws.retrieve.return_value = flaw_mock

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
                "ps_update_stream": "rhel-8.10.0.z",
                "ps_component": "kernel",
                "selected": True,
                "offer": {"acked": True, "selected": True, "eus": False, "aus": False},
                "affect": {"uuid": "aff-2", "embargoed": False},
            },
            {
                "ps_update_stream": "fedora-rawhide",
                "ps_component": "kernel",
                "selected": False,
                "offer": {"acked": False, "selected": False, "eus": False, "aus": False},
                "affect": {"uuid": "aff-3", "embargoed": False},
            },
        ],
        "not_applicable": [
            {"uuid": "aff-4", "ps_module": "community-kernel"},
        ],
    }
    session.trackers.file.return_value = suggestions

    result = trackers_bulk_file(
        flaw_id="CVE-2024-1234",
        dry_run=True,
    )

    assert result["ok"] is True
    assert result["dry_run"] is True
    assert result["would_file"] == 2
    assert result["not_applicable_count"] == 1
    assert result["trackers"][0]["ps_update_stream"] == "rhel-9.4.0.z"
    assert result["trackers"][1]["ps_update_stream"] == "rhel-8.10.0.z"
    session.trackers.create.assert_not_called()
    session.flaws.retrieve.assert_called_once_with("CVE-2024-1234")
    session.trackers.file.assert_called_once_with(
        {"flaw_uuids": ["70d80ad3-a8cf-4763-be08-799191d12860"]},
        exclude_existing_trackers=True,
    )


@patch("osidb_mcp.tools_write.get_session")
def test_trackers_bulk_file_executes_with_sync_optimization(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    flaw_mock = MagicMock()
    flaw_mock.uuid = "70d80ad3-a8cf-4763-be08-799191d12860"
    session.flaws.retrieve.return_value = flaw_mock

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
                "ps_update_stream": "rhel-8.10.0.z",
                "ps_component": "kernel",
                "selected": True,
                "offer": {"acked": True, "selected": True, "eus": False, "aus": False},
                "affect": {"uuid": "aff-2", "embargoed": False},
            },
        ],
        "not_applicable": [],
    }
    session.trackers.file.return_value = suggestions

    tracker1 = MagicMock()
    tracker1.to_dict.return_value = {
        "uuid": "trk-1",
        "type": "JIRA",
        "external_system_id": "RHEL-111",
    }
    tracker2 = MagicMock()
    tracker2.to_dict.return_value = {
        "uuid": "trk-2",
        "type": "JIRA",
        "external_system_id": "RHEL-222",
    }
    session.trackers.create.side_effect = [tracker1, tracker2]

    result = trackers_bulk_file(flaw_id="CVE-2024-1234")

    assert result["ok"] is True
    assert result["filed"] == 2
    assert result["failed"] == 0

    calls = session.trackers.create.call_args_list
    assert len(calls) == 2
    # First call: sync_to_bz=False
    assert calls[0].kwargs["form_data"] == {
        "affects": ["aff-1"],
        "ps_update_stream": "rhel-9.4.0.z",
        "embargoed": False,
        "sync_to_bz": False,
    }
    # Last call: sync_to_bz defaults to True (not set explicitly)
    assert calls[1].kwargs["form_data"] == {
        "affects": ["aff-2"],
        "ps_update_stream": "rhel-8.10.0.z",
        "embargoed": False,
    }


@patch("osidb_mcp.tools_write.get_session")
def test_trackers_bulk_file_only_selected_false(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    flaw_mock = MagicMock()
    flaw_mock.uuid = "70d80ad3-a8cf-4763-be08-799191d12860"
    session.flaws.retrieve.return_value = flaw_mock

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
        "not_applicable": [],
    }
    session.trackers.file.return_value = suggestions

    tracker1 = MagicMock()
    tracker1.to_dict.return_value = {"uuid": "trk-1", "type": "JIRA"}
    tracker2 = MagicMock()
    tracker2.to_dict.return_value = {"uuid": "trk-2", "type": "BUGZILLA"}
    session.trackers.create.side_effect = [tracker1, tracker2]

    result = trackers_bulk_file(flaw_id="CVE-2024-1234", only_selected=False)

    assert result["ok"] is True
    assert result["filed"] == 2
    calls = session.trackers.create.call_args_list
    assert len(calls) == 2


@patch("osidb_mcp.tools_write.get_session")
def test_trackers_bulk_file_no_matching_streams(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    flaw_mock = MagicMock()
    flaw_mock.uuid = "70d80ad3-a8cf-4763-be08-799191d12860"
    session.flaws.retrieve.return_value = flaw_mock

    suggestions = MagicMock()
    suggestions.to_dict.return_value = {
        "streams_components": [
            {
                "ps_update_stream": "fedora-rawhide",
                "ps_component": "kernel",
                "selected": False,
                "offer": {"acked": False, "selected": False, "eus": False, "aus": False},
                "affect": {"uuid": "aff-1", "embargoed": False},
            },
        ],
        "not_applicable": [
            {"uuid": "aff-2", "ps_module": "community-kernel"},
        ],
    }
    session.trackers.file.return_value = suggestions

    result = trackers_bulk_file(flaw_id="CVE-2024-1234")

    assert result["ok"] is True
    assert result["filed"] == 0
    assert "No streams matched" in result["message"]
    session.trackers.create.assert_not_called()


@patch("osidb_mcp.tools_write.get_session")
def test_trackers_bulk_file_partial_failure(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    flaw_mock = MagicMock()
    flaw_mock.uuid = "70d80ad3-a8cf-4763-be08-799191d12860"
    session.flaws.retrieve.return_value = flaw_mock

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
                "ps_update_stream": "rhel-8.10.0.z",
                "ps_component": "kernel",
                "selected": True,
                "offer": {"acked": True, "selected": True, "eus": False, "aus": False},
                "affect": {"uuid": "aff-2", "embargoed": False},
            },
        ],
        "not_applicable": [],
    }
    session.trackers.file.return_value = suggestions

    tracker1 = MagicMock()
    tracker1.to_dict.return_value = {"uuid": "trk-1", "type": "JIRA"}
    session.trackers.create.side_effect = [
        tracker1,
        Exception("Server error"),
    ]

    result = trackers_bulk_file(flaw_id="CVE-2024-1234")

    assert result["ok"] is False
    assert result["filed"] == 1
    assert result["failed"] == 1
    assert result["failures"][0]["ps_update_stream"] == "rhel-8.10.0.z"


@patch("osidb_mcp.tools_write.get_session")
def test_trackers_bulk_file_uuid_passthrough(mock_get_session: MagicMock) -> None:
    """When flaw_id is already a UUID, no flaws.retrieve call is made."""
    session = mock_get_session.return_value
    suggestions = MagicMock()
    suggestions.to_dict.return_value = {
        "streams_components": [],
        "not_applicable": [],
    }
    session.trackers.file.return_value = suggestions

    result = trackers_bulk_file(
        flaw_id="70d80ad3-a8cf-4763-be08-799191d12860",
        dry_run=True,
    )

    session.flaws.retrieve.assert_not_called()
    session.trackers.file.assert_called_once_with(
        {"flaw_uuids": ["70d80ad3-a8cf-4763-be08-799191d12860"]},
        exclude_existing_trackers=True,
    )
    assert result["ok"] is True


@patch("osidb_mcp.tools_write.get_session")
def test_trackers_bulk_file_cve_resolution_failure(mock_get_session: MagicMock) -> None:
    """When CVE ID cannot be resolved, return a clean error."""
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.json.return_value = {"detail": "Not found."}
    http_error = requests.HTTPError(response=resp)
    session.flaws.retrieve.side_effect = http_error

    result = trackers_bulk_file(flaw_id="CVE-9999-99999")

    assert result["ok"] is False
    session.trackers.file.assert_not_called()


# ---------------------------------------------------------------------------
# flaw_cvss_add tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_cvss_add_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=False)
    session.flaws.cvss_scores.create.return_value = _mock_subresource("cvss-1")

    result = flaw_cvss_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_scores=[
            {"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"}
        ],
    )

    assert result["ok"] is True
    assert len(result["created"]) == 1
    assert "partial" not in result

    call_kwargs = session.flaws.cvss_scores.create.call_args[1]
    assert call_kwargs["api_version"] == "v1"

    cvss_data = session.flaws.cvss_scores.create.call_args[0][0]
    assert cvss_data["embargoed"] is False


@patch("osidb_mcp.tools_write.get_session")
def test_cvss_add_multiple(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=True)
    session.flaws.cvss_scores.create.side_effect = [
        _mock_subresource("cvss-1"),
        _mock_subresource("cvss-2"),
    ]

    result = flaw_cvss_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_scores=[
            {"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"},
            {
                "cvss_version": "V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N",
            },
        ],
    )

    assert result["ok"] is True
    assert len(result["created"]) == 2
    assert "partial" not in result


@patch("osidb_mcp.tools_write.get_session")
def test_cvss_add_flaw_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.retrieve.side_effect = requests.HTTPError(response=resp)

    result = flaw_cvss_add(
        flaw_id="nonexistent",
        cvss_scores=[
            {"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"}
        ],
    )

    assert result["ok"] is False
    assert result["status_code"] == 404


@patch("osidb_mcp.tools_write.get_session")
def test_cvss_add_partial_failure(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=True)
    session.flaws.cvss_scores.create.side_effect = [
        _mock_subresource("cvss-1"),
        requests.ConnectionError("timeout"),
    ]

    result = flaw_cvss_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_scores=[
            {"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"},
            {
                "cvss_version": "V4",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N",
            },
        ],
    )

    assert result["ok"] is True
    assert result["partial"] is True
    assert len(result["created"]) == 1
    assert len(result["errors"]) == 1
    assert result["errors"][0]["index"] == 1


# ---------------------------------------------------------------------------
# flaw_cvss_remove tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_cvss_remove_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.cvss_scores.delete.return_value = None

    result = flaw_cvss_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_score_id="cvss-uuid-1",
    )

    assert result["ok"] is True
    assert result["deleted"] == "cvss-uuid-1"
    session.flaws.cvss_scores.delete.assert_called_once_with(
        "aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        "cvss-uuid-1",
        api_version="v1",
    )


@patch("osidb_mcp.tools_write.get_session")
def test_cvss_remove_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.cvss_scores.delete.side_effect = requests.HTTPError(response=resp)

    result = flaw_cvss_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_score_id="bad-uuid",
    )

    assert result["ok"] is False
    assert result["status_code"] == 404


# ---------------------------------------------------------------------------
# flaw_comment_create tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=False)
    comment = MagicMock()
    comment.to_dict.return_value = {
        "uuid": "comment-uuid-1",
        "text": "Triage note",
    }
    session.flaws.comments.create.return_value = comment

    result = flaw_comment_create(
        flaw_id="CVE-2026-52719",
        text="Triage note",
    )

    assert result["ok"] is True
    assert result["comment"]["uuid"] == "comment-uuid-1"
    session.flaws.comments.create.assert_called_once_with(
        {"text": "Triage note", "embargoed": False, "is_private": False},
        "CVE-2026-52719",
    )


@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_private(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=True)
    comment = MagicMock()
    comment.to_dict.return_value = {"uuid": "comment-uuid-2", "text": "Private note"}
    session.flaws.comments.create.return_value = comment

    result = flaw_comment_create(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        text="Private note",
        is_private=True,
    )

    assert result["ok"] is True
    session.flaws.comments.create.assert_called_once_with(
        {"text": "Private note", "embargoed": True, "is_private": True},
        "aaa58a80-dd9c-43dd-ba19-61fa88a66714",
    )


@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_with_creator(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=False)
    comment = MagicMock()
    comment.to_dict.return_value = {
        "uuid": "comment-uuid-3",
        "text": "Note with creator",
        "creator": "jdoe@redhat.com",
    }
    session.flaws.comments.create.return_value = comment

    result = flaw_comment_create(
        flaw_id="CVE-2026-52719",
        text="Note with creator",
        creator="jdoe@redhat.com",
    )

    assert result["ok"] is True
    session.flaws.comments.create.assert_called_once_with(
        {
            "text": "Note with creator",
            "embargoed": False,
            "is_private": False,
            "creator": "jdoe@redhat.com",
        },
        "CVE-2026-52719",
    )


@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_flaw_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.retrieve.side_effect = requests.HTTPError(response=resp)

    result = flaw_comment_create(
        flaw_id="CVE-9999-00000",
        text="Should fail",
    )

    assert result["ok"] is False
    assert result["status_code"] == 404
    session.flaws.comments.create.assert_not_called()


@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_api_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=False)
    resp = MagicMock()
    resp.status_code = 400
    resp.text = "Bad request"
    session.flaws.comments.create.side_effect = requests.HTTPError(response=resp)

    result = flaw_comment_create(
        flaw_id="CVE-2026-52719",
        text="Should fail on create",
    )

    assert result["ok"] is False
    assert result["status_code"] == 400


# ---------------------------------------------------------------------------
# flaw_comment_create internal (Jira) tests
# ---------------------------------------------------------------------------


def _jira_settings(**overrides: Any) -> "Settings":
    from osidb_mcp.config import AccessMode, Settings

    defaults: dict[str, Any] = dict(
        base_url="https://osidb.example.com",
        auth="kerberos",
        username=None,
        password=None,
        verify_ssl=True,
        user_agent=None,
        access_mode=AccessMode.readwrite,
        jira_url="https://issues.redhat.com",
        jira_access_token="tok-123",
        jira_api_email="user@redhat.com",
    )
    defaults.update(overrides)
    return Settings(**defaults)


@patch("osidb_mcp.tools_write.requests.post")
@patch("osidb_mcp.tools_write.current_settings", return_value=_jira_settings())
@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_internal_success(
    mock_get_session: MagicMock,
    _mock_settings: MagicMock,
    mock_post: MagicMock,
) -> None:
    session = mock_get_session.return_value
    flaw = _mock_flaw_full(task_key="OSIM-83479")
    session.flaws.retrieve.return_value = flaw

    resp = MagicMock()
    resp.status_code = 201
    resp.json.return_value = {"id": "99001"}
    resp.raise_for_status.return_value = None
    mock_post.return_value = resp

    result = flaw_comment_create(
        flaw_id="CVE-2026-52719",
        text="Internal triage note",
        internal=True,
    )

    assert result["ok"] is True
    assert result["jira_comment_id"] == "99001"
    assert result["jira_issue"] == "OSIM-83479"
    session.flaws.retrieve.assert_called_once_with("CVE-2026-52719", include_fields="task_key")
    mock_post.assert_called_once()
    call_kwargs = mock_post.call_args
    assert (
        "OSIM-83479" in call_kwargs[1]["url"]
        if "url" in call_kwargs[1]
        else "OSIM-83479" in call_kwargs[0][0]
    )


@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_internal_no_task_key(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    flaw = _mock_flaw_full(task_key=None)
    session.flaws.retrieve.return_value = flaw

    result = flaw_comment_create(
        flaw_id="CVE-2026-52719",
        text="Should fail",
        internal=True,
    )

    assert result["ok"] is False
    assert result["error"] == "no_jira_task"


@patch(
    "osidb_mcp.tools_write.current_settings",
    return_value=_jira_settings(jira_url=None, jira_access_token=None),
)
@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_internal_missing_jira_config(
    mock_get_session: MagicMock,
    _mock_settings: MagicMock,
) -> None:
    session = mock_get_session.return_value
    flaw = _mock_flaw_full(task_key="OSIM-99999")
    session.flaws.retrieve.return_value = flaw

    result = flaw_comment_create(
        flaw_id="CVE-2026-52719",
        text="Should fail",
        internal=True,
    )

    assert result["ok"] is False
    assert result["error"] == "jira_not_configured"
    assert "JIRA_URL" in result["detail"]
    assert "JIRA_ACCESS_TOKEN" in result["detail"]


@patch("osidb_mcp.tools_write.requests.post")
@patch("osidb_mcp.tools_write.current_settings", return_value=_jira_settings())
@patch("osidb_mcp.tools_write.get_session")
def test_comment_create_internal_jira_error(
    mock_get_session: MagicMock,
    _mock_settings: MagicMock,
    mock_post: MagicMock,
) -> None:
    session = mock_get_session.return_value
    flaw = _mock_flaw_full(task_key="OSIM-83479")
    session.flaws.retrieve.return_value = flaw

    resp = MagicMock()
    resp.status_code = 403
    resp.text = "Forbidden"
    mock_post.return_value = resp
    resp.raise_for_status.side_effect = requests.HTTPError(response=resp)

    result = flaw_comment_create(
        flaw_id="CVE-2026-52719",
        text="Should fail on Jira",
        internal=True,
    )

    assert result["ok"] is False
    assert result["status_code"] == 403


# ---------------------------------------------------------------------------
# flaw_label_add / flaw_label_remove tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_label_add_success(mock_get_session: MagicMock) -> None:
    mock_get_session.return_value
    r = MagicMock()
    r.status_code = 201
    parsed = MagicMock()
    parsed.to_dict.return_value = {"label": "triage", "state": "NEW"}
    r.parsed = parsed
    with patch(
        "osidb_bindings.bindings.python_client.api.osidb.osidb_api_v1_flaws_labels_create.sync_detailed",
        return_value=r,
    ):
        result = flaw_label_add(
            flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
            label="triage",
        )

    assert result["ok"] is True
    assert result["label"]["label"] == "triage"


def test_label_add_invalid_uuid() -> None:
    result = flaw_label_add(flaw_id="not-a-uuid", label="triage")
    assert result["ok"] is False
    assert result["error"] == "bad_request"


@patch("osidb_mcp.tools_write.get_session")
def test_label_remove_success(mock_get_session: MagicMock) -> None:
    mock_get_session.return_value
    r = MagicMock()
    r.status_code = 204
    with patch(
        "osidb_bindings.bindings.python_client.api.osidb.osidb_api_v1_flaws_labels_destroy.sync_detailed",
        return_value=r,
    ):
        result = flaw_label_remove(
            flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
            label_id="label-1",
        )

    assert result["ok"] is True
    assert result["deleted"] == "label-1"


# ---------------------------------------------------------------------------
# flaw_incident_request tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_incident_request_success(mock_get_session: MagicMock) -> None:
    mock_get_session.return_value
    r = MagicMock()
    r.status_code = 200
    parsed = MagicMock()
    parsed.to_dict.return_value = {"kind": "MAJOR_INCIDENT_REQUESTED", "comment": "urgent"}
    r.parsed = parsed
    with patch(
        "osidb_bindings.bindings.python_client.api.osidb.osidb_api_v1_flaws_incident_requests_create.sync_detailed",
        return_value=r,
    ):
        result = flaw_incident_request(
            flaw_id="CVE-2026-52719",
            kind="MAJOR_INCIDENT_REQUESTED",
            comment="urgent",
        )

    assert result["ok"] is True
    assert result["incident_request"]["kind"] == "MAJOR_INCIDENT_REQUESTED"


# ---------------------------------------------------------------------------
# flaw_acknowledgment_update tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_ack_update_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    current = MagicMock()
    current.name = "Original"
    current.affiliation = "Org"
    current.from_upstream = False
    current.embargoed = True
    current.updated_dt = "2026-06-08T12:00:00Z"
    session.flaws.acknowledgments.retrieve.return_value = current
    updated = _mock_subresource("ack-1")
    session.flaws.acknowledgments.update.return_value = updated

    result = flaw_acknowledgment_update(
        flaw_id="CVE-2026-52719",
        acknowledgment_id="ack-1",
        name="Updated Name",
    )

    assert result["ok"] is True
    update_data = session.flaws.acknowledgments.update.call_args[0][2]
    assert update_data["name"] == "Updated Name"
    assert update_data["affiliation"] == "Org"


@patch("osidb_mcp.tools_write.get_session")
def test_ack_update_retrieve_fails(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.acknowledgments.retrieve.side_effect = requests.HTTPError(response=resp)

    result = flaw_acknowledgment_update(
        flaw_id="CVE-2026-52719",
        acknowledgment_id="bad-id",
        name="X",
    )

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# flaw_reference_update tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_ref_update_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    current = MagicMock()
    current.url = "https://old.com"
    current.description = "Old"
    current.type = "EXTERNAL"
    current.embargoed = False
    current.updated_dt = "2026-06-08T12:00:00Z"
    session.flaws.references.retrieve.return_value = current
    updated = _mock_subresource("ref-1")
    session.flaws.references.update.return_value = updated

    result = flaw_reference_update(
        flaw_id="CVE-2026-52719",
        reference_id="ref-1",
        url="https://new.com",
    )

    assert result["ok"] is True
    update_data = session.flaws.references.update.call_args[0][2]
    assert update_data["url"] == "https://new.com"


# ---------------------------------------------------------------------------
# flaw_cvss_update tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_write.requests.put")
@patch("osidb_mcp.tools_write.get_session")
def test_cvss_update_success(mock_get_session: MagicMock, mock_put: MagicMock) -> None:
    session = mock_get_session.return_value
    current = MagicMock()
    current.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
    current.comment = ""
    current.cvss_version = "V3"
    current.issuer = "RH"
    current.embargoed = False
    current.updated_dt = "2026-06-08T12:00:00Z"
    session.flaws.cvss_scores.retrieve.return_value = current

    client = session.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {"Authorization": "Bearer tok"}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    put_resp = MagicMock()
    put_resp.raise_for_status.return_value = None
    put_resp.json.return_value = {
        "uuid": "cvss-1",
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H",
    }
    mock_put.return_value = put_resp

    result = flaw_cvss_update(
        flaw_id="CVE-2026-52719",
        cvss_score_id="cvss-1",
        vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H",
    )

    assert result["ok"] is True
    assert result["cvss_score"]["vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H"
    mock_put.assert_called_once()
    put_kwargs = mock_put.call_args
    assert "cvss_scores/cvss-1" in put_kwargs[0][0]
    assert put_kwargs[1]["json"]["vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H"


@patch("osidb_mcp.tools_write.requests.put")
@patch("osidb_mcp.tools_write.get_session")
def test_cvss_update_http_error(mock_get_session: MagicMock, mock_put: MagicMock) -> None:
    session = mock_get_session.return_value
    current = MagicMock()
    current.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
    current.comment = ""
    current.cvss_version = "V3"
    current.issuer = "RH"
    current.embargoed = False
    current.updated_dt = "2026-06-08T12:00:00Z"
    session.flaws.cvss_scores.retrieve.return_value = current

    client = session.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    resp = MagicMock()
    resp.status_code = 400
    resp.text = "Bad request"
    mock_put.return_value = resp
    resp.raise_for_status.side_effect = requests.HTTPError(response=resp)

    result = flaw_cvss_update(
        flaw_id="CVE-2026-52719",
        cvss_score_id="cvss-1",
        vector="bad-vector",
    )

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# flaw_package_version_add tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_package_version_add_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full(embargoed=False)
    r = MagicMock()
    r.status_code = 201
    parsed = MagicMock()
    parsed.to_dict.return_value = {"package": "curl", "versions": []}
    r.parsed = parsed
    session.get_client_with_new_access_token.return_value = MagicMock()
    with patch(
        "osidb_bindings.bindings.python_client.api.osidb.osidb_api_v1_flaws_package_versions_create.sync_detailed",
        return_value=r,
    ):
        result = flaw_package_version_add(
            flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
            package="curl",
            versions=[{"version": "7.88.1"}],
        )

    assert result["ok"] is True
    assert result["package_version"]["package"] == "curl"


def test_package_version_add_invalid_uuid() -> None:
    result = flaw_package_version_add(
        flaw_id="not-a-uuid",
        package="curl",
        versions=[{"version": "7.88.1"}],
    )
    assert result["ok"] is False
    assert result["error"] == "bad_request"


# ---------------------------------------------------------------------------
# affects_bulk_create / update / delete tests
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_affects_bulk_create_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    result_obj = MagicMock()
    result_obj.to_dict.return_value = [{"uuid": "a1"}, {"uuid": "a2"}]
    session.affects.bulk_create.return_value = result_obj

    result = affects_bulk_create(
        affects=[
            {
                "flaw": "f1",
                "ps_module": "m",
                "ps_component": "c",
                "affectedness": "NEW",
                "embargoed": False,
            },
            {
                "flaw": "f1",
                "ps_module": "m2",
                "ps_component": "c2",
                "affectedness": "NEW",
                "embargoed": False,
            },
        ]
    )

    assert result["ok"] is True
    session.affects.bulk_create.assert_called_once()


@patch("osidb_mcp.tools_write.get_session")
def test_affects_bulk_create_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 400
    resp.text = "Bad request"
    session.affects.bulk_create.side_effect = requests.HTTPError(response=resp)

    result = affects_bulk_create(affects=[{"flaw": "f1"}])

    assert result["ok"] is False


@patch("osidb_mcp.tools_write.get_session")
def test_affects_bulk_update_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    result_obj = MagicMock()
    result_obj.to_dict.return_value = [{"uuid": "a1"}]
    session.affects.bulk_update.return_value = result_obj

    result = affects_bulk_update(
        affects=[
            {"uuid": "a1", "updated_dt": "2026-06-08T12:00:00Z", "affectedness": "AFFECTED"},
        ]
    )

    assert result["ok"] is True


@patch("osidb_mcp.tools_write.requests.delete")
@patch("osidb_mcp.tools_write.get_session")
def test_affects_bulk_delete_success(mock_get_session: MagicMock, mock_delete: MagicMock) -> None:
    client = mock_get_session.return_value.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {"Authorization": "Bearer tok"}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    delete_resp = MagicMock()
    delete_resp.raise_for_status.return_value = None
    mock_delete.return_value = delete_resp

    result = affects_bulk_delete(affect_uuids=["uuid-1", "uuid-2"])

    assert result["ok"] is True
    assert result["deleted"] == ["uuid-1", "uuid-2"]
    mock_delete.assert_called_once()
    assert mock_delete.call_args[1]["json"] == ["uuid-1", "uuid-2"]


@patch("osidb_mcp.tools_write.requests.delete")
@patch("osidb_mcp.tools_write.get_session")
def test_affects_bulk_delete_error(mock_get_session: MagicMock, mock_delete: MagicMock) -> None:
    client = mock_get_session.return_value.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    mock_delete.side_effect = requests.HTTPError(response=resp)

    result = affects_bulk_delete(affect_uuids=["bad-uuid"])

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# affect_update_bulk tests
# ---------------------------------------------------------------------------


def _mock_list_response(affects):
    """Build a mock retrieve_list response with .results containing affect objects."""
    resp = MagicMock()
    resp.results = affects
    return resp


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    affect_a = _mock_affect_full(uuid="aaa-111", affectedness="NEW")
    affect_b = _mock_affect_full(uuid="bbb-222", affectedness="NEW")
    session.affects.retrieve_list.return_value = _mock_list_response([affect_a, affect_b])

    bulk_result = MagicMock()
    bulk_result.to_dict.return_value = [
        {"uuid": "aaa-111", "affectedness": "AFFECTED", "resolution": "FIX"},
        {"uuid": "bbb-222", "affectedness": "AFFECTED", "resolution": "DEFER"},
    ]
    session.affects.bulk_update.return_value = bulk_result

    result = affect_update_bulk(
        affects=[
            {"affect_uuid": "aaa-111", "affectedness": "AFFECTED", "resolution": "FIX"},
            {"affect_uuid": "bbb-222", "affectedness": "AFFECTED", "resolution": "DEFER"},
        ]
    )

    assert result["ok"] is True
    assert "fetch_errors" not in result
    session.affects.retrieve_list.assert_called_once_with(
        uuid__in=["aaa-111", "bbb-222"],
        limit=2,
    )
    session.affects.bulk_update.assert_called_once()
    payloads = session.affects.bulk_update.call_args[0][0]
    assert len(payloads) == 2
    assert payloads[0]["uuid"] == "aaa-111"
    assert payloads[0]["affectedness"] == "AFFECTED"
    assert payloads[0]["resolution"] == "FIX"
    assert payloads[0]["updated_dt"] == "2026-06-08T14:00:00Z"
    assert payloads[1]["uuid"] == "bbb-222"
    assert payloads[1]["resolution"] == "DEFER"


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_not_affected_justification(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    affect_a = _mock_affect_full(uuid="aaa-111", affectedness="NEW")
    session.affects.retrieve_list.return_value = _mock_list_response([affect_a])

    bulk_result = MagicMock()
    bulk_result.to_dict.return_value = [
        {
            "uuid": "aaa-111",
            "affectedness": "NOT_AFFECTED",
            "not_affected_justification": "VULNERABLE_CODE_NOT_PRESENT",
        },
    ]
    session.affects.bulk_update.return_value = bulk_result

    result = affect_update_bulk(
        affects=[
            {
                "affect_uuid": "aaa-111",
                "affectedness": "NOT_AFFECTED",
                "not_affected_justification": "VULNERABLE_CODE_NOT_PRESENT",
            },
        ]
    )

    assert result["ok"] is True
    session.affects.bulk_update.assert_called_once()
    payloads = session.affects.bulk_update.call_args[0][0]
    assert len(payloads) == 1
    assert payloads[0]["affectedness"] == "NOT_AFFECTED"
    assert payloads[0]["not_affected_justification"] == "VULNERABLE_CODE_NOT_PRESENT"


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_empty_list(mock_get_session: MagicMock) -> None:
    result = affect_update_bulk(affects=[])

    assert result["ok"] is True
    assert result["updated"] == []
    mock_get_session.assert_not_called()


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_partial_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    affect_a = _mock_affect_full(uuid="aaa-111")
    session.affects.retrieve_list.return_value = _mock_list_response([affect_a])

    bulk_result = MagicMock()
    bulk_result.to_dict.return_value = [{"uuid": "aaa-111", "affectedness": "AFFECTED"}]
    session.affects.bulk_update.return_value = bulk_result

    result = affect_update_bulk(
        affects=[
            {"affect_uuid": "aaa-111", "affectedness": "AFFECTED"},
            {"affect_uuid": "bbb-222", "affectedness": "AFFECTED"},
        ]
    )

    assert result["ok"] is True
    assert len(result["fetch_errors"]) == 1
    assert result["fetch_errors"][0]["affect_uuid"] == "bbb-222"
    assert "not found" in result["fetch_errors"][0]["error"]
    session.affects.bulk_update.assert_called_once()
    payloads = session.affects.bulk_update.call_args[0][0]
    assert len(payloads) == 1


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_list_request_fails(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.retrieve_list.side_effect = requests.ConnectionError("timeout")

    result = affect_update_bulk(
        affects=[
            {"affect_uuid": "aaa-111"},
            {"affect_uuid": "bbb-222"},
        ]
    )

    assert result["ok"] is False
    session.affects.bulk_update.assert_not_called()


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_all_not_found(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.retrieve_list.return_value = _mock_list_response([])

    result = affect_update_bulk(
        affects=[
            {"affect_uuid": "aaa-111"},
            {"affect_uuid": "bbb-222"},
        ]
    )

    assert result["ok"] is False
    assert result["error"] == "all_fetches_failed"
    assert len(result["fetch_errors"]) == 2
    session.affects.bulk_update.assert_not_called()


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_put_fails(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    affect = _mock_affect_full()
    session.affects.retrieve_list.return_value = _mock_list_response([affect])

    resp = MagicMock()
    resp.status_code = 409
    resp.text = "Conflict"
    session.affects.bulk_update.side_effect = requests.HTTPError(response=resp)

    result = affect_update_bulk(
        affects=[
            {"affect_uuid": "bbb58a80-dd9c-43dd-ba19-61fa88a66714", "affectedness": "AFFECTED"},
        ]
    )

    assert result["ok"] is False
    assert result["status_code"] == 409


@patch("osidb_mcp.tools_write.get_session")
def test_affect_update_bulk_missing_uuid(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    affect_a = _mock_affect_full(uuid="aaa-111")
    session.affects.retrieve_list.return_value = _mock_list_response([affect_a])

    bulk_result = MagicMock()
    bulk_result.to_dict.return_value = [{"uuid": "aaa-111"}]
    session.affects.bulk_update.return_value = bulk_result

    result = affect_update_bulk(
        affects=[
            {"affectedness": "AFFECTED"},
            {"affect_uuid": "aaa-111", "affectedness": "AFFECTED"},
        ]
    )

    assert result["ok"] is True
    assert len(result["fetch_errors"]) == 1
    assert result["fetch_errors"][0]["affect_uuid"] is None
    session.affects.retrieve_list.assert_called_once_with(
        uuid__in=["aaa-111"],
        limit=1,
    )
    payloads = session.affects.bulk_update.call_args[0][0]
    assert len(payloads) == 1


# ---------------------------------------------------------------------------
# flaw_package_version_update
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_package_version_update_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    current = MagicMock()
    current.to_dict.return_value = {
        "package": "kernel",
        "versions": [{"version": "5.14"}],
        "embargoed": False,
    }
    current.updated_dt = "2026-01-01T00:00:00Z"
    session.flaws.package_versions.retrieve.return_value = current

    updated = MagicMock()
    updated.to_dict.return_value = {
        "uuid": "pkg-uuid-1",
        "package": "kernel",
        "versions": [{"version": "5.15"}],
    }
    session.flaws.package_versions.update.return_value = updated

    result = flaw_package_version_update(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        package_version_id="pkg-uuid-1",
        versions=[{"version": "5.15"}],
    )

    assert result["ok"] is True
    assert result["package_version"]["versions"][0]["version"] == "5.15"
    session.flaws.package_versions.retrieve.assert_called_once()
    session.flaws.package_versions.update.assert_called_once()


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_package_version_update_invalid_flaw_id(mock_get_session: MagicMock) -> None:
    result = flaw_package_version_update(
        flaw_id="not-a-uuid",
        package_version_id="pkg-uuid-1",
    )
    assert result["ok"] is False
    assert result["error"] == "bad_request"


# ---------------------------------------------------------------------------
# flaw_package_version_remove
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_package_version_remove_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    result = flaw_package_version_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        package_version_id="pkg-uuid-1",
    )

    assert result["ok"] is True
    assert result["deleted"] == "pkg-uuid-1"
    session.flaws.package_versions.delete.assert_called_once_with(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        id="pkg-uuid-1",
    )


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_package_version_remove_invalid_flaw_id(mock_get_session: MagicMock) -> None:
    result = flaw_package_version_remove(
        flaw_id="CVE-2024-1234",
        package_version_id="pkg-uuid-1",
    )
    assert result["ok"] is False
    assert result["error"] == "bad_request"


@patch("osidb_mcp.tools_write.get_session")
def test_flaw_package_version_remove_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.flaws.package_versions.delete.side_effect = requests.HTTPError(response=resp)

    result = flaw_package_version_remove(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        package_version_id="pkg-uuid-1",
    )

    assert result["ok"] is False
    assert result["status_code"] == 404


# ---------------------------------------------------------------------------
# affect_cvss_score_add
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_affect_cvss_score_add_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    affect = MagicMock()
    affect.embargoed = False
    session.affects.retrieve.return_value = affect

    score_result = MagicMock()
    score_result.to_dict.return_value = {
        "uuid": "score-1",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "score": 9.8,
        "cvss_version": "V3",
        "issuer": "RH",
    }
    session.affects.cvss_scores.create.return_value = score_result

    result = affect_cvss_score_add(
        affect_id="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )

    assert result["ok"] is True
    assert result["cvss_score"]["uuid"] == "score-1"
    session.affects.cvss_scores.create.assert_called_once()
    call_data = session.affects.cvss_scores.create.call_args[1]["form_data"]
    assert call_data["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert call_data["embargoed"] is False


@patch("osidb_mcp.tools_write.get_session")
def test_affect_cvss_score_add_explicit_embargoed(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    score_result = MagicMock()
    score_result.to_dict.return_value = {"uuid": "score-2", "cvss_version": "V3"}
    session.affects.cvss_scores.create.return_value = score_result

    result = affect_cvss_score_add(
        affect_id="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        embargoed=True,
    )

    assert result["ok"] is True
    session.affects.retrieve.assert_not_called()
    call_data = session.affects.cvss_scores.create.call_args[1]["form_data"]
    assert call_data["embargoed"] is True


@patch("osidb_mcp.tools_write.get_session")
def test_affect_cvss_score_add_invalid_affect_id(mock_get_session: MagicMock) -> None:
    result = affect_cvss_score_add(
        affect_id="not-a-uuid",
        vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    )
    assert result["ok"] is False
    assert result["error"] == "bad_request"


# ---------------------------------------------------------------------------
# affect_cvss_score_remove
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_affect_cvss_score_remove_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    result = affect_cvss_score_remove(
        affect_id="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_score_id="score-uuid-1",
    )

    assert result["ok"] is True
    assert result["deleted"] == "score-uuid-1"
    session.affects.cvss_scores.delete.assert_called_once_with(
        affect_id="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        id="score-uuid-1",
    )


@patch("osidb_mcp.tools_write.get_session")
def test_affect_cvss_score_remove_invalid_affect_id(mock_get_session: MagicMock) -> None:
    result = affect_cvss_score_remove(
        affect_id="not-a-uuid",
        cvss_score_id="score-uuid-1",
    )
    assert result["ok"] is False
    assert result["error"] == "bad_request"


@patch("osidb_mcp.tools_write.get_session")
def test_affect_cvss_score_remove_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.affects.cvss_scores.delete.side_effect = requests.HTTPError(response=resp)

    result = affect_cvss_score_remove(
        affect_id="bbb58a80-dd9c-43dd-ba19-61fa88a66714",
        cvss_score_id="score-uuid-1",
    )

    assert result["ok"] is False
    assert result["status_code"] == 404


# ---------------------------------------------------------------------------
# tracker_update
# ---------------------------------------------------------------------------


@patch("osidb_mcp.tools_write.get_session")
def test_tracker_update_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    current = MagicMock()
    current.to_dict.return_value = {
        "uuid": "trk-1",
        "type": "JIRA",
        "affects": ["affect-uuid-1"],
        "ps_update_stream": "rhel-9.4.0.z",
        "updated_dt": "2026-01-01T00:00:00Z",
    }
    session.trackers.retrieve.return_value = current

    updated = MagicMock()
    updated.to_dict.return_value = {
        "uuid": "trk-1",
        "type": "JIRA",
        "affects": ["affect-uuid-1", "affect-uuid-2"],
        "ps_update_stream": "rhel-9.4.0.z",
    }
    session.trackers.update.return_value = updated

    result = tracker_update(
        tracker_id="trk-1",
        fields={"affects": ["affect-uuid-1", "affect-uuid-2"]},
    )

    assert result["ok"] is True
    assert result["tracker"]["affects"] == ["affect-uuid-1", "affect-uuid-2"]
    session.trackers.retrieve.assert_called_once_with("trk-1")
    call_data = session.trackers.update.call_args[1]["form_data"]
    assert "affect-uuid-2" in call_data["affects"]


@patch("osidb_mcp.tools_write.get_session")
def test_tracker_update_retrieve_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 404
    resp.text = "Not found"
    session.trackers.retrieve.side_effect = requests.HTTPError(response=resp)

    result = tracker_update(tracker_id="trk-bad", fields={"affects": []})

    assert result["ok"] is False
    assert result["status_code"] == 404


@patch("osidb_mcp.tools_write.get_session")
def test_tracker_update_update_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value

    current = MagicMock()
    current.to_dict.return_value = {"uuid": "trk-1", "updated_dt": "2026-01-01T00:00:00Z"}
    session.trackers.retrieve.return_value = current

    resp = MagicMock()
    resp.status_code = 409
    resp.text = "Conflict"
    session.trackers.update.side_effect = requests.HTTPError(response=resp)

    result = tracker_update(tracker_id="trk-1", fields={"affects": []})

    assert result["ok"] is False
    assert result["status_code"] == 409
