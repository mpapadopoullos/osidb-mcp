"""Unit tests for write tools (no live OSIDB)."""

from unittest.mock import MagicMock, patch

import requests

from osidb_mcp.tools_write import (
    affect_add,
    affect_remove,
    affect_update,
    flaw_acknowledgment_add,
    flaw_acknowledgment_remove,
    flaw_create,
    flaw_cvss_add,
    flaw_cvss_remove,
    flaw_reference_add,
    flaw_reference_remove,
    flaw_update,
    tracker_file,
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
    session.flaws.create.assert_called_once_with({
        "title": "Test flaw",
        "comment_zero": "Description",
        "embargoed": True,
    })


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
        references=[{"url": "https://example.com/issue/5104", "description": "Upstream issue", "type": "UPSTREAM"}],
        cvss_scores=[{"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H", "issuer": "RH"}],
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
            {"cvss_version": "V4", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N"},
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
    affect_result = _mock_subresource("affect-uuid-1")
    session.affects.create.return_value = affect_result

    result = affect_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        affects=[{"ps_update_stream": "rhel-9.4", "affectedness": "AFFECTED"}],
    )

    assert result["ok"] is True
    assert len(result["created"]) == 1
    assert "partial" not in result

    create_data = session.affects.create.call_args[0][0]
    assert create_data["flaw"] == "aaa58a80-dd9c-43dd-ba19-61fa88a66714"
    assert create_data["embargoed"] is True


@patch("osidb_mcp.tools_write.get_session")
def test_affect_add_partial_failure(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.retrieve.return_value = _mock_flaw_full()
    session.affects.create.side_effect = [
        _mock_subresource("a1"),
        requests.ConnectionError("fail"),
    ]

    result = affect_add(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        affects=[
            {"ps_update_stream": "rhel-9.4"},
            {"ps_update_stream": "rhel-8.10"},
        ],
    )

    assert result["ok"] is True
    assert result["partial"] is True
    assert len(result["created"]) == 1
    assert len(result["errors"]) == 1


# ---------------------------------------------------------------------------
# affect_remove tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_write.get_session")
def test_affect_remove_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.delete.return_value = None

    result = affect_remove(affect_uuids=["uuid-1", "uuid-2"])

    assert result["ok"] is True
    assert result["deleted"] == ["uuid-1", "uuid-2"]
    assert "partial" not in result
    assert session.affects.delete.call_count == 2


@patch("osidb_mcp.tools_write.get_session")
def test_affect_remove_partial_failure(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.affects.delete.side_effect = [None, requests.ConnectionError("fail")]

    result = affect_remove(affect_uuids=["uuid-1", "uuid-2"])

    assert result["ok"] is True
    assert result["partial"] is True
    assert result["deleted"] == ["uuid-1"]
    assert len(result["errors"]) == 1


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
def test_tracker_file_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    tracker_result = MagicMock()
    tracker_result.to_dict.return_value = {
        "trackers": [{"uuid": "trk-1", "type": "JIRA"}],
    }
    session.trackers.file.return_value = tracker_result

    result = tracker_file(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        affect_uuids=["bbb58a80-dd9c-43dd-ba19-61fa88a66714"],
    )

    assert result["ok"] is True
    session.trackers.file.assert_called_once_with({
        "flaw_uuids": ["aaa58a80-dd9c-43dd-ba19-61fa88a66714"],
        "affect_uuids": ["bbb58a80-dd9c-43dd-ba19-61fa88a66714"],
    })


@patch("osidb_mcp.tools_write.get_session")
def test_tracker_file_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Invalid affect UUID"}'
    session.trackers.file.side_effect = requests.HTTPError(response=resp)

    result = tracker_file(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        affect_uuids=["bad-uuid"],
    )

    assert result["ok"] is False
    assert result["status_code"] == 400


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
        cvss_scores=[{"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"}],
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
            {"cvss_version": "V4", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N"},
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
        cvss_scores=[{"cvss_version": "V3", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"}],
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
            {"cvss_version": "V4", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:H/SC:N/SI:N/SA:N"},
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
