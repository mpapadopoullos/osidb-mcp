"""Unit tests for write tools (no live OSIDB)."""

from unittest.mock import MagicMock, patch

import requests

from osidb_mcp.tools_write import (
    affect_add,
    affect_remove,
    affect_update,
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
    flaw_reference_add,
    flaw_reference_remove,
    flaw_reference_update,
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


@patch("osidb_mcp.tools_write.requests.put")
@patch("osidb_mcp.tools_write.requests.get")
@patch("osidb_mcp.tools_write.get_session")
def test_flaw_update_single_field(mock_get_session: MagicMock, mock_get: MagicMock, mock_put: MagicMock) -> None:
    client = mock_get_session.return_value.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {"Authorization": "Bearer tok"}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    get_resp = MagicMock()
    get_resp.json.return_value = {
        "title": "Original title", "comment_zero": "desc", "embargoed": True,
        "impact": "MODERATE", "components": ["kernel"], "cve_id": "CVE-2026-52719",
        "cve_description": "", "statement": "", "cwe_id": "CWE-125",
        "source": "RESEARCHER", "reported_dt": "2026-05-19T00:00:00Z",
        "unembargo_dt": None, "mitigation": "", "owner": None,
        "updated_dt": "2026-06-08T12:00:00Z",
    }
    get_resp.raise_for_status.return_value = None
    mock_get.return_value = get_resp

    put_resp = MagicMock()
    put_resp.json.return_value = {"uuid": "aaa58a80-dd9c-43dd-ba19-61fa88a66714", "impact": "IMPORTANT"}
    put_resp.raise_for_status.return_value = None
    mock_put.return_value = put_resp

    result = flaw_update(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714", impact="IMPORTANT")

    assert result["ok"] is True
    mock_put.assert_called_once()
    put_data = mock_put.call_args[1]["json"]
    assert put_data["impact"] == "IMPORTANT"
    assert put_data["title"] == "Original title"
    assert put_data["updated_dt"] == "2026-06-08T12:00:00Z"


@patch("osidb_mcp.tools_write.requests.get")
@patch("osidb_mcp.tools_write.get_session")
def test_flaw_update_retrieve_fails(mock_get_session: MagicMock, mock_get: MagicMock) -> None:
    client = mock_get_session.return_value.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    mock_get.side_effect = requests.ConnectionError("timeout")

    result = flaw_update(flaw_id="bad-uuid", title="New title")

    assert result["ok"] is False


@patch("osidb_mcp.tools_write.requests.put")
@patch("osidb_mcp.tools_write.requests.get")
@patch("osidb_mcp.tools_write.get_session")
def test_flaw_update_put_fails(mock_get_session: MagicMock, mock_get: MagicMock, mock_put: MagicMock) -> None:
    client = mock_get_session.return_value.get_client_with_new_access_token.return_value
    client.base_url = "https://osidb.example.com"
    client.get_headers.return_value = {"Authorization": "Bearer tok"}
    client.verify_ssl = True
    client.get_auth.return_value = None
    client.get_timeout.return_value = 300.0

    get_resp = MagicMock()
    get_resp.json.return_value = {
        "title": "Original", "comment_zero": "desc", "embargoed": True,
        "impact": "MODERATE", "components": [], "cve_id": None,
        "cve_description": None, "statement": "", "cwe_id": None,
        "source": None, "reported_dt": None, "unembargo_dt": None,
        "mitigation": None, "owner": None,
        "updated_dt": "2026-06-08T12:00:00Z",
    }
    get_resp.raise_for_status.return_value = None
    mock_get.return_value = get_resp

    resp_409 = MagicMock()
    resp_409.status_code = 409
    resp_409.text = "Conflict"
    mock_put.side_effect = requests.HTTPError(response=resp_409)

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
        {"text": "Note with creator", "embargoed": False, "is_private": False, "creator": "jdoe@redhat.com"},
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
# flaw_label_add / flaw_label_remove tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_write.get_session")
def test_label_add_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
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
    session = mock_get_session.return_value
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
    session = mock_get_session.return_value
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

@patch("osidb_mcp.tools_write.get_session")
def test_cvss_update_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    current = MagicMock()
    current.vector = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H"
    current.comment = ""
    current.cvss_version = "V3"
    current.issuer = "RH"
    current.embargoed = False
    current.updated_dt = "2026-06-08T12:00:00Z"
    session.flaws.cvss_scores.retrieve.return_value = current
    updated = _mock_subresource("cvss-1")
    session.flaws.cvss_scores.update.return_value = updated

    result = flaw_cvss_update(
        flaw_id="CVE-2026-52719",
        cvss_score_id="cvss-1",
        vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H",
    )

    assert result["ok"] is True
    update_data = session.flaws.cvss_scores.update.call_args[0][2]
    assert update_data["vector"] == "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:H"


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

    result = affects_bulk_create(affects=[
        {"flaw": "f1", "ps_module": "m", "ps_component": "c", "affectedness": "NEW", "embargoed": False},
        {"flaw": "f1", "ps_module": "m2", "ps_component": "c2", "affectedness": "NEW", "embargoed": False},
    ])

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

    result = affects_bulk_update(affects=[
        {"uuid": "a1", "updated_dt": "2026-06-08T12:00:00Z", "affectedness": "AFFECTED"},
    ])

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
