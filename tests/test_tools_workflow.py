"""Unit tests for workflow tools (no live OSIDB)."""

from unittest.mock import MagicMock, patch

import requests

from osidb_mcp.tools_workflow import (
    flaw_promote,
    flaw_reject,
    flaw_reset,
    flaw_revert,
)


def _classification_response(state: str = "TRIAGE"):
    return {"state": state, "workflow": "DEFAULT"}


# ---------------------------------------------------------------------------
# flaw_promote tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_promote_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.promote.return_value = _classification_response("TRIAGE")

    result = flaw_promote(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is True
    assert result["classification"]["state"] == "TRIAGE"
    session.flaws.promote.assert_called_once_with("aaa58a80-dd9c-43dd-ba19-61fa88a66714")


@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_promote_missing_requirements(mock_get_session: MagicMock) -> None:
    """Promote fails when prerequisites are not met (e.g. no owner)."""
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Flaw has no owner"}'
    session.flaws.promote.side_effect = requests.HTTPError(response=resp)

    result = flaw_promote(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 400


# ---------------------------------------------------------------------------
# flaw_reject tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reject_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.reject.return_value = _classification_response("REJECTED")

    result = flaw_reject(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        reason="Not a valid vulnerability",
    )

    assert result["ok"] is True
    assert result["classification"]["state"] == "REJECTED"
    session.flaws.reject.assert_called_once_with(
        "aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        {"reason": "Not a valid vulnerability"},
    )


@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reject_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Cannot reject from DONE state"}'
    session.flaws.reject.side_effect = requests.HTTPError(response=resp)

    result = flaw_reject(
        flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714",
        reason="Invalid",
    )

    assert result["ok"] is False
    assert result["status_code"] == 400


# ---------------------------------------------------------------------------
# flaw_reset tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reset_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.reset.return_value = _classification_response("NEW")

    result = flaw_reset(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is True
    assert result["classification"]["state"] == "NEW"
    session.flaws.reset.assert_called_once_with("aaa58a80-dd9c-43dd-ba19-61fa88a66714")


@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_reset_http_error(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.reset.side_effect = requests.ConnectionError("timeout")

    result = flaw_reset(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is False


# ---------------------------------------------------------------------------
# flaw_revert tests
# ---------------------------------------------------------------------------

@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_revert_success(mock_get_session: MagicMock) -> None:
    session = mock_get_session.return_value
    session.flaws.revert.return_value = _classification_response("TRIAGE")

    result = flaw_revert(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is True
    assert result["classification"]["state"] == "TRIAGE"
    session.flaws.revert.assert_called_once_with("aaa58a80-dd9c-43dd-ba19-61fa88a66714")


@patch("osidb_mcp.tools_workflow.get_session")
def test_flaw_revert_already_initial_state(mock_get_session: MagicMock) -> None:
    """Revert from NEW fails since there is no previous state."""
    session = mock_get_session.return_value
    resp = MagicMock()
    resp.status_code = 400
    resp.text = '{"detail": "Cannot revert from initial state"}'
    session.flaws.revert.side_effect = requests.HTTPError(response=resp)

    result = flaw_revert(flaw_id="aaa58a80-dd9c-43dd-ba19-61fa88a66714")

    assert result["ok"] is False
    assert result["error"] == "osidb_http_error"
    assert result["status_code"] == 400
