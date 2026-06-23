"""MCP tool implementations for OSIDB flaw workflow state transitions."""

from __future__ import annotations

import importlib
from typing import Any

from osidb_mcp.errors import error_response
from osidb_mcp.serialize import to_jsonable
from osidb_mcp.session_holder import get_session


def flaw_promote(flaw_id: str) -> dict[str, Any]:
    """Promote a flaw to the next workflow state.

    Advances the flaw one step forward in the workflow:
    NEW -> TRIAGE -> PRE_SECONDARY_ASSESSMENT -> SECONDARY_ASSESSMENT -> DONE.

    Each transition has prerequisites (e.g. owner assigned, title set,
    trackers filed). OSIDB returns 400 if requirements are not met.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    session = get_session()
    try:
        result = session.flaws.promote(flaw_id)  # ty:ignore[unresolved-attribute]
        return {"ok": True, "classification": to_jsonable(result)}
    except Exception as exc:
        return error_response(exc)


def flaw_reject(flaw_id: str, reason: str) -> dict[str, Any]:
    """Reject a flaw (move to REJECTED state).

    Only flaws in NEW or TRIAGE state can be rejected.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).
        reason: Explanation for the rejection (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    session = get_session()
    try:
        result = session.flaws.reject(flaw_id, {"reason": reason})  # ty:ignore[unresolved-attribute]
        return {"ok": True, "classification": to_jsonable(result)}
    except Exception as exc:
        return error_response(exc)


def flaw_reset(flaw_id: str) -> dict[str, Any]:
    """Reset a flaw back to NEW state.

    Can be called from NEW, TRIAGE, or DONE states.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    session = get_session()
    try:
        result = session.flaws.reset(flaw_id)  # ty:ignore[unresolved-attribute]
        return {"ok": True, "classification": to_jsonable(result)}
    except Exception as exc:
        return error_response(exc)


def flaw_revert(flaw_id: str) -> dict[str, Any]:
    """Revert a flaw to the previous workflow state.

    Moves the flaw one step backward:
    DONE -> SECONDARY_ASSESSMENT -> PRE_SECONDARY_ASSESSMENT -> TRIAGE -> NEW.

    Cannot revert from NEW (already initial state).

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (new workflow state info).
    """
    session = get_session()
    try:
        result = session.flaws.revert(flaw_id)  # ty:ignore[unresolved-attribute]
        return {"ok": True, "classification": to_jsonable(result)}
    except Exception as exc:
        return error_response(exc)


def workflow_adjust(flaw_id: str) -> dict[str, Any]:
    """Force recalculation of a flaw's workflow classification.

    POST /workflows/api/v1/workflows/{id}/adjust -- useful after external
    changes that might have changed the flaw's applicable workflow.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).

    Returns:
        JSON dict with ``ok``, ``classification`` (recalculated workflow info).
    """
    try:
        client = get_session().get_client_with_new_access_token()
        mod = importlib.import_module(
            "osidb_bindings.bindings.python_client.api.workflows."
            "workflows_api_v1_workflows_adjust_create"
        )
        r = mod.sync_detailed(flaw_id, client=client)
        if r.parsed is None:
            return {"ok": False, "error": "empty_response", "status_code": int(r.status_code)}
        return {"ok": True, "classification": to_jsonable(r.parsed.to_dict())}
    except Exception as exc:
        return error_response(exc)
