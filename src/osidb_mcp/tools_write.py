"""MCP tool implementations (write / mutation OSIDB operations)."""

from __future__ import annotations

import importlib
from typing import Any
from uuid import UUID

import requests

from osidb_mcp.errors import http_error_payload
from osidb_mcp.serialize import to_jsonable
from osidb_mcp.session_holder import current_settings, get_session

_FLAW_FIELDS = (
    "title", "comment_zero", "embargoed", "cve_id", "impact", "components",
    "cve_description", "statement", "cwe_id", "source", "reported_dt",
    "unembargo_dt", "mitigation", "owner",
)

_AFFECT_FIELDS = (
    "affectedness", "resolution", "impact", "ps_component", "ps_module",
    "ps_update_stream", "purl", "delegated_resolution",
)


def _error_response(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, requests.RequestException):
        return {"ok": False, **http_error_payload(exc)}
    return {"ok": False, "error": "osidb_error", "detail": str(exc)}


def _create_subresources(
    resource_group: Any,
    flaw_id: str,
    items: list[dict[str, Any]],
    embargoed: bool,
    label: str,
    *,
    api_version: str | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Create sub-resources sequentially, collecting successes and errors."""
    created: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []
    for i, item in enumerate(items):
        item["embargoed"] = embargoed
        try:
            kwargs: dict[str, Any] = {}
            if api_version is not None:
                kwargs["api_version"] = api_version
            result = resource_group.create(item, flaw_id, **kwargs)
            created.append(to_jsonable(result))
        except (requests.RequestException, Exception) as exc:
            detail = http_error_payload(exc) if isinstance(exc, requests.RequestException) else str(exc)
            errors.append({"index": i, label: item, "error": detail})
    return created, errors


def flaw_create(
    title: str,
    comment_zero: str,
    embargoed: bool,
    cve_id: str | None = None,
    impact: str | None = None,
    components: list[str] | None = None,
    cve_description: str | None = None,
    statement: str | None = None,
    cwe_id: str | None = None,
    source: str | None = None,
    reported_dt: str | None = None,
    unembargo_dt: str | None = None,
    mitigation: str | None = None,
    acknowledgments: list[dict[str, Any]] | None = None,
    references: list[dict[str, Any]] | None = None,
    cvss_scores: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Create a new OSIDB flaw with optional sub-resources.

    Creates the flaw via POST /osidb/api/v2/flaws, then sequentially creates
    acknowledgments (v1), references (v1), and CVSS scores (v1) as sub-resources.

    Args:
        title: Flaw title (required).
        comment_zero: Initial comment / description (required).
        embargoed: Embargo status (required).
        cve_id: CVE identifier if already assigned.
        impact: Severity: CRITICAL, IMPORTANT, MODERATE, or LOW.
        components: Flaw-level component names (e.g. ["kernel"]).
        cve_description: Public CVE description text.
        statement: Red Hat impact statement.
        cwe_id: CWE identifier (e.g. "CWE-125").
        source: Report source: RESEARCHER, CUSTOMER, UPSTREAM, etc.
        reported_dt: Date reported (ISO 8601, e.g. "2026-05-19T00:00:00Z").
        unembargo_dt: Planned unembargo date (ISO 8601).
        mitigation: Mitigation advice text.
        acknowledgments: List of dicts, each with ``name`` (str), optional ``affiliation`` (str),
            optional ``from_upstream`` (bool, default false).
        references: List of dicts, each with ``url`` (str), optional ``description`` (str),
            optional ``type`` (ARTICLE, UPSTREAM, or EXTERNAL).
        cvss_scores: List of dicts, each with ``cvss_version`` (V3 or V4), ``vector`` (str),
            optional ``comment`` (str), optional ``issuer`` (str, default RH).

    Returns:
        JSON dict with ``ok``, ``flaw_uuid``, and created sub-resource details.
        On partial failure: ``partial: true`` with errors for failed sub-resources.
    """
    session = get_session()

    flaw_data: dict[str, Any] = {
        "title": title,
        "comment_zero": comment_zero,
        "embargoed": embargoed,
    }
    if cve_id is not None:
        flaw_data["cve_id"] = cve_id
    if impact is not None:
        flaw_data["impact"] = impact
    if components is not None:
        flaw_data["components"] = components
    if cve_description is not None:
        flaw_data["cve_description"] = cve_description
    if statement is not None:
        flaw_data["statement"] = statement
    if cwe_id is not None:
        flaw_data["cwe_id"] = cwe_id
    if source is not None:
        flaw_data["source"] = source
    if reported_dt is not None:
        flaw_data["reported_dt"] = reported_dt
    if unembargo_dt is not None:
        flaw_data["unembargo_dt"] = unembargo_dt
    if mitigation is not None:
        flaw_data["mitigation"] = mitigation

    try:
        flaw = session.flaws.create(flaw_data)
    except requests.RequestException as exc:
        return {"ok": False, **http_error_payload(exc)}
    except Exception as exc:
        return {"ok": False, "error": "flaw_create_failed", "detail": str(exc)}

    flaw_uuid = str(getattr(flaw, "uuid", ""))
    flaw_cve = getattr(flaw, "cve_id", cve_id) or ""

    result: dict[str, Any] = {
        "ok": True,
        "flaw_uuid": flaw_uuid,
        "cve_id": flaw_cve,
    }

    all_errors: list[dict[str, Any]] = []

    if acknowledgments:
        created, errors = _create_subresources(
            session.flaws.acknowledgments,
            flaw_uuid,
            acknowledgments,
            embargoed,
            "acknowledgment",
        )
        result["acknowledgments"] = created
        all_errors.extend(errors)

    if references:
        created, errors = _create_subresources(
            session.flaws.references,
            flaw_uuid,
            references,
            embargoed,
            "reference",
        )
        result["references"] = created
        all_errors.extend(errors)

    if cvss_scores:
        created, errors = _create_subresources(
            session.flaws.cvss_scores,
            flaw_uuid,
            cvss_scores,
            embargoed,
            "cvss_score",
            api_version="v1",
        )
        result["cvss_scores"] = created
        all_errors.extend(errors)

    if all_errors:
        result["partial"] = True
        result["errors"] = all_errors

    return result


# ---------------------------------------------------------------------------
# flaw_update
# ---------------------------------------------------------------------------

def flaw_update(
    flaw_id: str,
    title: str | None = None,
    comment_zero: str | None = None,
    embargoed: bool | None = None,
    cve_id: str | None = None,
    impact: str | None = None,
    components: list[str] | None = None,
    cve_description: str | None = None,
    statement: str | None = None,
    cwe_id: str | None = None,
    source: str | None = None,
    reported_dt: str | None = None,
    unembargo_dt: str | None = None,
    mitigation: str | None = None,
    owner: str | None = None,
) -> dict[str, Any]:
    """Update an existing OSIDB flaw (PUT /osidb/api/v2/flaws/{id}).

    Retrieves the current flaw first to obtain ``updated_dt`` (optimistic
    concurrency) and current field values, then merges caller-provided fields
    over the existing data before issuing the PUT.

    Args:
        flaw_id: Flaw CVE id or internal UUID (required).
        title: Flaw title.
        comment_zero: Initial comment / description.
        embargoed: Embargo status.
        cve_id: CVE identifier.
        impact: Severity (CRITICAL, IMPORTANT, MODERATE, LOW).
        components: Flaw-level component names.
        cve_description: Public CVE description.
        statement: Red Hat impact statement.
        cwe_id: CWE identifier.
        source: Report source.
        reported_dt: Date reported (ISO 8601).
        unembargo_dt: Planned unembargo date (ISO 8601).
        mitigation: Mitigation advice.
        owner: Flaw owner (Jira username for assignment).
    """
    session = get_session()

    try:
        current = session.flaws.retrieve(flaw_id)
    except Exception as exc:
        return _error_response(exc)

    flaw_data: dict[str, Any] = {}
    for field in _FLAW_FIELDS:
        current_val = getattr(current, field, None)
        if current_val is not None:
            flaw_data[field] = to_jsonable(current_val)

    overrides = {
        "title": title, "comment_zero": comment_zero, "embargoed": embargoed,
        "cve_id": cve_id, "impact": impact, "components": components,
        "cve_description": cve_description, "statement": statement,
        "cwe_id": cwe_id, "source": source, "reported_dt": reported_dt,
        "unembargo_dt": unembargo_dt, "mitigation": mitigation,
        "owner": owner,
    }
    for k, v in overrides.items():
        if v is not None:
            flaw_data[k] = v

    flaw_data["updated_dt"] = to_jsonable(getattr(current, "updated_dt", None))

    try:
        result = session.flaws.update(flaw_id, flaw_data)
        return {"ok": True, "flaw": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# affect_add / affect_remove
# ---------------------------------------------------------------------------

def affect_add(
    flaw_id: str,
    affects: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add one or more affects to an existing flaw.

    Delegates to ``affects_bulk_create`` (POST /osidb/api/v2/affects/bulk),
    which matches OSIM's actual pattern.  Auto-sets ``flaw`` and ``embargoed``
    on each affect if not already present.

    Args:
        flaw_id: Flaw UUID (required). Must be the internal UUID, not a CVE id.
        affects: List of affect dicts, each with ``ps_update_stream`` (required),
            optional ``affectedness``, ``resolution``, ``ps_component``, ``impact``,
            ``embargoed``.
    """
    session = get_session()

    try:
        flaw = session.flaws.retrieve(flaw_id, include_fields="embargoed")
        flaw_embargoed = getattr(flaw, "embargoed", False)
    except Exception as exc:
        return _error_response(exc)

    for affect in affects:
        affect["flaw"] = flaw_id
        if "embargoed" not in affect:
            affect["embargoed"] = flaw_embargoed

    return affects_bulk_create(affects)


def affect_remove(
    affect_uuids: list[str],
) -> dict[str, Any]:
    """Remove one or more affects by UUID.

    Delegates to ``affects_bulk_delete`` (DELETE /osidb/api/v2/affects/bulk),
    which matches OSIM's actual pattern.

    Args:
        affect_uuids: List of affect UUID strings to delete.
    """
    return affects_bulk_delete(affect_uuids)


# ---------------------------------------------------------------------------
# flaw_acknowledgment_add / flaw_acknowledgment_remove
# ---------------------------------------------------------------------------

def flaw_acknowledgment_add(
    flaw_id: str,
    acknowledgments: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add acknowledgment(s) to an existing flaw.

    Args:
        flaw_id: Flaw UUID or CVE id (required).
        acknowledgments: List of dicts, each with ``name`` (str),
            optional ``affiliation`` (str), ``from_upstream`` (bool),
            ``embargoed`` (bool).
    """
    session = get_session()

    try:
        flaw = session.flaws.retrieve(flaw_id, include_fields="embargoed")
        flaw_embargoed = getattr(flaw, "embargoed", False)
    except Exception as exc:
        return _error_response(exc)

    created, errors = _create_subresources(
        session.flaws.acknowledgments,
        flaw_id,
        acknowledgments,
        flaw_embargoed,
        "acknowledgment",
    )
    out: dict[str, Any] = {"ok": True, "created": created}
    if errors:
        out["partial"] = True
        out["errors"] = errors
    return out


def flaw_acknowledgment_remove(
    flaw_id: str,
    acknowledgment_id: str,
) -> dict[str, Any]:
    """Remove an acknowledgment from a flaw.

    Args:
        flaw_id: Flaw UUID or CVE id.
        acknowledgment_id: Acknowledgment UUID to delete.
    """
    session = get_session()
    try:
        session.flaws.acknowledgments.delete(flaw_id, acknowledgment_id)
        return {"ok": True, "deleted": acknowledgment_id}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_reference_add / flaw_reference_remove
# ---------------------------------------------------------------------------

def flaw_reference_add(
    flaw_id: str,
    references: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add reference(s) to an existing flaw.

    Args:
        flaw_id: Flaw UUID or CVE id (required).
        references: List of dicts, each with ``url`` (str, required),
            optional ``description`` (str), ``type`` (ARTICLE, UPSTREAM, EXTERNAL),
            ``embargoed`` (bool).
    """
    session = get_session()

    try:
        flaw = session.flaws.retrieve(flaw_id, include_fields="embargoed")
        flaw_embargoed = getattr(flaw, "embargoed", False)
    except Exception as exc:
        return _error_response(exc)

    created, errors = _create_subresources(
        session.flaws.references,
        flaw_id,
        references,
        flaw_embargoed,
        "reference",
    )
    out: dict[str, Any] = {"ok": True, "created": created}
    if errors:
        out["partial"] = True
        out["errors"] = errors
    return out


def flaw_reference_remove(
    flaw_id: str,
    reference_id: str,
) -> dict[str, Any]:
    """Remove a reference from a flaw.

    Args:
        flaw_id: Flaw UUID or CVE id.
        reference_id: Reference UUID to delete.
    """
    session = get_session()
    try:
        session.flaws.references.delete(flaw_id, reference_id)
        return {"ok": True, "deleted": reference_id}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_cvss_add / flaw_cvss_remove
# ---------------------------------------------------------------------------

def flaw_cvss_add(
    flaw_id: str,
    cvss_scores: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add CVSS score(s) to an existing flaw.

    Args:
        flaw_id: Flaw UUID or CVE id (required).
        cvss_scores: List of dicts, each with ``cvss_version`` (V3 or V4),
            ``vector`` (str, required), optional ``comment`` (str),
            optional ``issuer`` (str, default RH).
    """
    session = get_session()

    try:
        flaw = session.flaws.retrieve(flaw_id, include_fields="embargoed")
        flaw_embargoed = getattr(flaw, "embargoed", False)
    except Exception as exc:
        return _error_response(exc)

    created, errors = _create_subresources(
        session.flaws.cvss_scores,
        flaw_id,
        cvss_scores,
        flaw_embargoed,
        "cvss_score",
        api_version="v1",
    )
    out: dict[str, Any] = {"ok": True, "created": created}
    if errors:
        out["partial"] = True
        out["errors"] = errors
    return out


def flaw_cvss_remove(
    flaw_id: str,
    cvss_score_id: str,
) -> dict[str, Any]:
    """Remove a CVSS score from a flaw.

    Args:
        flaw_id: Flaw UUID or CVE id.
        cvss_score_id: CVSS score UUID to delete.
    """
    session = get_session()
    try:
        session.flaws.cvss_scores.delete(flaw_id, cvss_score_id, api_version="v1")
        return {"ok": True, "deleted": cvss_score_id}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# affect_update
# ---------------------------------------------------------------------------

def affect_update(
    affect_uuid: str,
    affectedness: str | None = None,
    resolution: str | None = None,
    impact: str | None = None,
    ps_component: str | None = None,
    purl: str | None = None,
    delegated_resolution: str | None = None,
) -> dict[str, Any]:
    """Update an existing affect (PUT /osidb/api/v2/affects/{uuid}).

    Retrieves the current affect first to obtain ``updated_dt`` (optimistic
    concurrency) and current field values, then merges caller-provided fields
    over the existing data before issuing the PUT.

    Args:
        affect_uuid: Affect UUID (required).
        affectedness: AFFECTED, NOT_AFFECTED, or NEW.
        resolution: FIX, DEFER, WONTFIX, OOSS, DELEGATED, or empty.
        impact: Override severity for this specific affect.
        ps_component: Product stream component name.
        purl: Package URL string.
        delegated_resolution: Delegated resolution value.
    """
    session = get_session()

    try:
        current = session.affects.retrieve(affect_uuid)
    except Exception as exc:
        return _error_response(exc)

    affect_data: dict[str, Any] = {}
    for field in _AFFECT_FIELDS:
        current_val = getattr(current, field, None)
        if current_val is not None:
            affect_data[field] = to_jsonable(current_val)

    overrides = {
        "affectedness": affectedness,
        "resolution": resolution,
        "impact": impact,
        "ps_component": ps_component,
        "purl": purl,
        "delegated_resolution": delegated_resolution,
    }
    for k, v in overrides.items():
        if v is not None:
            affect_data[k] = v

    affect_data["updated_dt"] = to_jsonable(getattr(current, "updated_dt", None))
    affect_data["flaw"] = to_jsonable(getattr(current, "flaw", None))
    affect_data["embargoed"] = getattr(current, "embargoed", False)

    try:
        result = session.affects.update(affect_uuid, affect_data)
        return {"ok": True, "affect": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# affect_update_bulk
# ---------------------------------------------------------------------------

def affect_update_bulk(
    affects: list[dict[str, Any]],
) -> dict[str, Any]:
    """Update multiple affects in one bulk call (PUT /osidb/api/v2/affects/bulk).

    Fetches all affects in a single list request via
    ``/osidb/api/v2/affects?uuid__in=...`` to obtain ``updated_dt`` for
    optimistic concurrency, merges caller-provided field overrides, then
    sends one bulk PUT.

    Args:
        affects: List of dicts, each with ``affect_uuid`` (required) plus any
                 fields to change: ``affectedness``, ``resolution``, ``impact``,
                 ``ps_component``, ``purl``, ``delegated_resolution``.
    """
    if not affects:
        return {"ok": True, "updated": [], "detail": "nothing to update"}

    fetch_errors: list[dict[str, Any]] = []
    valid_specs: list[dict[str, Any]] = []
    uuids: list[str] = []

    for spec in affects:
        affect_uuid = spec.get("affect_uuid")
        if not affect_uuid:
            fetch_errors.append({"affect_uuid": None, "error": "missing affect_uuid"})
        else:
            valid_specs.append(spec)
            uuids.append(affect_uuid)

    if not uuids:
        return {
            "ok": False,
            "error": "all_fetches_failed",
            "fetch_errors": fetch_errors,
        }

    session = get_session()

    try:
        list_resp = session.affects.retrieve_list(
            uuid__in=uuids, limit=len(uuids),
        )
    except Exception as exc:
        return _error_response(exc)

    fetched_by_uuid: dict[str, Any] = {}
    for affect_obj in list_resp.results:
        uid = str(getattr(affect_obj, "uuid", ""))
        if uid:
            fetched_by_uuid[uid] = affect_obj

    payloads: list[dict[str, Any]] = []
    for spec in valid_specs:
        affect_uuid = spec["affect_uuid"]
        current = fetched_by_uuid.get(affect_uuid)
        if current is None:
            fetch_errors.append({
                "affect_uuid": affect_uuid,
                "error": f"affect {affect_uuid} not found in list response",
            })
            continue

        affect_data: dict[str, Any] = {}
        for field in _AFFECT_FIELDS:
            current_val = getattr(current, field, None)
            if current_val is not None:
                affect_data[field] = to_jsonable(current_val)

        for k in ("affectedness", "resolution", "impact", "ps_component",
                   "purl", "delegated_resolution"):
            v = spec.get(k)
            if v is not None:
                affect_data[k] = v

        affect_data["uuid"] = affect_uuid
        affect_data["updated_dt"] = to_jsonable(getattr(current, "updated_dt", None))
        affect_data["flaw"] = to_jsonable(getattr(current, "flaw", None))
        affect_data["embargoed"] = getattr(current, "embargoed", False)

        payloads.append(affect_data)

    if not payloads:
        return {
            "ok": False,
            "error": "all_fetches_failed",
            "fetch_errors": fetch_errors,
        }

    try:
        result = session.affects.bulk_update(payloads)
        resp: dict[str, Any] = {"ok": True, "updated": to_jsonable(result)}
        if fetch_errors:
            resp["fetch_errors"] = fetch_errors
        return resp
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# tracker_create
# ---------------------------------------------------------------------------


def tracker_create(
    affect_uuids: list[str],
    ps_update_stream: str,
    embargoed: bool,
    *,
    sync_to_bz: bool = True,
) -> dict[str, Any]:
    """Create a tracker (Jira/Bugzilla ticket) for one or more affects.

    Calls POST /osidb/api/v2/trackers to create the actual tracker record
    and external ticket in Jira or Bugzilla (determined server-side by stream).

    Use ``tracker_suggestions`` first to identify valid streams and affects.

    Args:
        affect_uuids: List of affect UUIDs to attach to this tracker.
        ps_update_stream: Target update stream (e.g. "rhel-9.4.0.z").
        embargoed: Whether the flaw is embargoed (controls ACLs).
        sync_to_bz: Sync flaw to Bugzilla after creation (default True).
            Set False when batch-filing multiple trackers to avoid redundant
            BZ syncs; set True on the last call to trigger the final sync.

    Returns:
        JSON dict with created tracker details (uuid, type, external_system_id).
    """
    session = get_session()
    try:
        form_data: dict[str, Any] = {
            "affects": affect_uuids,
            "ps_update_stream": ps_update_stream,
            "embargoed": embargoed,
        }
        if not sync_to_bz:
            form_data["sync_to_bz"] = False

        result = session.trackers.create(form_data=form_data)
        return {"ok": True, "tracker": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# trackers_bulk_file
# ---------------------------------------------------------------------------


def trackers_bulk_file(
    flaw_id: str,
    *,
    only_selected: bool = True,
    exclude_existing_trackers: bool = True,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Bulk-file trackers for a flaw based on OSIDB suggestions.

    Two-step process:
    1. Get suggestions from POST /trackers/api/v2/file
    2. Create trackers for matching streams via POST /osidb/api/v2/trackers

    Uses sync_to_bz=false on all creations except the last to avoid redundant
    Bugzilla flaw syncs; the final creation triggers one sync for all.

    Args:
        flaw_id: Flaw UUID or CVE id.
        only_selected: If True (default), only file trackers for streams
            marked as 'selected' by OSIDB (acked, non-community, supported).
            If False, file for ALL available streams.
        exclude_existing_trackers: Skip streams that already have trackers.
        dry_run: If True, return what WOULD be filed without actually filing.

    Returns:
        JSON dict with filed trackers summary, successes, and failures.
    """
    session = get_session()

    try:
        suggestions = session.trackers.file(
            {"flaw_uuids": [flaw_id]},
            exclude_existing_trackers=exclude_existing_trackers,
        )
        suggestions_data = to_jsonable(suggestions)
    except Exception as exc:
        return _error_response(exc)

    streams = suggestions_data.get("streams_components", [])
    not_applicable = suggestions_data.get("not_applicable", [])

    if only_selected:
        to_file = [
            s for s in streams
            if s.get("selected") or (s.get("offer") or {}).get("selected")
        ]
    else:
        to_file = streams

    if not to_file:
        return {
            "ok": True,
            "filed": 0,
            "message": "No streams matched the filing criteria.",
            "not_applicable_count": len(not_applicable),
        }

    embargoed = (to_file[0].get("affect") or {}).get("embargoed", False)

    if dry_run:
        preview = [
            {
                "ps_update_stream": s.get("ps_update_stream"),
                "ps_component": s.get("ps_component"),
                "affect_uuid": (s.get("affect") or {}).get("uuid"),
                "selected": s.get("selected", False),
                "acked": (s.get("offer") or {}).get("acked", False),
            }
            for s in to_file
        ]
        return {
            "ok": True,
            "dry_run": True,
            "would_file": len(preview),
            "trackers": preview,
            "not_applicable_count": len(not_applicable),
        }

    successes: list[dict[str, Any]] = []
    failures: list[dict[str, Any]] = []

    for i, stream in enumerate(to_file):
        is_last = (i == len(to_file) - 1)
        affect_uuid = (stream.get("affect") or {}).get("uuid")
        if not affect_uuid:
            failures.append({
                "ps_update_stream": stream.get("ps_update_stream"),
                "ps_component": stream.get("ps_component"),
                "error": "Missing affect UUID in suggestion data",
            })
            continue

        form_data: dict[str, Any] = {
            "affects": [affect_uuid],
            "ps_update_stream": stream["ps_update_stream"],
            "embargoed": embargoed,
        }
        if not is_last:
            form_data["sync_to_bz"] = False

        try:
            result = session.trackers.create(form_data=form_data)
            successes.append({
                "ps_update_stream": stream.get("ps_update_stream"),
                "ps_component": stream.get("ps_component"),
                "tracker": to_jsonable(result),
            })
        except Exception as exc:
            failures.append({
                "ps_update_stream": stream.get("ps_update_stream"),
                "ps_component": stream.get("ps_component"),
                "error": str(exc),
            })

    return {
        "ok": len(failures) == 0,
        "filed": len(successes),
        "failed": len(failures),
        "successes": successes,
        "failures": failures if failures else None,
    }


# ---------------------------------------------------------------------------
# flaw_comment_create
# ---------------------------------------------------------------------------

def _post_jira_comment(task_key: str, text: str) -> dict[str, Any]:
    """Post a comment directly to a Jira issue via REST API v3."""
    settings = current_settings()

    missing: list[str] = []
    if not settings.jira_url:
        missing.append("JIRA_URL")
    if not settings.jira_access_token:
        missing.append("JIRA_ACCESS_TOKEN")
    if not settings.jira_api_email:
        missing.append("JIRA_API_EMAIL")
    if missing:
        return {
            "ok": False,
            "error": "jira_not_configured",
            "detail": f"Missing env vars: {', '.join(missing)}",
        }

    url = f"{settings.jira_url.rstrip('/')}/rest/api/3/issue/{task_key}/comment"
    body = {
        "body": {
            "type": "doc",
            "version": 1,
            "content": [
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": text}],
                }
            ],
        }
    }
    headers = {"Content-Type": "application/json"}
    auth = (settings.jira_api_email, settings.jira_access_token)

    try:
        import certifi

        ca_bundle = certifi.where()
    except ImportError:
        ca_bundle = True  # type: ignore[assignment]

    try:
        resp = requests.post(
            url, json=body, headers=headers, auth=auth, timeout=30, verify=ca_bundle
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            "ok": True,
            "jira_comment_id": data.get("id"),
            "jira_issue": task_key,
        }
    except Exception as exc:
        return _error_response(exc)


def flaw_comment_create(
    flaw_id: str,
    text: str,
    *,
    creator: str | None = None,
    is_private: bool = False,
    internal: bool = False,
) -> dict[str, Any]:
    """Create a comment on a flaw (POST /osidb/api/v1/flaws/{id}/comments).

    Auto-fetches the flaw's embargoed status to set the correct value on the
    comment payload.

    When ``internal=True``, the comment is posted directly to the flaw's Jira
    issue instead of going through the OSIDB/Bugzilla comment endpoint.
    Requires ``JIRA_URL``, ``JIRA_ACCESS_TOKEN``, and ``JIRA_API_EMAIL``
    env vars.

    Args:
        flaw_id: Flaw UUID or CVE id (required).
        text: Comment body text (required).
        creator: Comment author identifier (e.g. Jira username).
            If omitted, defaults to the authenticated user.
            Ignored when ``internal=True``.
        is_private: Whether the comment is private (default False).
            Ignored when ``internal=True``.
        internal: When True, post the comment to the Jira project
            instead of to OSIDB/Bugzilla (default False).
    """
    session = get_session()

    if internal:
        try:
            flaw = session.flaws.retrieve(flaw_id, include_fields="task_key")
            task_key = getattr(flaw, "task_key", None)
        except Exception as exc:
            return _error_response(exc)

        if not task_key:
            return {
                "ok": False,
                "error": "no_jira_task",
                "detail": "Flaw has no associated Jira issue (task_key is empty)",
            }

        return _post_jira_comment(task_key, text)

    try:
        flaw = session.flaws.retrieve(flaw_id, include_fields="embargoed")
        flaw_embargoed = getattr(flaw, "embargoed", False)
    except Exception as exc:
        return _error_response(exc)

    comment_data: dict[str, Any] = {
        "text": text,
        "embargoed": flaw_embargoed,
        "is_private": is_private,
    }
    if creator is not None:
        comment_data["creator"] = creator

    try:
        result = session.flaws.comments.create(comment_data, flaw_id)
        return {"ok": True, "comment": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_label_add / flaw_label_remove
# ---------------------------------------------------------------------------

def flaw_label_add(
    flaw_id: str,
    label: str,
    *,
    state: str | None = None,
    contributor: str | None = None,
    label_type: str | None = None,
) -> dict[str, Any]:
    """Add a collaborator label to a flaw (POST /osidb/api/v1/flaws/{id}/labels).

    Args:
        flaw_id: Flaw UUID (required).
        label: Label name (required).
        state: Label state (NEW, REQ, DONE, SKIP). Default NEW.
        contributor: Contributor name.
        label_type: Label type (alias, context_based).
    """
    from osidb_bindings.bindings.python_client.models.flaw_collaborator_post_request import (
        FlawCollaboratorPostRequest,
    )

    try:
        flaw_uuid = UUID(str(flaw_id).strip())
    except ValueError:
        return {"ok": False, "error": "bad_request", "detail": "flaw_id must be a UUID for label operations"}

    kw: dict[str, Any] = {"label": label}
    if state:
        from osidb_bindings.bindings.python_client.models.state_enum import StateEnum
        kw["state"] = StateEnum(state)
    if contributor:
        kw["contributor"] = contributor
    if label_type:
        from osidb_bindings.bindings.python_client.models.flaw_collaborator_post_type_enum import (
            FlawCollaboratorPostTypeEnum,
        )
        kw["type_"] = FlawCollaboratorPostTypeEnum(label_type)

    body = FlawCollaboratorPostRequest(**kw)

    try:
        client = get_session().get_client_with_new_access_token()
        from osidb_bindings.bindings.python_client.api.osidb import (
            osidb_api_v1_flaws_labels_create,
        )
        r = osidb_api_v1_flaws_labels_create.sync_detailed(
            flaw_uuid, client=client, body=body,
        )
        if r.parsed is None:
            return {"ok": False, "error": "empty_response", "status_code": int(r.status_code)}
        return {"ok": True, "label": to_jsonable(r.parsed.to_dict())}
    except Exception as exc:
        return _error_response(exc)


def flaw_label_remove(
    flaw_id: str,
    label_id: str,
) -> dict[str, Any]:
    """Remove a label from a flaw (DELETE /osidb/api/v1/flaws/{id}/labels/{id}).

    Args:
        flaw_id: Flaw UUID (required).
        label_id: Label ID to delete (required).
    """
    try:
        flaw_uuid = UUID(str(flaw_id).strip())
    except ValueError:
        return {"ok": False, "error": "bad_request", "detail": "flaw_id must be a UUID for label operations"}

    try:
        client = get_session().get_client_with_new_access_token()
        from osidb_bindings.bindings.python_client.api.osidb import (
            osidb_api_v1_flaws_labels_destroy,
        )
        r = osidb_api_v1_flaws_labels_destroy.sync_detailed(
            flaw_uuid, label_id, client=client,
        )
        return {"ok": True, "deleted": label_id}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_incident_request
# ---------------------------------------------------------------------------

def flaw_incident_request(
    flaw_id: str,
    kind: str,
    comment: str,
) -> dict[str, Any]:
    """Create an incident request on a flaw (POST /osidb/api/v1/flaws/{id}/incident-requests).

    Args:
        flaw_id: Flaw CVE id or UUID (required).
        kind: Request kind: MAJOR_INCIDENT_REQUESTED, MINOR_INCIDENT_REQUESTED,
              or EXPLOITS_KEV_REQUESTED (required).
        comment: Justification comment (required).
    """
    from osidb_bindings.bindings.python_client.models.incident_request_request import (
        IncidentRequestRequest,
    )
    from osidb_bindings.bindings.python_client.models.kind_enum import KindEnum

    body = IncidentRequestRequest(comment=comment, kind=KindEnum(kind))

    try:
        client = get_session().get_client_with_new_access_token()
        from osidb_bindings.bindings.python_client.api.osidb import (
            osidb_api_v1_flaws_incident_requests_create,
        )
        r = osidb_api_v1_flaws_incident_requests_create.sync_detailed(
            flaw_id, client=client, body=body,
        )
        if r.parsed is None:
            return {"ok": False, "error": "empty_response", "status_code": int(r.status_code)}
        return {"ok": True, "incident_request": to_jsonable(r.parsed.to_dict())}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_acknowledgment_update
# ---------------------------------------------------------------------------

def flaw_acknowledgment_update(
    flaw_id: str,
    acknowledgment_id: str,
    *,
    name: str | None = None,
    affiliation: str | None = None,
    from_upstream: bool | None = None,
) -> dict[str, Any]:
    """Update an acknowledgment on a flaw (PUT /osidb/api/v1/flaws/{id}/acknowledgments/{id}).

    Auto-fetches the current acknowledgment to merge updates.

    Args:
        flaw_id: Flaw UUID or CVE id (required).
        acknowledgment_id: Acknowledgment UUID (required).
        name: Acknowledged person/org name.
        affiliation: Affiliation.
        from_upstream: Whether the acknowledgment comes from upstream.
    """
    session = get_session()

    try:
        current = session.flaws.acknowledgments.retrieve(flaw_id, acknowledgment_id)
    except Exception as exc:
        return _error_response(exc)

    data: dict[str, Any] = {}
    for field in ("name", "affiliation", "from_upstream", "embargoed"):
        val = getattr(current, field, None)
        if val is not None:
            data[field] = to_jsonable(val)
    data["updated_dt"] = to_jsonable(getattr(current, "updated_dt", None))

    if name is not None:
        data["name"] = name
    if affiliation is not None:
        data["affiliation"] = affiliation
    if from_upstream is not None:
        data["from_upstream"] = from_upstream

    try:
        result = session.flaws.acknowledgments.update(flaw_id, acknowledgment_id, data)
        return {"ok": True, "acknowledgment": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_reference_update
# ---------------------------------------------------------------------------

def flaw_reference_update(
    flaw_id: str,
    reference_id: str,
    *,
    url: str | None = None,
    description: str | None = None,
    reference_type: str | None = None,
) -> dict[str, Any]:
    """Update a reference on a flaw (PUT /osidb/api/v1/flaws/{id}/references/{id}).

    Auto-fetches the current reference to merge updates.

    Args:
        flaw_id: Flaw UUID or CVE id (required).
        reference_id: Reference UUID (required).
        url: Reference URL.
        description: Description text.
        reference_type: ARTICLE, UPSTREAM, or EXTERNAL.
    """
    session = get_session()

    try:
        current = session.flaws.references.retrieve(flaw_id, reference_id)
    except Exception as exc:
        return _error_response(exc)

    data: dict[str, Any] = {}
    for field in ("url", "description", "type", "embargoed"):
        val = getattr(current, field, None)
        if val is not None:
            data[field] = to_jsonable(val)
    data["updated_dt"] = to_jsonable(getattr(current, "updated_dt", None))

    if url is not None:
        data["url"] = url
    if description is not None:
        data["description"] = description
    if reference_type is not None:
        data["type"] = reference_type

    try:
        result = session.flaws.references.update(flaw_id, reference_id, data)
        return {"ok": True, "reference": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_cvss_update
# ---------------------------------------------------------------------------

def flaw_cvss_update(
    flaw_id: str,
    cvss_score_id: str,
    *,
    vector: str | None = None,
    comment: str | None = None,
    cvss_version: str | None = None,
    issuer: str | None = None,
) -> dict[str, Any]:
    """Update a CVSS score on a flaw (PUT /osidb/api/v1/flaws/{id}/cvss_scores/{id}).

    Auto-fetches the current score to merge updates.

    Args:
        flaw_id: Flaw UUID or CVE id (required).
        cvss_score_id: CVSS score UUID (required).
        vector: CVSS vector string.
        comment: Score comment.
        cvss_version: V3 or V4.
        issuer: Score issuer (default RH).
    """
    session = get_session()

    try:
        current = session.flaws.cvss_scores.retrieve(
            flaw_id, cvss_score_id, api_version="v1",
        )
    except Exception as exc:
        return _error_response(exc)

    data: dict[str, Any] = {}
    for field in ("vector", "comment", "cvss_version", "issuer", "embargoed"):
        val = getattr(current, field, None)
        if val is not None:
            data[field] = to_jsonable(val)
    data["updated_dt"] = to_jsonable(getattr(current, "updated_dt", None))

    if vector is not None:
        data["vector"] = vector
    if comment is not None:
        data["comment"] = comment
    if cvss_version is not None:
        data["cvss_version"] = cvss_version
    if issuer is not None:
        data["issuer"] = issuer

    try:
        result = session.flaws.cvss_scores.update(
            flaw_id, cvss_score_id, data, api_version="v1",
        )
        return {"ok": True, "cvss_score": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# flaw_package_version_add
# ---------------------------------------------------------------------------

def flaw_package_version_add(
    flaw_id: str,
    package: str,
    versions: list[dict[str, Any]],
) -> dict[str, Any]:
    """Add package version info to a flaw (POST /osidb/api/v1/flaws/{id}/package_versions).

    Args:
        flaw_id: Flaw UUID (required).
        package: Package name (required).
        versions: List of version dicts, each with ``version`` (str).
    """
    from osidb_bindings.bindings.python_client.models.flaw_package_version_post_request import (
        FlawPackageVersionPostRequest,
    )
    from osidb_bindings.bindings.python_client.models.flaw_version_request import (
        FlawVersionRequest,
    )

    try:
        flaw_uuid = UUID(str(flaw_id).strip())
    except ValueError:
        return {"ok": False, "error": "bad_request", "detail": "flaw_id must be a UUID"}

    session = get_session()
    try:
        flaw = session.flaws.retrieve(flaw_id, include_fields="embargoed")
        embargoed = getattr(flaw, "embargoed", False)
    except Exception as exc:
        return _error_response(exc)

    version_objs = [FlawVersionRequest(**v) for v in versions]
    body = FlawPackageVersionPostRequest(
        package=package, versions=version_objs, embargoed=embargoed,
    )

    try:
        client = session.get_client_with_new_access_token()
        from osidb_bindings.bindings.python_client.api.osidb import (
            osidb_api_v1_flaws_package_versions_create,
        )
        r = osidb_api_v1_flaws_package_versions_create.sync_detailed(
            flaw_uuid, client=client, body=body,
        )
        if r.parsed is None:
            return {"ok": False, "error": "empty_response", "status_code": int(r.status_code)}
        return {"ok": True, "package_version": to_jsonable(r.parsed.to_dict())}
    except Exception as exc:
        return _error_response(exc)


# ---------------------------------------------------------------------------
# affects_bulk_create / affects_bulk_update / affects_bulk_delete
# ---------------------------------------------------------------------------

def affects_bulk_create(
    affects: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bulk-create affects (POST /osidb/api/v2/affects/bulk).

    Args:
        affects: List of affect dicts, each with at minimum ``flaw`` (UUID),
                 ``ps_module``, ``ps_component``, ``affectedness``, ``embargoed``.
    """
    session = get_session()
    try:
        result = session.affects.bulk_create(affects)
        return {"ok": True, "created": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


def affects_bulk_update(
    affects: list[dict[str, Any]],
) -> dict[str, Any]:
    """Bulk-update affects (PUT /osidb/api/v2/affects/bulk).

    Args:
        affects: List of affect dicts. Each must include ``uuid`` and ``updated_dt``
                 for optimistic concurrency, plus any fields to change.
    """
    session = get_session()
    try:
        result = session.affects.bulk_update(affects)
        return {"ok": True, "updated": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)


def affects_bulk_delete(
    affect_uuids: list[str],
) -> dict[str, Any]:
    """Bulk-delete affects (DELETE /osidb/api/v2/affects/bulk).

    Uses raw HTTP because osidb-bindings does not expose bulk_delete on
    session.affects (blocked by OSIDB-2996) and the generated client's
    bulk_destroy endpoint omits the request body.

    Args:
        affect_uuids: List of affect UUID strings to delete.
    """
    session = get_session()
    client = session.get_client_with_new_access_token()

    try:
        resp = requests.delete(
            f"{client.base_url}/osidb/api/v2/affects/bulk",
            json=affect_uuids,
            headers=client.get_headers(),
            verify=client.verify_ssl,
            auth=client.get_auth(),
            timeout=client.get_timeout(),
        )
        resp.raise_for_status()
        return {"ok": True, "deleted": affect_uuids}
    except Exception as exc:
        return _error_response(exc)
