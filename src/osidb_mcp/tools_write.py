"""MCP tool implementations (write / mutation OSIDB operations)."""

from __future__ import annotations

from typing import Any

import requests

from osidb_mcp.errors import http_error_payload
from osidb_mcp.serialize import to_jsonable
from osidb_mcp.session_holder import get_session

_FLAW_FIELDS = (
    "title", "comment_zero", "embargoed", "cve_id", "impact", "components",
    "cve_description", "statement", "cwe_id", "source", "reported_dt",
    "unembargo_dt", "mitigation",
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

    created: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    for i, affect in enumerate(affects):
        affect["flaw"] = flaw_id
        if "embargoed" not in affect:
            affect["embargoed"] = flaw_embargoed
        try:
            result = session.affects.create(affect)
            created.append(to_jsonable(result))
        except Exception as exc:
            detail = http_error_payload(exc) if isinstance(exc, requests.RequestException) else str(exc)
            errors.append({"index": i, "affect": affect, "error": detail})

    out: dict[str, Any] = {"ok": True, "created": created}
    if errors:
        out["partial"] = True
        out["errors"] = errors
    return out


def affect_remove(
    affect_uuids: list[str],
) -> dict[str, Any]:
    """Remove one or more affects by UUID.

    Args:
        affect_uuids: List of affect UUID strings to delete.
    """
    session = get_session()

    deleted: list[str] = []
    errors: list[dict[str, Any]] = []

    for uuid in affect_uuids:
        try:
            session.affects.delete(uuid)
            deleted.append(uuid)
        except Exception as exc:
            detail = http_error_payload(exc) if isinstance(exc, requests.RequestException) else str(exc)
            errors.append({"affect_uuid": uuid, "error": detail})

    out: dict[str, Any] = {"ok": True, "deleted": deleted}
    if errors:
        out["partial"] = True
        out["errors"] = errors
    return out


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
# tracker_file
# ---------------------------------------------------------------------------

def tracker_file(
    flaw_id: str,
    affect_uuids: list[str],
) -> dict[str, Any]:
    """File trackers (Jira/Bugzilla) for one or more affects.

    Creates tracker filings for the specified affects via
    POST /trackers/api/file.

    Args:
        flaw_id: Flaw UUID (required).
        affect_uuids: List of affect UUIDs to create trackers for (required).

    Returns:
        JSON dict with ``ok`` and created tracker details.
    """
    session = get_session()
    try:
        result = session.trackers.file({
            "flaw_uuids": [flaw_id],
            "affect_uuids": affect_uuids,
        })
        return {"ok": True, "trackers": to_jsonable(result)}
    except Exception as exc:
        return _error_response(exc)
