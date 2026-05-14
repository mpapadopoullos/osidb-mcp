"""MCP tool implementations (read-only OSIDB operations)."""

from __future__ import annotations

import datetime
import importlib
from typing import Any, Literal
from uuid import UUID

import requests
from osidb_bindings.bindings.python_client.api.osidb import osidb_whoami_retrieve
from osidb_bindings.bindings.python_client.models.osidb_api_v2_affects_list_flaw_impact import (
    OsidbApiV2AffectsListFlawImpact,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_affects_list_flaw_impact_in_item import (
    OsidbApiV2AffectsListFlawImpactInItem,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_affects_list_flaw_workflow_state_item import (
    OsidbApiV2AffectsListFlawWorkflowStateItem,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_flaws_list_impact import (
    OsidbApiV2FlawsListImpact,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_flaws_list_impact_in_item import (
    OsidbApiV2FlawsListImpactInItem,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_flaws_list_major_incident_state import (
    OsidbApiV2FlawsListMajorIncidentState,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_flaws_list_major_incident_state_in_item import (
    OsidbApiV2FlawsListMajorIncidentStateInItem,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_flaws_list_source import (
    OsidbApiV2FlawsListSource,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_flaws_list_source_in_item import (
    OsidbApiV2FlawsListSourceInItem,
)
from osidb_bindings.bindings.python_client.models.osidb_api_v2_flaws_list_workflow_state_item import (
    OsidbApiV2FlawsListWorkflowStateItem,
)

from osidb_mcp.errors import http_error_payload
from osidb_mcp.query_filters import (
    AFFECTS_EXTRA_KEYS,
    DEFAULT_LIST_LIMIT,
    FLAWS_EXTRA_KEYS,
    clamp_limit,
    clamp_offset,
    merge_extra_query,
)
from osidb_mcp.serialize import paginated_summary, to_jsonable
from osidb_mcp.session_holder import get_session

_trackers_list = importlib.import_module(
    "osidb_bindings.bindings.python_client.api.osidb.osidb_api_v2_trackers_list"
)
TRACKERS_EXTRA_KEYS = frozenset(_trackers_list.QUERY_PARAMS.keys())

# Shown on flaw list/search responses so agents keep the stable OSIDB id when cve_id is empty.
_FLAW_LIST_IDENTITY_HINT = (
    "Each flaw has `uuid` (internal OSIDB id). When `cve_id` is null or empty, use that `uuid` "
    "as `flaw_id` for flaw_get / get_flaw_details / flaw_*_list; for affects_list use `flaw_uuid`, "
    "for trackers_list use `affects_flaw_uuid`."
)


def _flaw_has_usable_cve_id(flaw: dict[str, Any]) -> bool:
    cve = flaw.get("cve_id")
    return isinstance(cve, str) and bool(cve.strip())


def _envelope_osidb_flaw_uuid_when_no_cve(body: dict[str, Any]) -> dict[str, Any]:
    """Duplicate flaw uuid at top level when there is no CVE yet (helps agents and UIs)."""
    if not body.get("ok"):
        return body
    flaw = body.get("flaw")
    if not isinstance(flaw, dict) or _flaw_has_usable_cve_id(flaw):
        return body
    uid = flaw.get("uuid")
    if uid:
        body["osidb_flaw_uuid"] = uid
    return body


def _attach_flaw_list_identity_hint(body: dict[str, Any]) -> dict[str, Any]:
    if body.get("ok"):
        body["identifier_hint"] = _FLAW_LIST_IDENTITY_HINT
    return body


def _parse_uuid_param(name: str, value: str) -> UUID:
    try:
        return UUID(str(value).strip())
    except ValueError as e:
        raise ValueError(f"{name} must be a UUID string") from e


def _parse_dt(value: str | None) -> datetime.datetime | None:
    if not value:
        return None
    s = value.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00:00"
    return datetime.datetime.fromisoformat(s)


def _impact_in(values: list[str] | None) -> list[OsidbApiV2FlawsListImpactInItem] | None:
    if not values:
        return None
    return [OsidbApiV2FlawsListImpactInItem(v) for v in values]


def _workflow_in(
    values: list[str] | None,
) -> list[OsidbApiV2FlawsListWorkflowStateItem] | None:
    if not values:
        return None
    return [OsidbApiV2FlawsListWorkflowStateItem(v) for v in values]


def osidb_status() -> dict[str, Any]:
    try:
        st = get_session().status()
        return {"ok": True, "status": to_jsonable(st)}
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}


def osidb_whoami() -> dict[str, Any]:
    try:
        s = get_session()
        r = osidb_whoami_retrieve.sync_detailed(
            client=s.get_client_with_new_access_token()
        )
        if r.parsed is None:
            return {
                "ok": False,
                "error": "whoami_empty",
                "status_code": int(r.status_code),
            }
        return {"ok": True, "whoami": to_jsonable(r.parsed.to_dict())}
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}


def flaw_get(
    flaw_id: str,
    include_fields: list[str] | None = None,
    exclude_fields: list[str] | None = None,
    api_version: str | None = None,
) -> dict[str, Any]:
    try:
        kw: dict[str, Any] = {}
        if include_fields:
            kw["include_fields"] = include_fields
        if exclude_fields:
            kw["exclude_fields"] = exclude_fields
        flaw = get_session().flaws.retrieve(
            flaw_id, api_version=api_version, **kw
        )
        return _envelope_osidb_flaw_uuid_when_no_cve(
            {"ok": True, "flaw": to_jsonable(flaw)}
        )
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}


def _major_incident_in(
    values: list[str] | None,
) -> list[OsidbApiV2FlawsListMajorIncidentStateInItem] | None:
    if not values:
        return None
    return [OsidbApiV2FlawsListMajorIncidentStateInItem(v) for v in values]


def _build_flaws_kwargs(
    *,
    search: str | None,
    embargoed: bool | None,
    components: list[str] | None,
    components_in: list[str] | None,
    affects_ps_module: str | None,
    affects_ps_module_in: list[str] | None,
    affects_ps_component: str | None,
    affects_ps_component_in: list[str] | None,
    affects_ps_update_stream: str | None,
    affects_ps_update_stream_in: list[str] | None,
    workflow_state: list[str] | None,
    workflow_state_in: list[str] | None,
    impact: str | None,
    impact_in: list[str] | None,
    owner: str | None,
    owner_in: list[str] | None,
    owner_isempty: bool | None,
    cve_id_in: list[str] | None,
    changed_after: str | None,
    changed_before: str | None,
    major_incident_state: str | None,
    major_incident_state_in: list[str] | None,
    source: str | None,
    source_in: list[str] | None,
    include_fields: list[str] | None,
    exclude_fields: list[str] | None,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    kw: dict[str, Any] = {"limit": limit, "offset": offset}
    if search:
        kw["search"] = search
    if embargoed is not None:
        kw["embargoed"] = embargoed
    if components:
        kw["components"] = components
    if components_in:
        kw["components__in"] = components_in
    if affects_ps_module:
        kw["affects__ps_module"] = affects_ps_module
    if affects_ps_module_in:
        kw["affects__ps_module__in"] = affects_ps_module_in
    if affects_ps_component:
        kw["affects__ps_component"] = affects_ps_component
    if affects_ps_component_in:
        kw["affects__ps_component__in"] = affects_ps_component_in
    if affects_ps_update_stream:
        kw["affects__ps_update_stream"] = affects_ps_update_stream
    if affects_ps_update_stream_in:
        kw["affects__ps_update_stream__in"] = affects_ps_update_stream_in
    if workflow_state:
        kw["workflow_state"] = _workflow_in(workflow_state)
    if workflow_state_in:
        kw["workflow_state__in"] = _workflow_in(workflow_state_in)
    if impact:
        kw["impact"] = OsidbApiV2FlawsListImpact(impact)
    if impact_in:
        kw["impact__in"] = _impact_in(impact_in)
    if owner:
        kw["owner"] = owner
    if owner_in:
        kw["owner__in"] = owner_in
    if owner_isempty is not None:
        kw["owner__isempty"] = owner_isempty
    if cve_id_in:
        kw["cve_id__in"] = cve_id_in
    ca, cb = _parse_dt(changed_after), _parse_dt(changed_before)
    if ca is not None:
        kw["changed_after"] = ca
    if cb is not None:
        kw["changed_before"] = cb
    if major_incident_state:
        kw["major_incident_state"] = OsidbApiV2FlawsListMajorIncidentState(
            major_incident_state
        )
    if major_incident_state_in:
        kw["major_incident_state__in"] = _major_incident_in(major_incident_state_in)
    if source:
        kw["source"] = OsidbApiV2FlawsListSource(source)
    if source_in:
        kw["source__in"] = [OsidbApiV2FlawsListSourceInItem(s) for s in source_in]
    if include_fields:
        kw["include_fields"] = include_fields
    if exclude_fields:
        kw["exclude_fields"] = exclude_fields
    return kw


def flaws_list(
    *,
    search: str | None = None,
    embargoed: bool | None = None,
    components: list[str] | None = None,
    components_in: list[str] | None = None,
    affects_ps_module: str | None = None,
    affects_ps_module_in: list[str] | None = None,
    affects_ps_component: str | None = None,
    affects_ps_component_in: list[str] | None = None,
    affects_ps_update_stream: str | None = None,
    affects_ps_update_stream_in: list[str] | None = None,
    workflow_state: list[str] | None = None,
    workflow_state_in: list[str] | None = None,
    impact: str | None = None,
    impact_in: list[str] | None = None,
    owner: str | None = None,
    owner_in: list[str] | None = None,
    owner_isempty: bool | None = None,
    cve_id_in: list[str] | None = None,
    changed_after: str | None = None,
    changed_before: str | None = None,
    major_incident_state: str | None = None,
    major_incident_state_in: list[str] | None = None,
    source: str | None = None,
    source_in: list[str] | None = None,
    include_fields: list[str] | None = None,
    exclude_fields: list[str] | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    off = clamp_offset(offset)
    try:
        base = _build_flaws_kwargs(
            search=search,
            embargoed=embargoed,
            components=components,
            components_in=components_in,
            affects_ps_module=affects_ps_module,
            affects_ps_module_in=affects_ps_module_in,
            affects_ps_component=affects_ps_component,
            affects_ps_component_in=affects_ps_component_in,
            affects_ps_update_stream=affects_ps_update_stream,
            affects_ps_update_stream_in=affects_ps_update_stream_in,
            workflow_state=workflow_state,
            workflow_state_in=workflow_state_in,
            impact=impact,
            impact_in=impact_in,
            owner=owner,
            owner_in=owner_in,
            owner_isempty=owner_isempty,
            cve_id_in=cve_id_in,
            changed_after=changed_after,
            changed_before=changed_before,
            major_incident_state=major_incident_state,
            major_incident_state_in=major_incident_state_in,
            source=source,
            source_in=source_in,
            include_fields=include_fields,
            exclude_fields=exclude_fields,
            limit=lim,
            offset=off,
        )
        merged = merge_extra_query(base, extra_query, allowlist=FLAWS_EXTRA_KEYS)
        resp = get_session().flaws.retrieve_list(
            api_version=api_version,
            **merged,
        )
        return _attach_flaw_list_identity_hint(
            {
                "ok": True,
                **paginated_summary(resp, limit=lim, offset=off),
            }
        )
    except (requests.RequestException, ValueError) as e:
        if isinstance(e, ValueError):
            return {"ok": False, "error": "bad_request", "detail": str(e)}
        return {"ok": False, **http_error_payload(e)}


def flaws_count(
    *,
    search: str | None = None,
    embargoed: bool | None = None,
    components: list[str] | None = None,
    components_in: list[str] | None = None,
    affects_ps_module: str | None = None,
    affects_ps_module_in: list[str] | None = None,
    affects_ps_component: str | None = None,
    affects_ps_component_in: list[str] | None = None,
    affects_ps_update_stream: str | None = None,
    affects_ps_update_stream_in: list[str] | None = None,
    workflow_state: list[str] | None = None,
    workflow_state_in: list[str] | None = None,
    impact: str | None = None,
    impact_in: list[str] | None = None,
    owner: str | None = None,
    owner_in: list[str] | None = None,
    owner_isempty: bool | None = None,
    cve_id_in: list[str] | None = None,
    changed_after: str | None = None,
    changed_before: str | None = None,
    major_incident_state: str | None = None,
    major_incident_state_in: list[str] | None = None,
    source: str | None = None,
    source_in: list[str] | None = None,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        base = _build_flaws_kwargs(
            search=search,
            embargoed=embargoed,
            components=components,
            components_in=components_in,
            affects_ps_module=affects_ps_module,
            affects_ps_module_in=affects_ps_module_in,
            affects_ps_component=affects_ps_component,
            affects_ps_component_in=affects_ps_component_in,
            affects_ps_update_stream=affects_ps_update_stream,
            affects_ps_update_stream_in=affects_ps_update_stream_in,
            workflow_state=workflow_state,
            workflow_state_in=workflow_state_in,
            impact=impact,
            impact_in=impact_in,
            owner=owner,
            owner_in=owner_in,
            owner_isempty=owner_isempty,
            cve_id_in=cve_id_in,
            changed_after=changed_after,
            changed_before=changed_before,
            major_incident_state=major_incident_state,
            major_incident_state_in=major_incident_state_in,
            source=source,
            source_in=source_in,
            include_fields=None,
            exclude_fields=None,
            limit=50,
            offset=0,
        )
        base.pop("limit", None)
        base.pop("offset", None)
        merged = merge_extra_query(base, extra_query, allowlist=FLAWS_EXTRA_KEYS)
        n = get_session().flaws.count(api_version=api_version, **merged)
        return {"ok": True, "count": n}
    except (requests.RequestException, ValueError) as e:
        if isinstance(e, ValueError):
            return {"ok": False, "error": "bad_request", "detail": str(e)}
        return {"ok": False, **http_error_payload(e)}


def flaws_search(
    text: str,
    limit: int = DEFAULT_LIST_LIMIT,
    api_version: str | None = None,
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    try:
        resp = get_session().flaws.search(
            text,
            api_version=api_version,
            limit=lim,
        )
        return _attach_flaw_list_identity_hint(
            {
                "ok": True,
                **paginated_summary(resp, limit=lim, offset=0),
            }
        )
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}


def _affects_impact_in(
    values: list[str] | None,
) -> list[OsidbApiV2AffectsListFlawImpactInItem] | None:
    if not values:
        return None
    return [OsidbApiV2AffectsListFlawImpactInItem(v) for v in values]


def _affects_workflow_in(
    values: list[str] | None,
) -> list[OsidbApiV2AffectsListFlawWorkflowStateItem] | None:
    if not values:
        return None
    return [OsidbApiV2AffectsListFlawWorkflowStateItem(v) for v in values]


def affects_list(
    *,
    ps_module: str | None = None,
    ps_module_in: list[str] | None = None,
    ps_component: str | None = None,
    ps_component_in: list[str] | None = None,
    ps_update_stream: str | None = None,
    ps_update_stream_in: list[str] | None = None,
    flaw_cve_id: str | None = None,
    flaw_cve_id_in: list[str] | None = None,
    flaw_uuid: str | None = None,
    flaw_uuid_in: list[str] | None = None,
    flaw_workflow_state: list[str] | None = None,
    flaw_workflow_state_in: list[str] | None = None,
    flaw_impact: str | None = None,
    flaw_impact_in: list[str] | None = None,
    flaw_components: list[str] | None = None,
    flaw_components_in: list[str] | None = None,
    embargoed: bool | None = None,
    include_fields: list[str] | None = None,
    exclude_fields: list[str] | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    off = clamp_offset(offset)
    try:
        kw: dict[str, Any] = {"limit": lim, "offset": off}
        if ps_module:
            kw["ps_module"] = ps_module
        if ps_module_in:
            kw["ps_module__in"] = ps_module_in
        if ps_component:
            kw["ps_component"] = ps_component
        if ps_component_in:
            kw["ps_component__in"] = ps_component_in
        if ps_update_stream:
            kw["ps_update_stream"] = ps_update_stream
        if ps_update_stream_in:
            kw["ps_update_stream__in"] = ps_update_stream_in
        if flaw_cve_id:
            kw["flaw__cve_id"] = flaw_cve_id
        if flaw_cve_id_in:
            kw["flaw__cve_id__in"] = flaw_cve_id_in
        if flaw_uuid:
            kw["flaw__uuid"] = _parse_uuid_param("flaw_uuid", flaw_uuid)
        if flaw_uuid_in:
            kw["flaw__uuid__in"] = [
                _parse_uuid_param("flaw_uuid_in", u) for u in flaw_uuid_in
            ]
        if flaw_workflow_state:
            kw["flaw__workflow_state"] = _affects_workflow_in(flaw_workflow_state)
        if flaw_workflow_state_in:
            kw["flaw__workflow_state__in"] = _affects_workflow_in(
                flaw_workflow_state_in
            )
        if flaw_impact:
            kw["flaw__impact"] = OsidbApiV2AffectsListFlawImpact(flaw_impact)
        if flaw_impact_in:
            kw["flaw__impact__in"] = _affects_impact_in(flaw_impact_in)
        if flaw_components:
            kw["flaw__components"] = flaw_components
        if flaw_components_in:
            kw["flaw__components__in"] = flaw_components_in
        if embargoed is not None:
            kw["embargoed"] = embargoed
        if include_fields:
            kw["include_fields"] = include_fields
        if exclude_fields:
            kw["exclude_fields"] = exclude_fields
        merged = merge_extra_query(kw, extra_query, allowlist=AFFECTS_EXTRA_KEYS)
        resp = get_session().affects.retrieve_list(
            api_version=api_version,
            **merged,
        )
        return {
            "ok": True,
            **paginated_summary(resp, limit=lim, offset=off),
        }
    except (requests.RequestException, ValueError) as e:
        if isinstance(e, ValueError):
            return {"ok": False, "error": "bad_request", "detail": str(e)}
        return {"ok": False, **http_error_payload(e)}


def _finalize_trackers_kwargs(merged: dict[str, Any]) -> dict[str, Any]:
    """Map OpenAPI ``type`` query keys to the generated client ``type_`` kwargs."""
    from osidb_bindings.bindings.python_client.models.osidb_api_v2_trackers_list_type import (
        OsidbApiV2TrackersListType,
    )
    from osidb_bindings.bindings.python_client.models.osidb_api_v2_trackers_list_type_in_item import (
        OsidbApiV2TrackersListTypeInItem,
    )

    out = dict(merged)
    if "type" in out:
        v = out.pop("type")
        out["type_"] = (
            OsidbApiV2TrackersListType(v) if isinstance(v, str) else v
        )
    if "type__in" in out:
        v = out.pop("type__in")
        if isinstance(v, list):
            out["type_in"] = [
                OsidbApiV2TrackersListTypeInItem(x) if isinstance(x, str) else x
                for x in v
            ]
        else:
            out["type_in"] = v
    return out


def trackers_list(
    *,
    affects_flaw_cve_id: str | None = None,
    affects_flaw_cve_id_in: list[str] | None = None,
    affects_flaw_uuid: str | None = None,
    affects_flaw_uuid_in: list[str] | None = None,
    affects_ps_module_in: list[str] | None = None,
    affects_ps_component_in: list[str] | None = None,
    tracker_type: str | None = None,
    include_fields: list[str] | None = None,
    exclude_fields: list[str] | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    off = clamp_offset(offset)
    try:
        from osidb_bindings.bindings.python_client.models.osidb_api_v2_trackers_list_type import (
            OsidbApiV2TrackersListType,
        )

        kw: dict[str, Any] = {"limit": lim, "offset": off}
        if affects_flaw_cve_id:
            kw["affects__flaw__cve_id"] = affects_flaw_cve_id
        if affects_flaw_cve_id_in:
            kw["affects__flaw__cve_id__in"] = affects_flaw_cve_id_in
        if affects_flaw_uuid:
            kw["affects__flaw__uuid"] = _parse_uuid_param(
                "affects_flaw_uuid", affects_flaw_uuid
            )
        if affects_flaw_uuid_in:
            kw["affects__flaw__uuid__in"] = [
                _parse_uuid_param("affects_flaw_uuid_in", u)
                for u in affects_flaw_uuid_in
            ]
        if affects_ps_module_in:
            kw["affects__ps_module__in"] = affects_ps_module_in
        if affects_ps_component_in:
            kw["affects__ps_component__in"] = affects_ps_component_in
        if tracker_type:
            kw["type_"] = OsidbApiV2TrackersListType(tracker_type)
        if include_fields:
            kw["include_fields"] = include_fields
        if exclude_fields:
            kw["exclude_fields"] = exclude_fields
        merged = merge_extra_query(
            kw, extra_query, allowlist=TRACKERS_EXTRA_KEYS
        )
        merged = _finalize_trackers_kwargs(merged)
        resp = get_session().trackers.retrieve_list(
            api_version=api_version,
            **merged,
        )
        return {
            "ok": True,
            **paginated_summary(resp, limit=lim, offset=off),
        }
    except (requests.RequestException, ValueError) as e:
        if isinstance(e, ValueError):
            return {"ok": False, "error": "bad_request", "detail": str(e)}
        return {"ok": False, **http_error_payload(e)}


def flaw_comments_list(
    flaw_id: str,
    *,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    off = clamp_offset(offset)
    try:
        resp = get_session().flaws.comments.retrieve_list(
            flaw_id,
            api_version=api_version,
            limit=lim,
            offset=off,
        )
        return {
            "ok": True,
            **paginated_summary(resp, limit=lim, offset=off),
        }
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}


def flaw_references_list(
    flaw_id: str,
    *,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    off = clamp_offset(offset)
    try:
        resp = get_session().flaws.references.retrieve_list(
            flaw_id,
            api_version=api_version,
            limit=lim,
            offset=off,
        )
        return {
            "ok": True,
            **paginated_summary(resp, limit=lim, offset=off),
        }
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}


def flaw_cvss_scores_list(
    flaw_id: str,
    *,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
) -> dict[str, Any]:
    lim = clamp_limit(limit)
    off = clamp_offset(offset)
    try:
        resp = get_session().flaws.cvss_scores.retrieve_list(
            flaw_id,
            api_version=api_version,
            limit=lim,
            offset=off,
        )
        return {
            "ok": True,
            **paginated_summary(resp, limit=lim, offset=off),
        }
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}


# --- High-level capability tools (triage-style search / rollups) ---

_IMPACTS_ORDER = ("CRITICAL", "IMPORTANT", "MODERATE", "LOW")
_WORKFLOW_STATES_SUMMARY = tuple(
    str(x.value)
    for x in OsidbApiV2FlawsListWorkflowStateItem
    if x.value
)


def search_flaws(
    *,
    keyword: str | None = None,
    cve_ids: list[str] | None = None,
    severity: str | None = None,
    severities: list[str] | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    product_modules: list[str] | None = None,
    product_components: list[str] | None = None,
    workflow_state_in: list[str] | None = None,
    major_incident_state: str | None = None,
    major_incident_state_in: list[str] | None = None,
    embargoed: bool | None = None,
    owner_isempty: bool | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Search flaws by CVE id(s), severity (impact), date range (changed_after/before),
    product hints (PS modules / component names), and/or free-text keyword.
    """
    keyword = (keyword or "").strip() or None
    has_structured = any(
        [
            cve_ids,
            severity,
            severities,
            date_from,
            date_to,
            product_modules,
            product_components,
            workflow_state_in,
            major_incident_state,
            major_incident_state_in,
            embargoed is not None,
            owner_isempty is not None,
            extra_query,
        ]
    )
    if keyword and not has_structured:
        return flaws_search(keyword, limit=limit, api_version=api_version)

    impact_in: list[str] | None = None
    impact: str | None = None
    if severities:
        impact_in = list(severities)
    elif severity:
        impact = severity

    return flaws_list(
        search=keyword,
        cve_id_in=cve_ids,
        impact=impact,
        impact_in=impact_in,
        changed_after=date_from,
        changed_before=date_to,
        affects_ps_module_in=product_modules,
        affects_ps_component_in=product_components,
        workflow_state_in=workflow_state_in,
        major_incident_state=major_incident_state,
        major_incident_state_in=major_incident_state_in,
        embargoed=embargoed,
        owner_isempty=owner_isempty,
        limit=limit,
        offset=offset,
        api_version=api_version,
        extra_query=extra_query,
    )


def get_flaw_details(
    flaw_id: str,
    *,
    include_affects: bool = True,
    include_trackers: bool = True,
    affects_limit: int = DEFAULT_LIST_LIMIT,
    trackers_limit: int = DEFAULT_LIST_LIMIT,
    api_version: str | None = None,
) -> dict[str, Any]:
    """
    Full flaw record plus affected products (affects) and Jira/Bugzilla-style trackers
    for the same flaw id (CVE string or internal ``uuid``), up to per-section limits.
    When the flaw has no ``cve_id`` yet, affects/trackers are scoped by ``flaw__uuid``.
    """
    base = flaw_get(flaw_id, api_version=api_version)
    if not base.get("ok"):
        return base
    flaw = base.get("flaw")
    if not isinstance(flaw, dict):
        flaw = {}

    out: dict[str, Any] = {
        "ok": True,
        "flaw": flaw,
        "affects": None,
        "trackers": None,
    }
    lim_a = clamp_limit(affects_limit)
    lim_t = clamp_limit(trackers_limit)

    err_no_scope: dict[str, Any] = {
        "ok": False,
        "error": "no_cve_no_uuid",
        "detail": (
            "Cannot load affects/trackers: flaw has no cve_id and no uuid in the payload "
            "(pass flaw_id as the OSIDB uuid if needed)."
        ),
    }

    if _flaw_has_usable_cve_id(flaw):
        cve_key = str(flaw.get("cve_id", "")).strip()
        if include_affects:
            out["affects"] = affects_list(
                flaw_cve_id=cve_key,
                limit=lim_a,
                offset=0,
                api_version=api_version,
            )
        if include_trackers:
            out["trackers"] = trackers_list(
                affects_flaw_cve_id=cve_key,
                limit=lim_t,
                offset=0,
                api_version=api_version,
            )
    else:
        uid = flaw.get("uuid")
        uid_s = uid.strip() if isinstance(uid, str) else ""
        if not uid_s:
            if include_affects:
                out["affects"] = err_no_scope
            if include_trackers:
                out["trackers"] = err_no_scope
        else:
            if include_affects:
                out["affects"] = affects_list(
                    flaw_uuid=uid_s,
                    limit=lim_a,
                    offset=0,
                    api_version=api_version,
                )
            if include_trackers:
                out["trackers"] = trackers_list(
                    affects_flaw_uuid=uid_s,
                    limit=lim_t,
                    offset=0,
                    api_version=api_version,
                )

    return _envelope_osidb_flaw_uuid_when_no_cve(out)


def get_cve_summary(
    *,
    group_by: str = "both",
    embargoed: bool | None = None,
    changed_after: str | None = None,
    changed_before: str | None = None,
    affects_ps_module_in: list[str] | None = None,
    components_in: list[str] | None = None,
    owner_isempty: bool | None = None,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Aggregate flaw counts by impact (severity) and workflow state for executive-style
    rollups. Applies the same scope filters to every bucket. Uses multiple ``flaws_count``
    calls against OSIDB (O(buckets) API requests).
    """
    gb = (group_by or "both").strip().lower()
    if gb not in ("severity", "workflow", "both"):
        return {
            "ok": False,
            "error": "bad_request",
            "detail": "group_by must be 'severity', 'workflow', or 'both'",
        }

    shared: dict[str, Any] = {
        "embargoed": embargoed,
        "changed_after": changed_after,
        "changed_before": changed_before,
        "affects_ps_module_in": affects_ps_module_in,
        "components_in": components_in,
        "owner_isempty": owner_isempty,
        "api_version": api_version,
        "extra_query": extra_query,
    }

    errors: list[dict[str, Any]] = []
    by_severity: dict[str, Any] = {}
    by_workflow: dict[str, Any] = {}

    total = flaws_count(**shared)
    if not total.get("ok"):
        return total

    if gb in ("severity", "both"):
        for imp in _IMPACTS_ORDER:
            r = flaws_count(impact=imp, **shared)
            if r.get("ok"):
                by_severity[imp] = r.get("count")
            else:
                by_severity[imp] = None
                errors.append({"bucket": f"severity:{imp}", **r})

    if gb in ("workflow", "both"):
        for st in _WORKFLOW_STATES_SUMMARY:
            r = flaws_count(workflow_state_in=[st], **shared)
            if r.get("ok"):
                by_workflow[st] = r.get("count")
            else:
                by_workflow[st] = None
                errors.append({"bucket": f"workflow:{st}", **r})

    return {
        "ok": True,
        "filters": {k: v for k, v in shared.items() if v is not None},
        "total_matching_filters": total.get("count"),
        "by_severity": by_severity if gb in ("severity", "both") else None,
        "by_workflow": by_workflow if gb in ("workflow", "both") else None,
        "partial_errors": errors or None,
    }


def search_component(
    *,
    components_in: list[str],
    workflow_state_in: list[str] | None = None,
    impact_in: list[str] | None = None,
    embargoed: bool | None = None,
    changed_after: str | None = None,
    changed_before: str | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Find flaws whose flaw-level ``components`` intersect ``components_in`` (OSIDB v2 flaws list).
    For PS ``ps_component`` matching, use ``search_flaws`` / ``flaws_list`` with ``affects_ps_component_in``.
    """
    return flaws_list(
        components_in=components_in,
        workflow_state_in=workflow_state_in,
        impact_in=impact_in,
        embargoed=embargoed,
        changed_after=changed_after,
        changed_before=changed_before,
        limit=limit,
        offset=offset,
        api_version=api_version,
        extra_query=extra_query,
    )


def query_affects(
    *,
    flaw_cve_id: str | None = None,
    flaw_cve_id_in: list[str] | None = None,
    flaw_uuid: str | None = None,
    flaw_uuid_in: list[str] | None = None,
    ps_module_in: list[str] | None = None,
    ps_component_in: list[str] | None = None,
    limit: int = DEFAULT_LIST_LIMIT,
    offset: int = 0,
    api_version: str | None = None,
    extra_query: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """List affect rows for one CVE or many CVE ids (OSIDB v2 affects API)."""
    return affects_list(
        flaw_cve_id=flaw_cve_id,
        flaw_cve_id_in=flaw_cve_id_in,
        flaw_uuid=flaw_uuid,
        flaw_uuid_in=flaw_uuid_in,
        ps_module_in=ps_module_in,
        ps_component_in=ps_component_in,
        limit=limit,
        offset=offset,
        api_version=api_version,
        extra_query=extra_query,
    )


def get_pending_exploit_actions(
    *,
    api_version: Literal["v1", "v2"] = "v2",
) -> dict[str, Any]:
    """
    Pending exploit / IR actions report (``GET /exploits/api/v…/report/pending``).
    Experimental on some OSIDB deployments; may 404 if the exploits app is disabled.
    """
    try:
        client = get_session().get_client_with_new_access_token()
        if api_version == "v1":
            from osidb_bindings.bindings.python_client.api.exploits import (
                exploits_api_v1_report_pending_retrieve,
            )

            r = exploits_api_v1_report_pending_retrieve.sync_detailed(client=client)
        else:
            from osidb_bindings.bindings.python_client.api.exploits import (
                exploits_api_v2_report_pending_retrieve,
            )

            r = exploits_api_v2_report_pending_retrieve.sync_detailed(client=client)
        if r.parsed is None:
            return {
                "ok": False,
                "error": "empty_response",
                "status_code": int(r.status_code),
            }
        return {"ok": True, "report": to_jsonable(r.parsed.to_dict())}
    except requests.RequestException as e:
        return {"ok": False, **http_error_payload(e)}
