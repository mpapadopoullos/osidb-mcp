"""FastMCP application wiring (stdio)."""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from osidb_mcp.config import AccessMode, Settings
from osidb_mcp import tools_read


_READONLY_INSTRUCTIONS = """\
This server exposes read-only OSIDB operations (flaws/CVEs, affects, trackers, comments, references, CVSS) \
via official osidb-bindings. Responses may include embargoed data depending on your OSIDB account.

Flaw payloads include a stable ``uuid`` from OSIDB. When ``cve_id`` is missing or not yet assigned, use that \
``uuid`` as ``flaw_id`` for retrieve/subresource tools, and use ``flaw_uuid`` / ``affects_flaw_uuid`` on list APIs \
for affects and trackers (see tool descriptions).

Use high-level tools ``search_flaws``, ``get_flaw_details``, and ``get_cve_summary`` for triage-style search and rollups; \
use lower-level ``flaws_list`` / ``flaws_count`` when you need full filter control.
"""

_READWRITE_INSTRUCTIONS = _READONLY_INSTRUCTIONS + """\

This server is running in **readwrite** mode. Mutation tools (``flaw_create``, ``flaw_update``, \
``flaw_label_add``, ``flaw_incident_request``, ``affects_bulk_*``, etc.) are available in addition to \
all read-only tools. Write operations contact OSIDB and create real data; treat transcripts accordingly.
"""


def create_server(settings: Settings) -> FastMCP:
    is_readwrite = settings.access_mode == AccessMode.readwrite
    instructions = _READWRITE_INSTRUCTIONS if is_readwrite else _READONLY_INSTRUCTIONS
    mcp = FastMCP("osidb-mcp", instructions=instructions)

    mcp.tool(name="osidb_status", description="OSIDB API health / status payload.")(
        tools_read.osidb_status
    )
    mcp.tool(
        name="osidb_whoami",
        description="Current authenticated OSIDB user / profile (from /osidb/whoami).",
    )(tools_read.osidb_whoami)
    mcp.tool(
        name="flaw_get",
        description=(
            "Retrieve a single flaw by CVE id or internal OSIDB uuid; optional field projection. "
            "When cve_id is absent, responses duplicate ``osidb_flaw_uuid`` at the top level for follow-up calls."
        ),
    )(tools_read.flaw_get)
    mcp.tool(
        name="search_flaws",
        description=(
            "Search CVEs/flaws by keyword, CVE id(s), severity (impact), changed date range, "
            "PS product modules or components, workflow, major incident state, embargo, and owner. "
            "Keyword-only queries use OSIDB full-text search; structured filters use list APIs."
        ),
    )(tools_read.search_flaws)
    mcp.tool(
        name="get_flaw_details",
        description=(
            "Full flaw payload plus affects and trackers (Jira/Bugzilla filings) for one flaw. "
            "``flaw_id`` may be a CVE string or internal ``uuid``. If the flaw has no CVE yet, nested lists "
            "are queried via ``flaw__uuid`` / ``affects__flaw__uuid`` automatically."
        ),
    )(tools_read.get_flaw_details)
    mcp.tool(
        name="get_cve_summary",
        description=(
            "Executive-style aggregates: flaw counts by severity (impact) and by workflow state, "
            "with optional scope filters (dates, modules, components, embargo, owner). "
            "Runs multiple OSIDB count queries (see group_by: severity | workflow | both)."
        ),
    )(tools_read.get_cve_summary)
    mcp.tool(
        name="flaws_list",
        description=(
            "List flaws with filters: components, affects (ps_module/ps_component/ps_update_stream), "
            "workflow_state, impact, owner_isempty, embargoed, dates, etc. "
            "Optional ``extra_query`` must use OSIDB v2 list query keys (allowlisted). "
            "limit is capped at 100. Successful responses include ``identifier_hint`` for CVE vs uuid handling."
        ),
    )(tools_read.flaws_list)
    mcp.tool(
        name="flaws_count",
        description="Count flaws matching the same filters as flaws_list (no result bodies).",
    )(tools_read.flaws_count)
    mcp.tool(
        name="flaws_search",
        description=(
            "Full-text search flaws (maps to OSIDB search parameter). "
            "Successful responses include ``identifier_hint`` for CVE vs uuid handling."
        ),
    )(tools_read.flaws_search)
    mcp.tool(
        name="affects_list",
        description=(
            "List affects with ps_module / ps_component / ps_update_stream and flaw__ filters "
            "(e.g. flaw_workflow_state_in, flaw_impact_in, flaw_components_in). "
            "Scope by flaw using ``flaw_cve_id`` / ``flaw_cve_id_in`` or ``flaw_uuid`` / ``flaw_uuid_in`` when there is no CVE."
        ),
    )(tools_read.affects_list)
    mcp.tool(
        name="trackers_list",
        description=(
            "List trackers (filings) with optional CVE / ps_module / ps_component filters. "
            "Scope by flaw using ``affects_flaw_cve_id`` (or ``_in``) or ``affects_flaw_uuid`` (or ``_in``) when there is no CVE."
        ),
    )(tools_read.trackers_list)
    mcp.tool(
        name="flaw_comments_list",
        description="Paginated comments for a flaw id.",
    )(tools_read.flaw_comments_list)
    mcp.tool(
        name="flaw_references_list",
        description="Paginated external references for a flaw id.",
    )(tools_read.flaw_references_list)
    mcp.tool(
        name="flaw_cvss_scores_list",
        description="Paginated CVSS score rows for a flaw id.",
    )(tools_read.flaw_cvss_scores_list)
    mcp.tool(
        name="flaw_acknowledgments_list",
        description="Paginated acknowledgments for a flaw id (CVE or uuid).",
    )(tools_read.flaw_acknowledgments_list)
    mcp.tool(
        name="flaw_labels_list",
        description="Paginated collaborator labels for a flaw id.",
    )(tools_read.flaw_labels_list)
    mcp.tool(
        name="flaw_package_versions_list",
        description="Paginated package version rows for a flaw id.",
    )(tools_read.flaw_package_versions_list)
    mcp.tool(
        name="affect_get",
        description=(
            "Retrieve one affect by OSIDB uuid; optional ``include_fields`` / ``exclude_fields`` "
            "and ``include_history``."
        ),
    )(tools_read.affect_get)
    mcp.tool(
        name="tracker_get",
        description=(
            "Retrieve one tracker filing by uuid; optional ``include_fields`` / ``exclude_fields``."
        ),
    )(tools_read.tracker_get)
    mcp.tool(
        name="tracker_suggestions",
        description=(
            "Get tracker filing suggestions for a flaw (POST /trackers/api/v2/file). "
            "Returns which streams are recommended for filing (selected=true means "
            "acked/non-community/supported) and which are not applicable. "
            "Use before ``tracker_create`` or ``trackers_bulk_file`` to preview."
        ),
    )(tools_read.tracker_suggestions)
    mcp.tool(
        name="labels_list",
        description=(
            "Paginated global OSIDB labels (``GET /labels``). ``extra_query`` allowlisted (typically ``limit``/``offset``)."
        ),
    )(tools_read.labels_list)
    mcp.tool(
        name="affect_cvss_scores_list",
        description=(
            "Paginated CVSS score rows for one affect (by affect uuid). Optional allowlisted ``extra_query``."
        ),
    )(tools_read.affect_cvss_scores_list)
    mcp.tool(
        name="affect_cvss_score_get",
        description=(
            "Retrieve a single CVSS score for an affect by affect uuid and score id. "
            "Optional ``include_fields`` / ``exclude_fields``."
        ),
    )(tools_read.affect_cvss_score_get)
    mcp.tool(
        name="flaw_comment_get",
        description="Retrieve a single comment on a flaw by flaw id and comment id.",
    )(tools_read.flaw_comment_get)
    mcp.tool(
        name="flaw_label_get",
        description="Retrieve a single collaborator label on a flaw by flaw id and label id.",
    )(tools_read.flaw_label_get)
    mcp.tool(
        name="flaw_acknowledgment_get",
        description=(
            "Retrieve a single acknowledgment on a flaw by flaw id and acknowledgment id. "
            "Optional ``include_fields`` / ``exclude_fields``."
        ),
    )(tools_read.flaw_acknowledgment_get)
    mcp.tool(
        name="flaw_reference_get",
        description=(
            "Retrieve a single reference on a flaw by flaw id and reference id. "
            "Optional ``include_fields`` / ``exclude_fields``."
        ),
    )(tools_read.flaw_reference_get)
    mcp.tool(
        name="flaw_cvss_score_get",
        description=(
            "Retrieve a single CVSS score on a flaw by flaw id and score id. "
            "Optional ``include_fields`` / ``exclude_fields``."
        ),
    )(tools_read.flaw_cvss_score_get)
    mcp.tool(
        name="flaw_package_version_get",
        description=(
            "Retrieve a single package version entry on a flaw by flaw id and version id. "
            "Optional ``include_fields`` / ``exclude_fields``."
        ),
    )(tools_read.flaw_package_version_get)
    mcp.tool(
        name="alerts_list",
        description=(
            "List validation alerts with optional filters: parent_uuid, parent_model, "
            "name, alert_type. Supports ``include_fields`` / ``exclude_fields``."
        ),
    )(tools_read.alerts_list)
    mcp.tool(
        name="alert_get",
        description="Retrieve a single alert by UUID.",
    )(tools_read.alert_get)
    mcp.tool(
        name="exploits_epss",
        description=(
            "List EPSS (Exploit Prediction Scoring System) scores. "
            "Paginated via limit/offset."
        ),
    )(tools_read.exploits_epss)
    mcp.tool(
        name="exploits_cve_map",
        description="Get the CVE exploit map — check which CVEs have known exploits.",
    )(tools_read.exploits_cve_map)
    mcp.tool(
        name="exploits_report_date",
        description=(
            "Get an exploit report for a specific date (ISO 8601, e.g. '2026-06-01'). "
            "Supports v1 and v2 API versions."
        ),
    )(tools_read.exploits_report_date)
    mcp.tool(
        name="exploits_report_explanations",
        description="Get explanations for exploit report findings. Supports v1/v2.",
    )(tools_read.exploits_report_explanations)
    mcp.tool(
        name="exploits_flaw_data",
        description="List exploit-enriched flaw data. Paginated. Supports v1/v2.",
    )(tools_read.exploits_flaw_data)
    mcp.tool(
        name="workflows_list",
        description="List available OSIDB workflow definitions.",
    )(tools_read.workflows_list)
    mcp.tool(
        name="workflow_get",
        description="Get details for a specific workflow by id. Use verbose=true for full state graph.",
    )(tools_read.workflow_get)
    mcp.tool(
        name="search_component",
        description=(
            "Find flaws touching flaw-level ``components`` values (``components_in``). "
            "For PS ``ps_component`` filters, use ``search_flaws`` / ``flaws_list`` instead."
        ),
    )(tools_read.search_component)
    mcp.tool(
        name="query_affects",
        description=(
            "List affect rows for one or more CVEs and/or flaw UUIDs (v2 affects API); thin wrapper over ``affects_list``."
        ),
    )(tools_read.query_affects)
    mcp.tool(
        name="get_pending_exploit_actions",
        description=(
            "[EXPERIMENTAL] Pending exploit / IR actions from ``GET /exploits/api/v1|v2/report/pending``. "
            "May fail if the exploits integration is not enabled on this OSIDB instance."
        ),
    )(tools_read.get_pending_exploit_actions)

    if is_readwrite:
        from osidb_mcp import tools_write
        from osidb_mcp import tools_workflow

        mcp.tool(
            name="flaw_create",
            description=(
                "Create a new OSIDB flaw with optional sub-resources (acknowledgments, references, CVSS scores) "
                "in a single composite operation. The flaw is created first via POST /osidb/api/v2/flaws, then "
                "each sub-resource is created sequentially via v1 endpoints. Returns the flaw uuid and all "
                "created sub-resource uuids. Supports partial-success reporting if the flaw was created but "
                "a sub-resource call failed."
            ),
        )(tools_write.flaw_create)

        mcp.tool(
            name="flaw_update",
            description=(
                "Update fields on an existing OSIDB flaw (PUT /osidb/api/v2/flaws/{id}). "
                "Auto-fetches the current flaw to obtain ``updated_dt`` for optimistic concurrency. "
                "Only the fields you provide are changed; all others keep their current values. "
                "Supports ``owner`` assignment (Jira username for workflow prerequisites)."
            ),
        )(tools_write.flaw_update)

        mcp.tool(
            name="affect_add",
            description=(
                "Add one or more affects to an existing flaw (POST /osidb/api/v2/affects). "
                "``flaw_id`` must be the internal UUID. Each affect needs at least ``ps_update_stream``."
            ),
        )(tools_write.affect_add)

        mcp.tool(
            name="affect_remove",
            description=(
                "Remove one or more affects by UUID (DELETE /osidb/api/v2/affects/{uuid})."
            ),
        )(tools_write.affect_remove)

        mcp.tool(
            name="flaw_acknowledgment_add",
            description=(
                "Add acknowledgment(s) to an existing flaw (POST /osidb/api/v1/flaws/{id}/acknowledgments). "
                "Each acknowledgment needs at least ``name``."
            ),
        )(tools_write.flaw_acknowledgment_add)

        mcp.tool(
            name="flaw_acknowledgment_remove",
            description=(
                "Remove an acknowledgment from a flaw by UUID "
                "(DELETE /osidb/api/v1/flaws/{id}/acknowledgments/{sub_id})."
            ),
        )(tools_write.flaw_acknowledgment_remove)

        mcp.tool(
            name="flaw_reference_add",
            description=(
                "Add reference(s) to an existing flaw (POST /osidb/api/v1/flaws/{id}/references). "
                "Each reference needs at least ``url``."
            ),
        )(tools_write.flaw_reference_add)

        mcp.tool(
            name="flaw_reference_remove",
            description=(
                "Remove a reference from a flaw by UUID "
                "(DELETE /osidb/api/v1/flaws/{id}/references/{sub_id})."
            ),
        )(tools_write.flaw_reference_remove)

        mcp.tool(
            name="flaw_cvss_add",
            description=(
                "Add CVSS score(s) to an existing flaw "
                "(POST /osidb/api/v1/flaws/{id}/cvss_scores). "
                "Each score needs ``cvss_version`` (V3 or V4) and ``vector``."
            ),
        )(tools_write.flaw_cvss_add)

        mcp.tool(
            name="flaw_cvss_remove",
            description=(
                "Remove a CVSS score from a flaw by UUID "
                "(DELETE /osidb/api/v1/flaws/{id}/cvss_scores/{sub_id})."
            ),
        )(tools_write.flaw_cvss_remove)

        mcp.tool(
            name="affect_update",
            description=(
                "Update fields on an existing affect (PUT /osidb/api/v2/affects/{uuid}). "
                "Auto-fetches the current affect for optimistic concurrency. "
                "Only provided fields are changed; others keep current values."
            ),
        )(tools_write.affect_update)

        mcp.tool(
            name="tracker_create",
            description=(
                "Create a single tracker (Jira/Bugzilla ticket) for one or more affects "
                "(POST /osidb/api/v2/trackers). Requires affect_uuids, ps_update_stream, "
                "and embargoed. Use ``tracker_suggestions`` first to identify valid streams. "
                "Set sync_to_bz=false when batch-filing, true on the last call."
            ),
        )(tools_write.tracker_create)

        mcp.tool(
            name="trackers_bulk_file",
            description=(
                "Bulk-file trackers for a flaw. Gets suggestions from OSIDB, filters to "
                "recommended streams (acked, non-community), and files trackers sequentially "
                "with sync_to_bz optimization. Use dry_run=true to preview without filing. "
                "Set only_selected=false to file ALL available streams."
            ),
        )(tools_write.trackers_bulk_file)

        mcp.tool(
            name="flaw_comment_create",
            description=(
                "Create a comment on a flaw "
                "(POST /osidb/api/v1/flaws/{id}/comments). "
                "Auto-fetches the flaw's embargoed status. "
                "Optional ``creator`` sets the comment author (defaults to authenticated user)."
            ),
        )(tools_write.flaw_comment_create)

        mcp.tool(
            name="flaw_label_add",
            description=(
                "Add a collaborator label to a flaw "
                "(POST /osidb/api/v1/flaws/{id}/labels). "
                "Requires flaw UUID. Optional state (NEW, REQ, DONE, SKIP), contributor, label_type."
            ),
        )(tools_write.flaw_label_add)

        mcp.tool(
            name="flaw_label_remove",
            description=(
                "Remove a label from a flaw "
                "(DELETE /osidb/api/v1/flaws/{id}/labels/{id}). "
                "Requires flaw UUID."
            ),
        )(tools_write.flaw_label_remove)

        mcp.tool(
            name="flaw_incident_request",
            description=(
                "Create an incident request on a flaw "
                "(POST /osidb/api/v1/flaws/{id}/incident-requests). "
                "Kind: MAJOR_INCIDENT_REQUESTED, MINOR_INCIDENT_REQUESTED, or EXPLOITS_KEV_REQUESTED."
            ),
        )(tools_write.flaw_incident_request)

        mcp.tool(
            name="flaw_acknowledgment_update",
            description=(
                "Update an acknowledgment on a flaw "
                "(PUT /osidb/api/v1/flaws/{id}/acknowledgments/{id}). "
                "Auto-fetches the current acknowledgment for optimistic concurrency."
            ),
        )(tools_write.flaw_acknowledgment_update)

        mcp.tool(
            name="flaw_reference_update",
            description=(
                "Update a reference on a flaw "
                "(PUT /osidb/api/v1/flaws/{id}/references/{id}). "
                "Auto-fetches the current reference for optimistic concurrency."
            ),
        )(tools_write.flaw_reference_update)

        mcp.tool(
            name="flaw_cvss_update",
            description=(
                "Update a CVSS score on a flaw "
                "(PUT /osidb/api/v1/flaws/{id}/cvss_scores/{id}). "
                "Auto-fetches the current score for optimistic concurrency."
            ),
        )(tools_write.flaw_cvss_update)

        mcp.tool(
            name="flaw_package_version_add",
            description=(
                "Add package version info to a flaw "
                "(POST /osidb/api/v1/flaws/{id}/package_versions). "
                "Each version needs ``version`` and ``status`` (AFFECTED, UNAFFECTED, UNKNOWN)."
            ),
        )(tools_write.flaw_package_version_add)

        mcp.tool(
            name="affects_bulk_create",
            description=(
                "Bulk-create affects in one API call "
                "(POST /osidb/api/v2/affects/bulk). "
                "Each affect needs flaw UUID, ps_module, ps_component, affectedness, embargoed."
            ),
        )(tools_write.affects_bulk_create)

        mcp.tool(
            name="affects_bulk_update",
            description=(
                "Bulk-update affects in one API call "
                "(PUT /osidb/api/v2/affects/bulk). "
                "Each affect needs uuid and updated_dt for optimistic concurrency."
            ),
        )(tools_write.affects_bulk_update)

        mcp.tool(
            name="affects_bulk_delete",
            description=(
                "Bulk-delete affects in one API call "
                "(DELETE /osidb/api/v2/affects/bulk). "
                "Provide list of affect UUID strings."
            ),
        )(tools_write.affects_bulk_delete)

        mcp.tool(
            name="flaw_promote",
            description=(
                "Promote a flaw to the next workflow state "
                "(POST /osidb/api/{version}/flaws/{id}/promote). "
                "States: NEW -> TRIAGE -> PRE_SECONDARY_ASSESSMENT -> "
                "SECONDARY_ASSESSMENT -> DONE. Returns 400 if prerequisites are not met."
            ),
        )(tools_workflow.flaw_promote)

        mcp.tool(
            name="flaw_reject",
            description=(
                "Reject a flaw, moving it to REJECTED state "
                "(POST /osidb/api/{version}/flaws/{id}/reject). "
                "Requires a reason. Only from NEW or TRIAGE states."
            ),
        )(tools_workflow.flaw_reject)

        mcp.tool(
            name="flaw_reset",
            description=(
                "Reset a flaw back to NEW state "
                "(POST /osidb/api/{version}/flaws/{id}/reset). "
                "Can be called from NEW, TRIAGE, or DONE states."
            ),
        )(tools_workflow.flaw_reset)

        mcp.tool(
            name="flaw_revert",
            description=(
                "Revert a flaw to its previous workflow state "
                "(POST /osidb/api/{version}/flaws/{id}/revert). "
                "Moves one step backward: DONE -> SECONDARY_ASSESSMENT -> "
                "PRE_SECONDARY_ASSESSMENT -> TRIAGE -> NEW."
            ),
        )(tools_workflow.flaw_revert)

    return mcp
