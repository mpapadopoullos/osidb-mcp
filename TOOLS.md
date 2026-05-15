# osidb-mcp — Tools reference

This document describes each MCP tool exposed by **osidb-mcp**: what it is for, how analysts or agents usually invoke it (natural-language style), and important limitations. Install from [PyPI](https://pypi.org/project/osidb-mcp/) (`pip install osidb-mcp` or `pipx install osidb-mcp`). Environment variables and Kerberos/basic auth are covered in [README.md](README.md). Source code lives at [github.com/vdanen/osidb-mcp](https://github.com/vdanen/osidb-mcp). **LLM agents:** model choice and token discipline are covered under [Using with AI agents](README.md#using-with-ai-agents) in the README.

## Shared behaviour (read this once)

- **Authentication:** Every tool below (except your client’s own handling) assumes `OSIDB_BASE_URL` and a working session — Kerberos ticket or basic auth — as described in the README. Tokens are obtained and refreshed via **osidb-bindings**; you do not pass tokens into tools.
- **Embargoed data:** Responses may include embargoed flaws or fields depending on your OSIDB account. Treat logs and transcripts accordingly.
- **Pagination:** List-style tools clamp `limit` to **at most 100** and default it to **50** when omitted. Responses include `count`, `limit`, `offset`, and `results`. When `next` / `next_offset` are present, more pages exist — repeat with a higher `offset` (often `next_offset`) until exhausted.
- **`extra_query`:** On `flaws_list`, `flaws_count`, `affects_list`, and `trackers_list`, you may pass additional query keys only if they appear on the official OSIDB **v2** list endpoint for that resource. Unknown keys are rejected. There are caps on how many keys and how long list values may be (see `query_filters.py` in the repo).
- **`api_version`:** Optional string forwarded to bindings when you need a non-default OSIDB API version; leave unset for typical v2 behaviour.
- **Errors:** On failure, tools return JSON with `"ok": false` plus `error` / `detail` / `status_code` fields where applicable, rather than throwing inside the MCP layer.
- **CVE vs `uuid`:** Every flaw has a stable internal **`uuid`** in OSIDB. **`cve_id`** may be empty until assigned. Use **`uuid`** as `flaw_id` for retrieve/subresource tools when there is no CVE; use **`flaw_uuid`** / **`affects_flaw_uuid`** on list APIs. **`flaws_list`** / **`flaws_search`** responses include **`identifier_hint`**; **`flaw_get`** / **`get_flaw_details`** may add **`osidb_flaw_uuid`** when there is no CVE. Omitting **`uuid`** from **`include_fields`** hides it from the payload.
- **Access mode:** Only **`OSIDB_MCP_ACCESS_MODE=readonly`** is accepted (`readwrite` exits at startup). See [SECURITY.md](SECURITY.md).

---

## 1. `osidb_status`

**Purpose:** Lightweight health check — confirms reachability and returns the bindings “status” payload for the configured OSIDB.

**Example prompts:**

```
Q: "Is OSIDB up?"
Q: "Ping the OSIDB server we're configured for"
```

**Returns:** `{ "ok": true, "status": … }` on success.

**Limitations:** This is not a full application health dashboard; it reflects what the bindings expose for API status.

---

## 2. `osidb_whoami`

**Purpose:** Resolves the **current OSIDB user** (profile from `/osidb/whoami`). Use after configuring auth to verify identity and permissions.

**Example prompts:**

```
Q: "Which OSIDB user am I authenticated as?"
Q: "Verify my OSIDB session"
```

**Returns:** `{ "ok": true, "whoami": … }` with user metadata.

**Limitations:** If the endpoint returns an empty body, you get `ok: false` with `whoami_empty` and an HTTP status hint.

---

## 3. `flaw_get`

**Purpose:** Fetch a **single flaw** by identifier with optional field projection. Smallest payload when you already know the CVE or flaw id and do not need affects/trackers bundles.

**Example prompts:**

```
Q: "Get the raw OSIDB flaw record for CVE-2024-6387"
Q: "Retrieve flaw UUID … with only the fields I need"
```

**Typical parameters:**

- `flaw_id` — CVE id (e.g. `CVE-2024-6387`) or internal flaw id string your OSIDB accepts for `GET /flaws/…`.
- `include_fields` / `exclude_fields` — Optional lists to trim the JSON (reduces token usage).

**Returns:** `{ "ok": true, "flaw": … }`. If there is no CVE string on the flaw, **`osidb_flaw_uuid`** is duplicated at the top level (same as `flaw.uuid`) when `uuid` is present in the payload.

**Limitations:** Does **not** include nested affects or trackers; use `get_flaw_details` for that.

---

## 4. `search_flaws`

**Purpose:** **High-level flaw/CVE discovery** — keyword search and/or structured filters (severity, dates, PS modules/components, workflow, major incident state, embargo, unowned).

**Example prompts:**

```
Q: "Search OSIDB for openssh-related CVEs"
Q: "Critical flaws changed in the last 7 days"
Q: "CVEs in triage workflow with IMPORTANT severity"
Q: "Major incident flaws affecting rhel-9"
Q: "List CVE-2024-1234 and CVE-2024-5678 if they exist"
```

**Typical parameters:**

| Parameter | Role |
|-----------|------|
| `keyword` | Free text; if this is the **only** criterion, the tool uses OSIDB **full-text search** (`flaws_search`). |
| `cve_ids` | List of CVE strings → `cve_id_in` on the list API. |
| `severity` / `severities` | Single or multiple OSIDB **impact** values (e.g. `CRITICAL`, `IMPORTANT`). |
| `date_from` / `date_to` | ISO-style timestamps mapped to `changed_after` / `changed_before` on flaws. |
| `product_modules` / `product_components` | Lists mapped to `affects__ps_module__in` / `affects__ps_component__in`. |
| `workflow_state_in` | Workflow states to filter (exact strings OSIDB expects). |
| `major_incident_state` / `major_incident_state_in` | Major incident state filters on flaws (OSIDB list API). |
| `embargoed`, `owner_isempty` | Boolean filters. |
| `limit`, `offset` | Pagination (capped). |

**Returns:** Same envelope as `flaws_list` / `flaws_search` (`count`, `results`, …).

**Limitations:**

- **Keyword-only** queries use **`flaws_search`**, not the filtered list API — behaviour and ranking are OSIDB’s full-text search.
- **PS strings must match OSIDB** (e.g. exact `ps_module` / `ps_component` spellings). Wrong strings return empty sets, not an error.
- **Rejected CVEs:** OSIDB may still return flaws in `REJECTED` (or similar) states unless you filter them explicitly via `workflow_state_in` / `extra_query` where the API allows.
- **Not** a substitute for `flaws_list` when you need every low-level query key; use `flaws_list` + allowlisted `extra_query` for that.

---

## 5. `get_flaw_details`

**Purpose:** **One-call bundle**: flaw record + **affects** (product rows) + **trackers** (Jira/Bugzilla-style filings) so you do not have to chain separate list calls for the common triage view.

**Example prompts:**

```
Q: "Full picture for CVE-2024-6387: flaw, products, trackers"
Q: "What modules are affected and what trackers exist for this CVE?"
```

**Typical parameters:**

- `flaw_id` — Same as `flaw_get`.
- `include_affects` / `include_trackers` — Booleans (default `true`); turn off to save bandwidth.
- `affects_limit` / `trackers_limit` — Per-section caps (each clamped to 100).

**Returns:** `{ "ok", "flaw", "affects": <affects_list envelope>, "trackers": <trackers_list envelope> }`. When there is no CVE, nested sections are scoped by **`flaw__uuid`** / **`affects__flaw__uuid`**, and **`osidb_flaw_uuid`** may appear at the top level like `flaw_get`.

**Limitations:** Each section is paginated separately; if affects or trackers exceed the limit, increase limits or call `affects_list` / `trackers_list` with offsets.

---

## 6. `get_cve_summary`

**Purpose:** **Executive rollups** — total flaw count under shared filters, plus counts **by severity** and/or **by workflow** using multiple `flaws_count` calls.

**Example prompts:**

```
Q: "How many flaws match these filters, broken down by severity?"
Q: "Workflow distribution for critical issues in the last month on rhel-9"
```

**Typical parameters:**

- `group_by` — `"severity"`, `"workflow"`, or `"both"` (default `"both"`).
- Shared scope: `embargoed`, `changed_after`, `changed_before`, `affects_ps_module_in`, **`components_in`** (flaw-level components, not PS component), `owner_isempty`, `extra_query`.

**Returns:** Totals, `by_severity`, `by_workflow`, and optional `partial_errors` if some bucket queries failed.

**Limitations:**

- **Cost:** Up to one count per severity bucket and per known workflow state — multiple HTTP requests.
- **`components_in` here is flaw-level**, not `affects__ps_component`; use `affects_ps_module_in` / `flaws_list` for PS-centric slices.

---

## 7. `flaws_list`

**Purpose:** **Full filter control** over the OSIDB flaws **list** API — search string, components, nested affects filters, workflow, impact, owner, CVE id list, dates, major incident, source, field projection, and allowlisted `extra_query`.

**Example prompts:**

```
Q: "List flaws with affects on ps_module rhel-8 and component kernel, limit 50"
Q: "Flaws in NEW state with CRITICAL impact"
```

**Typical parameters:** See README table; names mirror query kwargs (`affects_ps_module_in`, `components_in`, `cve_id_in`, `major_incident_state_in`, …).

**Returns:** Paginated `results` plus `count`.

**Limitations:** `limit` ≤ 100. Wrong enum strings for workflow/impact/incident may produce API errors surfaced as `ok: false`.

---

## 8. `flaws_count`

**Purpose:** Same filter surface as `flaws_list` but returns **only** `{ "ok", "count" }` — ideal for dashboards and existence checks.

**Example prompts:**

```
Q: "How many flaws match these filters?"
```

**Limitations:** No `include_fields`; inner list API still applies server-side rules for invalid combinations.

---

## 9. `flaws_search`

**Purpose:** OSIDB **full-text** search over flaws (`search` / text parameter in bindings).

**Example prompts:**

```
Q: "Full-text search OSIDB for 'regreSSHion'"
```

**Typical parameters:** `text` (required), `limit`, `api_version`.

**Limitations:** Offset is fixed to `0` in the wrapper; deep paging of search results may require OSIDB capabilities beyond this thin tool.

**Note:** `search_flaws` already routes keyword-only queries here automatically.

---

## 10. `affects_list`

**Purpose:** List **affect** rows (PS module/component/update stream, affectedness, resolution, embedded flaw summary fields as returned by OSIDB). Best for **product- or stream-centric** questions.

**Example prompts:**

```
Q: "All affects on ps_update_stream rhel-9.6.z for non-LOW impact flaws"
Q: "Affects for modules matching rhel-9 with flaw workflow NEW"
```

**Typical parameters:** `ps_module` / `ps_module_in`, `ps_component` / `ps_component_in`, `ps_update_stream` / `ps_update_stream_in`, `flaw_cve_id` / `flaw_cve_id_in`, **`flaw_uuid`** / **`flaw_uuid_in`** (when the flaw has no CVE yet), `flaw_workflow_state_in`, `flaw_impact_in`, `flaw_components_in`, `embargoed`, field lists, `extra_query`.

**Returns:** Paginated affect objects.

**Limitations:** Interpreting **resolution** (e.g. `DELEGATED`) is a business rule: it does not by itself mean engineering work is active — pair with `trackers_list` / `get_flaw_details` for tracker state.

---

## 11. `trackers_list`

**Purpose:** List **tracker filings** linked via affects — Jira/Bugzilla types, statuses, resolutions, CVE scope, PS filters.

**Example prompts:**

```
Q: "All trackers for CVE-2024-6387"
Q: "Trackers for affects on component httpd in rhel-8"
```

**Typical parameters:** `affects_flaw_cve_id`, `affects_flaw_cve_id_in`, **`affects_flaw_uuid`**, **`affects_flaw_uuid_in`**, `affects_ps_module_in`, `affects_ps_component_in`, `tracker_type`, pagination, `extra_query`.

**Returns:** Paginated tracker rows.

**Limitations:** **Tracker status** (workflow in the bug tracker) is not the same as **flaw workflow** in OSIDB or **exploit** workflow; compare tools intentionally.

---

## 12. `flaw_comments_list`

**Purpose:** Paginated **discussion comments** for a flaw.

**Example prompts:**

```
Q: "Comments on flaw … for context on the triage decision"
```

**Typical parameters:** `flaw_id` (same identifier style as other flaw subresources), `limit`, `offset`.

**Returns:** Paginated comment objects (text, author, timestamps — exact shape from OSIDB).

**Limitations:** Requires the same **flaw id** form OSIDB expects for subresource routes (often the internal UUID from the flaw record; if CVE does not work for subresources in your deployment, resolve the flaw first with `flaw_get` / `get_flaw_details` and use `uuid` from the payload).

---

## 13. `flaw_references_list`

**Purpose:** External **references** (URLs, advisory IDs, etc.) attached to a flaw.

**Example prompts:**

```
Q: "List all external references for this flaw"
```

**Limitations:** Same `flaw_id` caveat as comments.

---

## 14. `flaw_cvss_scores_list`

**Purpose:** Paginated **CVSS score** rows (issuer, version, vector, scores) for a flaw.

**Example prompts:**

```
Q: "Show CVSS vectors stored on this flaw"
```

**Limitations:** Same `flaw_id` caveat as comments.

---

## Supplementary read tools

Additional lists and single-record reads registered after **`flaw_cvss_scores_list`** in [`server.py`](src/osidb_mcp/server.py).

### `flaw_acknowledgments_list`

Paginated acknowledgments for a **`flaw_id`** (CVE or uuid). Same **`limit`** / **`offset`** / **`api_version`** pattern as **`flaw_comments_list`**.

### `flaw_labels_list`

Paginated collaborator **labels** on a flaw.

### `flaw_package_versions_list`

Paginated package-version rows attached to a flaw.

### `affect_get`

Single affect record by **OSIDB affect uuid** (`affect_id`). Optional **`include_fields`**, **`exclude_fields`**, **`include_history`**.

### `tracker_get`

Single tracker filing by **uuid** (`tracker_id`). Optional **`include_fields`**, **`exclude_fields`**, **`include_meta_attr`**.

### `labels_list`

Paginated **global** labels (`GET …/labels`). **`extra_query`** keys are allowlisted from the bindings labels list endpoint (typically **`limit`** / **`offset`** only).

### `affect_cvss_scores_list`

Paginated CVSS score rows for one affect (**affect uuid**). Supports optional **`extra_query`** allowlisted from the v2 affects CVSS list endpoint.

---

## 15. `search_component`

**Purpose:** Find flaws whose **flaw-level** `components` field intersects a list of names — implemented as `flaws_list` with `components_in`.

**Example prompts:**

```
Q: "Flaws tagged with component runc at the flaw level"
```

**Typical parameters:** `components_in` (required list), optional `workflow_state_in`, `impact_in`, `embargoed`, date range, pagination, `extra_query`.

**Limitations:** This is **not** the same as searching **`ps_component`** on affects. For Product Security component paths, use **`search_flaws`** / **`flaws_list`** with `product_components` / `affects_ps_component_in`.

---

## 16. `query_affects`

**Purpose:** Convenience wrapper over **`affects_list`** for **CVE- or UUID-scoped** pulls: one CVE (`flaw_cve_id`) or many (`flaw_cve_id_in`), or one flaw UUID (`flaw_uuid`) / many (`flaw_uuid_in`), plus optional PS filters.

**Example prompts:**

```
Q: "All affect rows for CVE-2024-6387"
Q: "Affects for these ten CVEs on rhel-9"
Q: "Affects for flaw uuid … (no CVE yet)"
```

**Typical parameters:** `flaw_cve_id`, `flaw_cve_id_in`, `flaw_uuid`, `flaw_uuid_in`, `ps_module_in`, `ps_component_in`, `limit`, `offset`, `extra_query`.

**Limitations:** Inherits all `affects_list` semantics and limits; large `flaw_cve_id_in` lists are still subject to URL/query length limits on the server.

---

## 17. `get_pending_exploit_actions`

**Purpose:** **[EXPERIMENTAL]** Calls `GET /exploits/api/v1/report/pending` or `GET /exploits/api/v2/report/pending` and returns the parsed report JSON.

**Example prompts:**

```
Q: "Are there pending exploit / IR actions on this OSIDB?"
Q: "Fetch the v1 pending exploit report"
```

**Typical parameters:**

- `api_version` — `"v2"` (default) or `"v1"`.

**Returns:** `{ "ok": true, "report": … }` on success; `ok: false` on HTTP/network issues or empty parsed body.

**Limitations:**

- Many deployments **disable** or do not deploy the exploits app — expect **404** or similar; handle `ok: false` gracefully.
- **This tool does not take CVE / PS component / update-stream parameters** — only `api_version`. Anything filterable is inside the **report** payload returned by OSIDB. For engineering tracker state, use **`trackers_list`** / **`get_flaw_details`**.

---

## When to use which (cheat sheet)

| Goal | Tool |
|------|------|
| Natural-language / triage style search | `search_flaws` |
| One CVE: flaw + products + trackers | `get_flaw_details` |
| Dashboard counts | `get_cve_summary`, `flaws_count` |
| Exact OpenAPI / rare filters | `flaws_list` + allowlisted `extra_query` |
| Product or update stream lens | `affects_list`, `query_affects` |
| Filing / engineering trackers | `trackers_list` |
| Comments, refs, CVSS, acknowledgments, labels, package versions | `flaw_*_list` tools |
| One affect or tracker by uuid | `affect_get`, `tracker_get` |
| Global label catalog | `labels_list` |
| CVSS rows per affect | `affect_cvss_scores_list` |
| Health / identity | `osidb_status`, `osidb_whoami` |

For configuration snippets (Cursor, Claude, env vars), see [README.md](README.md).
