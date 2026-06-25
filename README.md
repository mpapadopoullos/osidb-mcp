# osidb-mcp

Python [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for [OSIDB](https://github.com/RedHatProductSecurity/osidb), built on [`osidb-bindings`](https://github.com/RedHatProductSecurity/osidb-bindings). Use it from Cursor, Claude Desktop, or any MCP client over **stdio**. Forked from [vdanen/osidb-mcp](https://github.com/vdanen/osidb-mcp) with added **write/mutation tools**.

## Install

```bash
pip install -e .
# or
uv pip install -e .
```

## Configuration (environment)

| Variable | Required | Description |
|----------|----------|-------------|
| `OSIDB_BASE_URL` | yes | OSIDB root URL, e.g. `https://osidb.example.com` |
| `OSIDB_AUTH` | no | `kerberos` (default) or `basic` |
| `OSIDB_USERNAME` / `OSIDB_PASSWORD` | for `basic` | Basic auth for token obtain |
| `OSIDB_VERIFY_SSL` | no | `true` (default) or `false` (prefer `REQUESTS_CA_BUNDLE` for custom CAs) |
| `OSIDB_USER_AGENT` | no | Optional extra User-Agent suffix |
| `OSIDB_MCP_ACCESS_MODE` | no | `readonly` (default) or `readwrite`. Readwrite mode registers mutation tools (flaw create/update, affects, acknowledgments, references). |
| `ENABLE_BUGZILLA_TOOLS` | no | `false` (default). When `true`, registers the `flaw_comment_create` tool (requires `readwrite` mode). |

Kerberos: the process must have a valid ticket (`kinit`) for the OSIDB HTTP service.

Optional keys forwarded by bindings: `BUGZILLA_API_KEY`, `JIRA_ACCESS_TOKEN`, `JIRA_API_EMAIL`.

## Cursor / Claude MCP snippet

```json
{
  "mcpServers": {
    "osidb": {
      "command": "osidb-mcp",
      "env": {
        "OSIDB_BASE_URL": "https://your-internal-osidb",
        "OSIDB_AUTH": "kerberos",
        "OSIDB_VERIFY_SSL": "true",
        "OSIDB_MCP_ACCESS_MODE": "readonly"
      }
    }
  }
}
```

## Tools

All **MCP tools** require a working OSIDB session (env + Kerberos or basic auth). The table lists every registered tool, in the same order as [`server.py`](src/osidb_mcp/server.py). For longer explanations, example prompts, and limitations, see **[TOOLS.md](TOOLS.md)**. If an **LLM agent** is calling these tools, read **[Using with AI agents](#using-with-ai-agents)** first.

### Read-only tools

| Tool | Purpose |
|------|---------|
| `osidb_status` | OSIDB API health / status payload (good connectivity check). |
| `osidb_whoami` | Current authenticated user / profile from `GET /osidb/whoami`. |
| `flaw_get` | One flaw by CVE id or internal **`uuid`**; optional `include_fields` / `exclude_fields`. Adds **`osidb_flaw_uuid`** at top level when there is no CVE yet. |
| `search_flaws` | High-level search: keyword and/or CVE ids, severity (`severity` / `severities`), changed-date range (`date_from` / `date_to`), PS `product_modules` / `product_components`, workflow, embargo, owner; keyword-only uses OSIDB full-text search. |
| `get_flaw_details` | Full flaw plus **affects** and **trackers**; `flaw_id` is CVE or **`uuid`**. If no CVE, nested lists use **`flaw__uuid`** / **`affects__flaw__uuid`**. |
| `get_cve_summary` | Executive rollups: counts **by severity** and **by workflow** plus total under shared filters (`group_by`: `severity` \| `workflow` \| `both`); multiple `flaws_count` calls; see `partial_errors` if a bucket fails. |
| `flaws_list` | Raw list API: components, nested affects filters (`affects_ps_*`), workflow, impact, owner, embargo, dates, `search`, allowlisted `extra_query` (OSIDB v2 query keys); `limit` ≤ 100. Success responses include **`identifier_hint`** (CVE vs `uuid`). |
| `flaws_count` | Same filter surface as `flaws_list` but returns **count** only (no flaw bodies). |
| `flaws_search` | Full-text search over flaws (`search` parameter); paginated like list APIs. Success responses include **`identifier_hint`**. |
| `affects_list` | Rows keyed by **affect** with `flaw__*` filters; scope flaw by **`flaw_cve_id`** / **`flaw_cve_id_in`** or **`flaw_uuid`** / **`flaw_uuid_in`** when there is no CVE. |
| `trackers_list` | Tracker filings; scope by **`affects_flaw_cve_id`** (or `_in`) or **`affects_flaw_uuid`** (or `_in`) when there is no CVE; optional PS filters and `tracker_type`. |
| `flaw_comments_list` | Paginated **discussion comments** for a flaw id. |
| `flaw_references_list` | Paginated **external references** (URLs, advisory refs, etc.) for a flaw id. |
| `flaw_cvss_scores_list` | Paginated **CVSS score** rows (issuer/version/vector) for a flaw id. |
| `flaw_acknowledgments_list` | Paginated **acknowledgments** for a flaw id (CVE or `uuid`). |
| `flaw_labels_list` | Paginated flaw **collaborator labels** for a flaw id. |
| `flaw_package_versions_list` | Paginated **package version** rows for a flaw id. |
| `affect_get` | Single **affect** by OSIDB uuid; optional field projection and `include_history`. |
| `tracker_get` | Single **tracker filing** by uuid; optional field projection / `include_meta_attr`. |
| `labels_list` | Paginated **global** OSIDB labels (`GET /labels`); optional allowlisted `extra_query`. |
| `affect_cvss_scores_list` | Paginated **CVSS** rows for one affect (by affect uuid); optional allowlisted `extra_query`. |
| `search_component` | Flaws whose flaw-level **components** intersect `components_in` (v2 flaws list); optional impact/workflow/date filters. |
| `query_affects` | **Affect rows** by CVE (`flaw_cve_id` / `flaw_cve_id_in`) and/or flaw UUID (`flaw_uuid` / `flaw_uuid_in`); wrapper over `affects_list`. |
| `get_pending_exploit_actions` | **[EXPERIMENTAL]** `GET /exploits/api/v1|v2/report/pending` — pending exploit / IR actions; may 404 if exploits app is off. |

`limit` (and analogous list limits) are capped at **100** per request unless noted otherwise on a tool.

### Write tools (`readwrite` mode only)

These tools are only registered when `OSIDB_MCP_ACCESS_MODE=readwrite`.

| Tool | Purpose |
|------|---------|
| `flaw_create` | Create a new flaw with optional sub-resources (acknowledgments, references, CVSS scores) in a single composite operation. |
| `flaw_update` | Update fields on an existing flaw. Auto-fetches `updated_dt` for optimistic concurrency. |
| `affect_add` | Add one or more affects to a flaw. Auto-injects `flaw` UUID and `embargoed` from parent flaw. |
| `affect_remove` | Remove one or more affects by UUID. |
| `flaw_acknowledgment_add` | Add acknowledgment(s) to an existing flaw. |
| `flaw_acknowledgment_remove` | Remove an acknowledgment from a flaw. |
| `flaw_reference_add` | Add reference(s) to an existing flaw. |
| `flaw_reference_remove` | Remove a reference from a flaw. |

All write tools return `{"ok": true, ...}` on success. On partial failure (e.g. flaw created but a sub-resource failed), they return `{"ok": true, "partial": true, "errors": [...]}`.

### When to use which

- **Triage / natural language style:** `search_flaws`, `get_flaw_details`, `get_cve_summary`.
- **Exact OpenAPI filters or rare query keys:** `flaws_list` / `flaws_count` with `extra_query` (allowlisted keys only).
- **Affect- or tracker-centric views:** `affects_list`, `trackers_list`, or the subresource tools under a known flaw id.

### Flaw identifiers (CVE vs internal `uuid`)

OSIDB flaws always have an internal **`uuid`**. A **`cve_id`** may be missing until one is assigned — that is normal, not “no identifier.”

- List/search responses include each flaw’s **`uuid`** in JSON. **`flaws_list`**, **`flaws_search`**, and **`search_flaws`** (structured path) also return an **`identifier_hint`** string for agents.
- **`flaw_get`** / **`get_flaw_details`**: when there is no usable CVE string, the tool adds top-level **`osidb_flaw_uuid`** (same value as `flaw.uuid`) so follow-up calls are obvious.
- **`get_flaw_details`**: if `cve_id` is empty, affects and trackers are loaded using **`flaw__uuid`** / **`affects__flaw__uuid`** automatically.
- **`affects_list`** / **`query_affects`**: use **`flaw_uuid`** / **`flaw_uuid_in`** to scope rows when there is no CVE. **`trackers_list`**: use **`affects_flaw_uuid`** / **`affects_flaw_uuid_in`**.
- **`flaw_comments_list`**, **`flaw_references_list`**, **`flaw_cvss_scores_list`**, **`flaw_acknowledgments_list`**, **`flaw_labels_list`**, **`flaw_package_versions_list`**: the `flaw_id` argument is the same as for **`flaw_get`** — CVE string **or** internal **`uuid`**. If you use **`include_fields`** on **`flaw_get`**, include **`uuid`** when you still need it downstream.

## Analyst examples

- **Same idea as “search CVEs”:** use **`search_flaws`** with `keyword`, or combine `cve_ids`, `severity` / `severities`, `date_from` / `date_to`, and `product_modules` / `product_components`.
- **Critical open flaws touching `httpd`:** `search_flaws` or `flaws_list` with `impact="CRITICAL"`, `workflow_state_in` for non-terminal states, and `product_components=["httpd"]` or `components_in` / `affects_ps_component` as your data model requires.
- **Unowned important CVEs for a RHEL major:** `search_flaws` with `owner_isempty=true`, `severities=["IMPORTANT"]`, and `product_modules` / `product_components` set to the **exact** PS strings your OSIDB uses for that major (confirm in your internal docs).
- **Executive rollup:** **`get_cve_summary`** with optional date range and product filters; tune `group_by` if you only need severity or only workflow buckets.

## Using with AI agents

These tools return **structured JSON** (sometimes large). The **MCP host** (Cursor, Claude Desktop, API client) chooses the **LLM** — this server cannot select or downgrade a model for you.

- **Good default:** A **mid-tier** model (e.g. Sonnet-class) is usually enough for reliable tool names, filters, and reading nested flaw / affect / tracker data.
- **Smaller / cheaper models:** Reasonable for **narrow** tasks (one CVE, a known tool, counts only). Tight prompts help; ambiguous multi-step triage may need more retries or a larger model.
- **Largest models:** Optional when the task is **underspecified** or you need unusually careful synthesis; for routine read-only chains they are **often more than needed**.
- **Saving tokens:** Use **`include_fields` / `exclude_fields`** where supported; prefer **`flaws_count`** or **`get_cve_summary`** over pulling many full list pages; keep **`limit`** modest; ask the agent to **summarize** instead of echoing entire tool payloads unless you are debugging.

## Security

See **[SECURITY.md](SECURITY.md)** for the threat model, OWASP-oriented checklist, and access-mode behavior.

- Outputs may include **embargoed** content; treat transcripts and logs according to your data classification policy (especially when using hosted LLMs).
- Use **two MCP entries** (readonly vs readwrite) so mutations only happen when you intend them.
- Never commit `OSIDB_PASSWORD`; use IDE env or secret stores.

## Development

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
python -m osidb_mcp
pytest tests
pip-audit
```

With [Makefile](Makefile): `make install`, `make test`, `make audit`, or `make check` (CI-equivalent).

**Live integration tests:** `make livetest` runs [`live_tests/`](live_tests/) with **`pytest -vv -s`** (verbose + uncaptured stderr) when `OSIDB_LIVE_TEST=1` and normal `OSIDB_*` credentials are set. Default assertions use **`CVE-2014-0160`**; optional **`OSIDB_LIVE_MIN_*`** env vars enforce minimum totals for your instance. Setup, count output, and `.gitignore` patterns for secrets are documented in **[live_tests/README.md](live_tests/README.md)**. Default **`make test`** / **`pytest`** only run **`tests/`** (offline).

On **Debian/Ubuntu** (including local containers), install **`libkrb5-dev`** before `pip install` so the **`gssapi`** dependency can find `krb5-config` (Kerberos stack used with `osidb-bindings`).

## License

MIT — see [LICENSE](LICENSE).
