# osidb-mcp

Python [Model Context Protocol](https://modelcontextprotocol.io/) (MCP) server for [OSIDB](https://github.com/RedHatProductSecurity/osidb), built on [`osidb-bindings`](https://github.com/RedHatProductSecurity/osidb-bindings) from PyPI. Use it from Cursor, Claude Desktop, or any MCP client over **stdio**. Source: [github.com/vdanen/osidb-mcp](https://github.com/vdanen/osidb-mcp).

## Install

```bash
pipx install osidb-mcp
# or
pip install osidb-mcp
```

Print the installed package version (no OSIDB env or credentials required):

```bash
osidb-mcp --version
# or: osidb-mcp -V
```

## Configuration (environment)

| Variable | Required | Description |
|----------|----------|-------------|
| `OSIDB_BASE_URL` | yes | OSIDB root URL, e.g. `https://osidb.example.com` |
| `OSIDB_AUTH` | no | `kerberos` (default) or `basic` |
| `OSIDB_USERNAME` / `OSIDB_PASSWORD` | for `basic` | Basic auth for token obtain |
| `OSIDB_VERIFY_SSL` | no | `true` (default) or `false` (prefer `REQUESTS_CA_BUNDLE` for custom CAs) |
| `OSIDB_USER_AGENT` | no | Optional extra User-Agent suffix |
| `OSIDB_MCP_ACCESS_MODE` | no | `readonly` (default) or `readwrite` (mutations reserved for a future release) |

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

## Tools (read-only)

All **MCP tools** require a working OSIDB session (env + Kerberos or basic auth). The CLI **`osidb-mcp --version` / `-V`** does not contact OSIDB (see [Install](#install)). The table lists every registered tool, in the same order as [`server.py`](src/osidb_mcp/server.py). For longer explanations, example prompts, and limitations, see **[TOOLS.md](TOOLS.md)**.

| Tool | Purpose |
|------|---------|
| `osidb_status` | OSIDB API health / status payload (good connectivity check). |
| `osidb_whoami` | Current authenticated user / profile from `GET /osidb/whoami`. |
| `flaw_get` | One flaw by CVE id or flaw id; optional `include_fields` / `exclude_fields` to trim the payload. |
| `search_flaws` | High-level search: keyword and/or CVE ids, severity (`severity` / `severities`), changed-date range (`date_from` / `date_to`), PS `product_modules` / `product_components`, workflow, embargo, owner; keyword-only uses OSIDB full-text search. |
| `get_flaw_details` | Full flaw plus **affects** (products/streams) and **trackers** (Jira/Bugzilla-style filings); toggles `include_affects` / `include_trackers` and per-section limits. |
| `get_cve_summary` | Executive rollups: counts **by severity** and **by workflow** plus total under shared filters (`group_by`: `severity` \| `workflow` \| `both`); multiple `flaws_count` calls; see `partial_errors` if a bucket fails. |
| `flaws_list` | Raw list API: components, nested affects filters (`affects_ps_*`), workflow, impact, owner, embargo, dates, `search`, allowlisted `extra_query` (OSIDB v2 query keys); `limit` ≤ 100. |
| `flaws_count` | Same filter surface as `flaws_list` but returns **count** only (no flaw bodies). |
| `flaws_search` | Full-text search over flaws (`search` parameter); paginated like list APIs. |
| `affects_list` | Rows keyed by **affect** (`ps_module` / `ps_component` / `ps_update_stream`) with `flaw__*` filters (e.g. `flaw_workflow_state_in`, `flaw_impact_in`). |
| `trackers_list` | Tracker filings with optional CVE / PS module / PS component filters and optional `tracker_type`. |
| `flaw_comments_list` | Paginated **discussion comments** for a flaw id. |
| `flaw_references_list` | Paginated **external references** (URLs, advisory refs, etc.) for a flaw id. |
| `flaw_cvss_scores_list` | Paginated **CVSS score** rows (issuer/version/vector) for a flaw id. |
| `search_component` | Flaws whose flaw-level **components** intersect `components_in` (v2 flaws list); optional impact/workflow/date filters. |
| `query_affects` | **Affect rows** for one CVE (`flaw_cve_id`) or many (`flaw_cve_id_in`); v2 affects API (wrapper over `affects_list`). |
| `get_pending_exploit_actions` | **[EXPERIMENTAL]** `GET /exploits/api/v1|v2/report/pending` — pending exploit / IR actions; may 404 if exploits app is off. |

`limit` (and analogous list limits) are capped at **100** per request unless noted otherwise on a tool.

### When to use which

- **Triage / natural language style:** `search_flaws`, `get_flaw_details`, `get_cve_summary`.
- **Exact OpenAPI filters or rare query keys:** `flaws_list` / `flaws_count` with `extra_query` (allowlisted keys only).
- **Affect- or tracker-centric views:** `affects_list`, `trackers_list`, or the subresource tools under a known flaw id.

## Analyst examples

- **Same idea as “search CVEs”:** use **`search_flaws`** with `keyword`, or combine `cve_ids`, `severity` / `severities`, `date_from` / `date_to`, and `product_modules` / `product_components`.
- **Critical open flaws touching `httpd`:** `search_flaws` or `flaws_list` with `impact="CRITICAL"`, `workflow_state_in` for non-terminal states, and `product_components=["httpd"]` or `components_in` / `affects_ps_component` as your data model requires.
- **Unowned important CVEs for a RHEL major:** `search_flaws` with `owner_isempty=true`, `severities=["IMPORTANT"]`, and `product_modules` / `product_components` set to the **exact** PS strings your OSIDB uses for that major (confirm in your internal docs).
- **Executive rollup:** **`get_cve_summary`** with optional date range and product filters; tune `group_by` if you only need severity or only workflow buckets.

## Security

- Outputs may include **embargoed** content; treat transcripts and logs according to your data classification policy.
- Prefer `readonly` (default). `readwrite` does not enable mutations yet but is reserved for explicit future write tools.
- Never commit `OSIDB_PASSWORD`; use IDE env or secret stores.

## Development

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -e ".[dev]"
python -m osidb_mcp
pytest
pip-audit
```

With [Makefile](Makefile): `make install`, `make test`, `make audit`, or `make check` (CI-equivalent). `make build` / `make upload` for releases (`upload` requires [twine](https://twine.readthedocs.io/) credentials).

## License

MIT — see [LICENSE](LICENSE).
