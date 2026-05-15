# Changelog

## 0.2.0

- **Access mode:** `OSIDB_MCP_ACCESS_MODE` supports only `readonly` (default). `readwrite` is **rejected at startup** with a clear error until mutation MCP tools exist; removes misleading “warn and continue” behavior.
- **New read tools:** `flaw_acknowledgments_list`, `flaw_labels_list`, `flaw_package_versions_list` (flaw-scoped lists); `affect_get`, `tracker_get` (single resource by id); `labels_list` (global OSIDB labels); `affect_cvss_scores_list` (per-affect CVSS rows).
- **Security documentation:** add [SECURITY.md](SECURITY.md) — threat model, OWASP-oriented checklist, dual-MCP recommendation for future read/write servers.
- **Docs:** README / TOOLS.md updated for new tools and `readonly`-only access mode.
- **Tests:** config/access-mode regression test for rejected `readwrite`.

## 0.1.4

- **Flaw identity without CVE:** `flaw_get` adds top-level `osidb_flaw_uuid` when `cve_id` is empty; `flaws_list` / `flaws_search` add `identifier_hint` for agents; MCP server instructions document CVE vs `uuid`.
- **Fix `get_flaw_details`:** when a flaw has no CVE, load affects and trackers via `flaw__uuid` / `affects__flaw__uuid` instead of misusing `flaw__cve_id`.
- **New filters:** `affects_list` — `flaw_uuid` / `flaw_uuid_in`; `trackers_list` — `affects_flaw_uuid` / `affects_flaw_uuid_in`; `query_affects` forwards UUID params.
- README / TOOLS.md: flaw identifier section and tool doc updates; tests for identity helpers.

## 0.1.3

- Add `search_component`, `query_affects`, `get_pending_exploit_actions`; `search_flaws` adds major-incident filters.
- README: full MCP tools table and “when to use which” guidance; TOOLS.md reference for tool details and example prompts.

## 0.1.2

- Add `osidb-mcp --version` / `-V` (no credentials or `OSIDB_BASE_URL` required).

## 0.1.1

- Add high-level MCP tools aligned with common CVE servers: `search_flaws`, `get_flaw_details`, `get_cve_summary`.

## 0.1.0

- Initial release: stdio MCP server, `readonly` access mode (OSIDB session via `osidb-bindings`, Kerberos or basic auth). `readwrite` was later rejected at startup until mutation tools exist.
