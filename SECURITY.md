# Security considerations — osidb-mcp

This document outlines threats and operational guidance for running **osidb-mcp**. For installation and tools, see [README.md](README.md).

## Threat model

- **Trust boundary:** The MCP server runs as a **local subprocess** with stdio attached to the host IDE or MCP client. The host process controls arguments and environment variables (`OSIDB_*`). Anyone who can spawn `osidb-mcp` with your Kerberos ticket or credentials can perform whatever OSIDB allows that identity to do.
- **Single identity:** All OSIDB calls use **one** OSIDB account per server process (JWT refreshed inside osidb-bindings). Agents cannot escalate privileges beyond what OSIDB grants that account.
- **Downstream disclosure:** Tool results may flow into **LLM transcripts**, logs, or vendor backends outside your boundary. Treat as sensitive especially when flaws may be **embargoed**.

## Access mode

- **`OSIDB_MCP_ACCESS_MODE`:** Only **`readonly`** is accepted today (default). **`readwrite` is rejected at startup** until mutation MCP tools exist.
- **Operational habit:** When read/write tools are added later, prefer **two separate MCP configurations** in the client (e.g. one `readonly`, one explicit write-capable server name/env) so write-capable servers are attached **only** when intentional.

## OWASP Top 10–oriented controls (mapping)

| Category | Mitigations in use |
|----------|-------------------|
| **A01 Broken access control** | OSIDB RBAC; use least-privilege OSIDB accounts for MCP; no MCP-driven RBAC bypass—agents inherit session identity only. |
| **A02 Cryptographic failures** | TLS verification defaults `true` (`OSIDB_VERIFY_SSL`); enterprise CA via `REQUESTS_CA_BUNDLE`; credentials via env/secret stores, not commits. |
| **A03 Injection** | List/filter helpers use **allowlisted** `extra_query` keys derived from official bindings query-parameter sets; limits on keys and list sizes (`query_filters.py`). |
| **A04 Insecure design** | Read-only MCP surface today; readwrite refused until mutations are deliberately shipped with schemas and docs. |
| **A05 Security misconfiguration** | Secure Kerberos/basic-auth flows via bindings; document not targeting arbitrary attacker-controlled URLs as OSIDB when supplying secrets (`OSIDB_BASE_URL`). |
| **A06 Vulnerable components** | CI runs **pip-audit**; keep `osidb-bindings` and `mcp` updated. |
| **A07 Auth failures** | Prefer Kerberos internally where applicable; rotate passwords for basic auth; do not log passwords or tokens. |
| **A08 Software/data integrity** | Mutations are not exposed yet; future bulk/agent mutations require careful caps and validation design. |
| **A09 Logging/monitoring failures** | Server avoids dumping secrets; HTTP error detail truncated (`errors.http_error_payload`). Optional org-specific audit hooks remain future work. |
| **A10 SSRF** | MCP forwards credentials only to `OSIDB_BASE_URL`; operators choose URL—the trusted boundary is still OSIDB’s hostname policy + credential misuse prevention. |

## Reporting security issues

If you discover a security vulnerability in **this MCP adapter**, please report it privately via your organization’s normal PSIRT/channel or open an issue on the repository’s GitHub **Issues** with `[SECURITY]` in the title (avoid posting exploitation detail publicly).
