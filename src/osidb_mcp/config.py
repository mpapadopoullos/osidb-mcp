"""Load configuration from the environment (no secrets in source code)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Literal


class AccessMode(str, Enum):
    """Server capability gate.

    ``readonly`` exposes only read tools (default).
    ``readwrite`` additionally registers mutation tools (flaw creation, etc.).
    """

    readonly = "readonly"
    readwrite = "readwrite"


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def _parse_access_mode() -> AccessMode:
    raw = (os.environ.get("OSIDB_MCP_ACCESS_MODE") or "readonly").strip().lower()
    if raw == "readonly":
        return AccessMode.readonly
    if raw == "readwrite":
        return AccessMode.readwrite
    raise ValueError(
        f"OSIDB_MCP_ACCESS_MODE must be 'readonly' or 'readwrite' (default: readonly). Got {raw!r}"
    )


@dataclass(frozen=True)
class Settings:
    base_url: str
    auth: Literal["kerberos", "basic"]
    username: str | None
    password: str | None
    verify_ssl: bool
    user_agent: str | None
    access_mode: AccessMode
    jira_url: str | None = None
    jira_access_token: str | None = None
    jira_api_email: str | None = None
    aegis_url: str | None = None
    osim_url: str = "https://osim.prodsec.redhat.com"
    enable_bugzilla_tools: bool = False


def load_settings() -> Settings:
    base = os.environ.get("OSIDB_BASE_URL", "").strip()
    if not base:
        raise ValueError("OSIDB_BASE_URL is required")

    auth = (os.environ.get("OSIDB_AUTH") or "kerberos").strip().lower()
    if auth not in ("kerberos", "basic"):
        raise ValueError("OSIDB_AUTH must be 'kerberos' or 'basic'")

    username = os.environ.get("OSIDB_USERNAME")
    password = os.environ.get("OSIDB_PASSWORD")
    if auth == "basic":
        if not username or not password:
            raise ValueError("OSIDB_AUTH=basic requires OSIDB_USERNAME and OSIDB_PASSWORD")
    else:
        username = None
        password = None

    ua = os.environ.get("OSIDB_USER_AGENT")
    if ua == "":
        ua = None

    jira_url = os.environ.get("JIRA_URL", "").strip() or None
    jira_token = os.environ.get("JIRA_ACCESS_TOKEN", "").strip() or None
    jira_email = os.environ.get("JIRA_API_EMAIL", "").strip() or None

    aegis_url = os.environ.get("AEGIS_URL", "").strip() or None
    osim_url = os.environ.get("OSIM_URL", "").strip() or "https://osim.prodsec.redhat.com"

    return Settings(
        base_url=base,
        auth=auth,  # ty:ignore[invalid-argument-type]
        username=username,
        password=password,
        verify_ssl=_env_bool("OSIDB_VERIFY_SSL", True),
        user_agent=ua,
        access_mode=_parse_access_mode(),
        jira_url=jira_url,
        jira_access_token=jira_token,
        jira_api_email=jira_email,
        aegis_url=aegis_url,
        osim_url=osim_url,
        enable_bugzilla_tools=_env_bool("ENABLE_BUGZILLA_TOOLS", False),
    )
