"""Load configuration from the environment (no secrets in source code)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Literal


class AccessMode(str, Enum):
    """Server capability gate. Only ``readonly`` is supported until mutation MCP tools ship."""

    readonly = "readonly"
    readwrite = "readwrite"  # reserved; rejected by `_parse_access_mode` until implemented


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
        raise ValueError(
            "OSIDB_MCP_ACCESS_MODE=readwrite is not supported yet (no mutation MCP tools). "
            "Use 'readonly'. When write tools are added, configure a dedicated MCP server entry "
            "for intentional mutations."
        )
    raise ValueError(
        "OSIDB_MCP_ACCESS_MODE must be 'readonly' (default). "
        f"Got {raw!r}"
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
            raise ValueError(
                "OSIDB_AUTH=basic requires OSIDB_USERNAME and OSIDB_PASSWORD"
            )
    else:
        username = None
        password = None

    ua = os.environ.get("OSIDB_USER_AGENT")
    if ua == "":
        ua = None

    return Settings(
        base_url=base,
        auth=auth,  # type: ignore[arg-type]
        username=username,
        password=password,
        verify_ssl=_env_bool("OSIDB_VERIFY_SSL", True),
        user_agent=ua,
        access_mode=_parse_access_mode(),
    )
