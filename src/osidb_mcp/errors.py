"""Format HTTP errors without leaking secrets."""

from __future__ import annotations

from typing import Any

import requests


def http_error_payload(exc: BaseException) -> dict[str, Any]:
    if isinstance(exc, requests.HTTPError):
        resp = exc.response
        status = resp.status_code if resp is not None else None
        text = (resp.text[:2000] if resp is not None else "") or ""
        return {
            "error": "osidb_http_error",
            "status_code": status,
            "detail": text,
        }
    return {"error": "osidb_error", "detail": str(exc)}


def error_response(exc: BaseException) -> dict[str, Any]:
    """Standard MCP tool error envelope."""
    if isinstance(exc, requests.RequestException):
        return {"ok": False, **http_error_payload(exc)}
    return {"ok": False, "error": "osidb_error", "detail": str(exc)}
