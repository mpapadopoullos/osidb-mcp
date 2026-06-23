"""Build kwargs for flaws/affects list with allowlisted ``extra_query``."""

from __future__ import annotations

import importlib
from typing import Any

from osidb_bindings.bindings.python_client.api.osidb import (
    osidb_api_v2_affects_list,
    osidb_api_v2_flaws_list,
)

_labels_list_mod = importlib.import_module(
    "osidb_bindings.bindings.python_client.api.osidb.osidb_api_v1_labels_list"
)
_affect_cvss_list_mod = importlib.import_module(
    "osidb_bindings.bindings.python_client.api.osidb.osidb_api_v2_affects_cvss_scores_list"
)

FLAWS_EXTRA_KEYS = frozenset(osidb_api_v2_flaws_list.QUERY_PARAMS.keys())
AFFECTS_EXTRA_KEYS = frozenset(osidb_api_v2_affects_list.QUERY_PARAMS.keys())
LABELS_EXTRA_KEYS = frozenset(_labels_list_mod.QUERY_PARAMS.keys())
AFFECT_CVSS_SCORES_EXTRA_KEYS = frozenset(_affect_cvss_list_mod.QUERY_PARAMS.keys())

EXTRAS_MAX_KEYS = 30
EXTRAS_MAX_LIST_LEN = 100
LIST_LIMIT_MAX = 100
DEFAULT_LIST_LIMIT = 50


def _coerce_extra_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, list):
        if len(value) > EXTRAS_MAX_LIST_LEN:
            raise ValueError(
                f"extra_query list values must have at most {EXTRAS_MAX_LIST_LEN} items"
            )
        out = []
        for item in value:
            if not isinstance(item, (str, int, float, bool)):
                raise ValueError("extra_query list items must be primitives")
            out.append(item)
        return out
    raise ValueError("extra_query values must be primitives or lists of primitives")


def merge_extra_query(
    base: dict[str, Any],
    extra: dict[str, Any] | None,
    *,
    allowlist: frozenset[str],
) -> dict[str, Any]:
    if not extra:
        return base
    if len(extra) > EXTRAS_MAX_KEYS:
        raise ValueError(f"extra_query may contain at most {EXTRAS_MAX_KEYS} keys")
    merged = dict(base)
    for key, raw in extra.items():
        if key not in allowlist:
            raise ValueError(f"extra_query key not allowed: {key!r}")
        merged[key] = _coerce_extra_value(raw)
    return merged


def clamp_limit(limit: int | None) -> int:
    if limit is None:
        return DEFAULT_LIST_LIMIT
    if limit < 1:
        return 1
    return min(limit, LIST_LIMIT_MAX)


def clamp_offset(offset: int | None) -> int:
    if offset is None or offset < 0:
        return 0
    return offset
