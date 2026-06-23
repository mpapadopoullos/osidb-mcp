"""Flaw identifier resolution and UUID validation utilities."""

from __future__ import annotations

from uuid import UUID

from osidb_bindings.session import Session


def _is_uuid(value: str) -> bool:
    try:
        UUID(value)
        return True
    except ValueError:
        return False


def parse_uuid_param(name: str, value: str) -> UUID:
    """Parse and validate a UUID string parameter.

    Raises ValueError with a descriptive message including the parameter name.
    """
    try:
        return UUID(str(value).strip())
    except ValueError as e:
        raise ValueError(f"{name} must be a UUID string") from e


def resolve_flaw_uuid(session: Session, flaw_id: str) -> str:
    """Return the flaw's internal UUID.

    If *flaw_id* is already a valid UUID string it is returned directly
    (no API call).  Otherwise it is treated as an alternative identifier
    (e.g. a CVE ID like ``CVE-2024-1234``) and resolved via
    ``session.flaws.retrieve()`` which accepts both formats.
    """
    flaw_id = flaw_id.strip()
    if _is_uuid(flaw_id):
        return flaw_id

    flaw = session.flaws.retrieve(flaw_id)
    uuid = getattr(flaw, "uuid", None)
    if not uuid:
        raise ValueError(f"Flaw '{flaw_id}' resolved but has no uuid attribute")
    return str(uuid)
