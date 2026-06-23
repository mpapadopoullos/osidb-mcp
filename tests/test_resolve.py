"""Unit tests for osidb_mcp.resolve module."""

from unittest.mock import MagicMock

import pytest

from osidb_mcp.resolve import _is_uuid, resolve_flaw_uuid


class TestIsUuid:
    def test_valid_uuidv4(self):
        assert _is_uuid("70d80ad3-a8cf-4763-be08-799191d12860") is True

    def test_valid_uuidv4_uppercase(self):
        assert _is_uuid("70D80AD3-A8CF-4763-BE08-799191D12860") is True

    def test_cve_id(self):
        assert _is_uuid("CVE-2024-1234") is False

    def test_cve_id_long(self):
        assert _is_uuid("CVE-2024-123456") is False

    def test_empty_string(self):
        assert _is_uuid("") is False

    def test_random_string(self):
        assert _is_uuid("not-a-uuid-at-all") is False

    def test_partial_uuid(self):
        assert _is_uuid("70d80ad3-a8cf-4763-be08") is False


class TestResolveFlawUuid:
    def test_uuid_passthrough(self):
        """A valid UUID is returned directly without calling the API."""
        session = MagicMock()
        result = resolve_flaw_uuid(session, "70d80ad3-a8cf-4763-be08-799191d12860")

        assert result == "70d80ad3-a8cf-4763-be08-799191d12860"
        session.flaws.retrieve.assert_not_called()

    def test_uuid_with_whitespace(self):
        """Leading/trailing whitespace is stripped before UUID check."""
        session = MagicMock()
        result = resolve_flaw_uuid(session, "  70d80ad3-a8cf-4763-be08-799191d12860  ")

        assert result == "70d80ad3-a8cf-4763-be08-799191d12860"
        session.flaws.retrieve.assert_not_called()

    def test_cve_id_resolves(self):
        """A CVE ID triggers a flaws.retrieve call and returns the flaw's uuid."""
        session = MagicMock()
        flaw_mock = MagicMock()
        flaw_mock.uuid = "70d80ad3-a8cf-4763-be08-799191d12860"
        session.flaws.retrieve.return_value = flaw_mock

        result = resolve_flaw_uuid(session, "CVE-2024-1234")

        assert result == "70d80ad3-a8cf-4763-be08-799191d12860"
        session.flaws.retrieve.assert_called_once_with("CVE-2024-1234")

    def test_cve_id_with_whitespace(self):
        """CVE ID with whitespace is stripped before resolution."""
        session = MagicMock()
        flaw_mock = MagicMock()
        flaw_mock.uuid = "70d80ad3-a8cf-4763-be08-799191d12860"
        session.flaws.retrieve.return_value = flaw_mock

        result = resolve_flaw_uuid(session, " CVE-2024-1234 ")

        session.flaws.retrieve.assert_called_once_with("CVE-2024-1234")
        assert result == "70d80ad3-a8cf-4763-be08-799191d12860"

    def test_flaw_missing_uuid_attribute(self):
        """If the resolved flaw has no uuid, raise ValueError."""
        session = MagicMock()
        flaw_mock = MagicMock(spec=[])  # no attributes
        session.flaws.retrieve.return_value = flaw_mock

        with pytest.raises(ValueError, match="has no uuid attribute"):
            resolve_flaw_uuid(session, "CVE-2024-1234")

    def test_retrieve_raises_propagates(self):
        """Exceptions from flaws.retrieve propagate to caller."""
        session = MagicMock()
        session.flaws.retrieve.side_effect = RuntimeError("connection failed")

        with pytest.raises(RuntimeError, match="connection failed"):
            resolve_flaw_uuid(session, "CVE-2024-1234")
