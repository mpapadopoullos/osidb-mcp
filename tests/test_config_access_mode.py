"""OSIDB_MCP_ACCESS_MODE parsing."""

import pytest

from osidb_mcp.config import load_settings


def test_default_readonly(monkeypatch):
    monkeypatch.setenv("OSIDB_BASE_URL", "https://osidb.example.com")
    monkeypatch.delenv("OSIDB_MCP_ACCESS_MODE", raising=False)
    s = load_settings()
    assert s.access_mode.value == "readonly"


def test_readonly_explicit(monkeypatch):
    monkeypatch.setenv("OSIDB_BASE_URL", "https://osidb.example.com")
    monkeypatch.setenv("OSIDB_MCP_ACCESS_MODE", "readonly")
    s = load_settings()
    assert s.access_mode.value == "readonly"


def test_readwrite_accepted(monkeypatch):
    monkeypatch.setenv("OSIDB_BASE_URL", "https://osidb.example.com")
    monkeypatch.setenv("OSIDB_MCP_ACCESS_MODE", "readwrite")
    s = load_settings()
    assert s.access_mode.value == "readwrite"


def test_invalid_mode_rejected(monkeypatch):
    monkeypatch.setenv("OSIDB_BASE_URL", "https://osidb.example.com")
    monkeypatch.setenv("OSIDB_MCP_ACCESS_MODE", "bogus")
    with pytest.raises(ValueError, match="bogus"):
        load_settings()
