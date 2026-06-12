"""Verify _load_dotenv() populates os.environ from a .env file."""

import os

from osidb_mcp.__main__ import _load_dotenv


def test_load_dotenv_populates_env(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("TEST_DOTENV_VAR=hello_from_dotenv\n")
    monkeypatch.delenv("TEST_DOTENV_VAR", raising=False)

    _load_dotenv(dotenv_path=str(env_file))

    assert os.environ.get("TEST_DOTENV_VAR") == "hello_from_dotenv"
    monkeypatch.delenv("TEST_DOTENV_VAR", raising=False)


def test_shell_env_takes_precedence(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("TEST_DOTENV_VAR=from_file\n")
    monkeypatch.setenv("TEST_DOTENV_VAR", "from_shell")

    _load_dotenv(dotenv_path=str(env_file))

    assert os.environ["TEST_DOTENV_VAR"] == "from_shell"


def test_missing_env_file_is_silent(tmp_path):
    _load_dotenv(dotenv_path=str(tmp_path / "nonexistent.env"))
