"""Console entrypoint: ``osidb-mcp`` and ``python -m osidb_mcp``."""

from __future__ import annotations

import logging
import sys

from osidb_mcp.config import load_settings
from osidb_mcp.server import create_server
from osidb_mcp.session_holder import configure


def _load_dotenv(dotenv_path: str | None = None) -> None:
    """Best-effort .env loading; no-op when python-dotenv is absent.

    When no explicit path is given, searches CWD first (python-dotenv default),
    then falls back to a .env next to the installed package source so that the
    server works even when Cursor (or another host) launches it from an
    arbitrary working directory.
    """
    try:
        from dotenv import load_dotenv
    except ImportError:
        return

    if dotenv_path:
        load_dotenv(dotenv_path=dotenv_path)
        return

    # Default: try CWD first
    from pathlib import Path

    cwd_env = Path.cwd() / ".env"
    if cwd_env.is_file():
        load_dotenv(dotenv_path=cwd_env)
        return

    # Fallback: .env in the project root (two levels up from this file)
    pkg_env = Path(__file__).resolve().parent.parent.parent / ".env"
    if pkg_env.is_file():
        load_dotenv(dotenv_path=pkg_env)
        return

    # Last resort: let python-dotenv search upward from CWD
    load_dotenv()


def main() -> None:
    if any(a in ("--version", "-V") for a in sys.argv[1:]):
        from osidb_mcp import __version__

        print(__version__)
        raise SystemExit(0)

    _load_dotenv()

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    log = logging.getLogger("osidb_mcp")

    try:
        settings = load_settings()
    except ValueError as e:
        print(f"osidb-mcp: {e}", file=sys.stderr)
        raise SystemExit(2) from e

    configure(settings)

    log.info("osidb-mcp access mode: %s", settings.access_mode.value)

    mcp = create_server(settings)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
