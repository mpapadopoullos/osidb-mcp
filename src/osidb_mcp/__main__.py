"""Console entrypoint: ``osidb-mcp`` and ``python -m osidb_mcp``."""

from __future__ import annotations

import logging
import sys

from osidb_mcp.config import load_settings
from osidb_mcp.server import create_server
from osidb_mcp.session_holder import configure


def main() -> None:
    if any(a in ("--version", "-V") for a in sys.argv[1:]):
        from osidb_mcp import __version__

        print(__version__)
        raise SystemExit(0)

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

    log.info("osidb-mcp access mode: readonly")

    mcp = create_server(settings)
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
