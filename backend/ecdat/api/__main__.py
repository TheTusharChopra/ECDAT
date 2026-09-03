"""`python -m ecdat.api` -- start the local API server.

Flags are intentionally few: this is an operator tool, not a service platform.
"""

from __future__ import annotations

import argparse

from .server import serve
from .service import Api


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="ecdat.api", description="Serve the ECDAT API over HTTP (local by default).")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Bind address (default 127.0.0.1; loopback only).")
    parser.add_argument("--port", type=int, default=8787, help="Bind port.")
    parser.add_argument("--allow-root", action="append", default=[], metavar="DIR",
                        help="Confine POST /scan targets to this directory. Repeatable. "
                             "Recommended whenever --host is not loopback.")
    parser.add_argument("--quiet", action="store_true", help="Suppress request logging.")
    args = parser.parse_args(argv)

    api = Api(allowed_roots=args.allow_root or None)
    serve(host=args.host, port=args.port, api=api,
          request_logger=None if args.quiet else print)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
