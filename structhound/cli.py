"""Command-line entry point for StructHound.

Usage (planned):
    structhound parse <artifact> [--symbols <path>] [--json out.json]

For now this is a scaffold: it wires up argument parsing and dispatches to the
(not-yet-implemented) orchestration layer so the CLI shape is fixed early.
"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="structhound",
        description="Build-resilient parser for Windows forensic artifacts.",
    )
    parser.add_argument("--version", action="store_true", help="print version and exit")

    sub = parser.add_subparsers(dest="command")

    p_parse = sub.add_parser("parse", help="parse an offline artifact")
    p_parse.add_argument("artifact", help="path to the authorized artifact file")
    p_parse.add_argument(
        "--symbols",
        metavar="PATH",
        help="optional symbol source for symbol-driven layout recovery",
    )
    p_parse.add_argument(
        "--json",
        metavar="OUT",
        help="write results as JSON to OUT instead of the console",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        from structhound import __version__

        print(f"structhound {__version__}")
        return 0

    if args.command == "parse":
        # TODO(M1): dispatch to the orchestration layer.
        print("parse: not yet implemented (scaffold)", file=sys.stderr)
        return 2

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
