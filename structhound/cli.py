"""Command-line entry point for StructHound.

Usage:
    structhound parse <artifact> [--symbols <path>] [--json out.json]

Only pre-existing, authorized artifact files are read.
"""

from __future__ import annotations

import argparse
import sys

from structhound import artifacts
from structhound.artifacts import minidump
from structhound.report import console, schema


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
        help="write results as JSON to OUT (use '-' for stdout) instead of the console",
    )

    return parser


def _run_parse(args: argparse.Namespace) -> int:
    try:
        with open(args.artifact, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"error: cannot read artifact: {exc}", file=sys.stderr)
        return 2

    try:
        fmt = artifacts.detect(data)
    except artifacts.UnknownArtifact as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    if fmt == "minidump":
        try:
            dump = minidump.parse(data)
        except minidump.MinidumpError as exc:
            print(f"error: malformed minidump: {exc}", file=sys.stderr)
            return 4
        report = schema.from_minidump(args.artifact, len(data), dump)
    else:  # pragma: no cover - guarded by detect()
        print(f"error: no reader for format '{fmt}'", file=sys.stderr)
        return 3

    if args.json is not None:
        payload = report.to_json()
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as out:
                out.write(payload)
            print(f"wrote {args.json}", file=sys.stderr)
    else:
        print(console.render(report))

    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        from structhound import __version__

        print(f"structhound {__version__}")
        return 0

    if args.command == "parse":
        return _run_parse(args)

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
