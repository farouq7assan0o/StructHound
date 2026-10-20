"""Command-line entry point for StructHound.

Usage:
    structhound parse <artifact> [--symbols <path>] [--json out.json]

Only pre-existing, authorized artifact files are read.
"""

from __future__ import annotations

import argparse
import sys

import json

from structhound import artifacts
from structhound.artifacts import minidump
from structhound.recover import engine, symbols
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

    p_layout = sub.add_parser(
        "layout", help="compute a struct's field layout from symbol/type info"
    )
    p_layout.add_argument("struct", help="name of the struct to resolve")
    p_layout.add_argument(
        "--symbols",
        metavar="PATH",
        required=True,
        help="type-description (symbol) file to compute the layout from",
    )
    p_layout.add_argument("--arch", default="x64", help="architecture (x64 or x86)")
    p_layout.add_argument(
        "--build", help="override the build id (defaults to the one in the symbol file)"
    )
    p_layout.add_argument(
        "--json", metavar="OUT", help="write JSON to OUT (use '-' for stdout)"
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


def _layout_to_dict(resolved: engine.ResolvedLayout) -> dict:
    layout = resolved.layout
    return {
        "struct": layout.name,
        "arch": layout.arch,
        "total_size": layout.total_size,
        "align": layout.align,
        "provenance": {
            "method": resolved.provenance.method.value,
            "confidence": resolved.provenance.confidence,
            "detail": resolved.provenance.detail,
        },
        "fields": [
            {"name": f.name, "offset": f.offset, "size": f.size}
            for f in layout.fields.values()
        ],
    }


def _run_layout(args) -> int:
    try:
        with open(args.symbols, encoding="utf-8") as fh:
            doc = json.load(fh)
    except OSError as exc:
        print(f"error: cannot read symbol file: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid symbol file: {exc}", file=sys.stderr)
        return 2

    module = doc.get("module", "<unknown>")
    build = args.build or str(doc.get("build", ""))

    try:
        source = symbols.source_from_doc(doc)
    except symbols.SymbolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    provider = engine.SymbolLayoutProvider(source)
    try:
        resolved = provider.layout(module, build, args.struct, args.arch)
    except engine.LayoutUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    except ValueError as exc:  # unknown arch
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.json is not None:
        payload = json.dumps(_layout_to_dict(resolved), indent=2)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as out:
                out.write(payload)
            print(f"wrote {args.json}", file=sys.stderr)
    else:
        print(console.render_layout(resolved))
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.version:
        from structhound import __version__

        print(f"structhound {__version__}")
        return 0

    if args.command == "parse":
        return _run_parse(args)

    if args.command == "layout":
        return _run_layout(args)

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
