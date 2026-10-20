"""Command-line entry point for StructHound.

Usage:
    structhound parse <artifact> [--symbols <path>] [--json out.json]

Only pre-existing, authorized artifact files are read.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from structhound import artifacts
from structhound.artifacts import hive, minidump
from structhound.recover import engine, signatures, symbols
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
        help="type-description (symbol) file to compute the layout from",
    )
    p_layout.add_argument(
        "--pdb",
        metavar="PATH",
        help="Windows PDB file to read struct type info from (native backend)",
    )
    p_layout.add_argument(
        "--module",
        metavar="PATH",
        help="a PE module (.dll/.exe): fetch its PDB from the symbol server, then resolve",
    )
    p_layout.add_argument(
        "--download-dir",
        metavar="DIR",
        help="where to cache PDBs fetched for --module (default: ./.symbols)",
    )
    p_layout.add_argument(
        "--signatures",
        metavar="PATH",
        help="signature file for offset recovery (requires --code)",
    )
    p_layout.add_argument(
        "--code",
        metavar="PATH",
        help="module code blob to scan for signatures (requires --signatures)",
    )
    p_layout.add_argument("--arch", default="x64", help="architecture (x64 or x86)")
    p_layout.add_argument(
        "--build", help="override the build id (defaults to the one in the symbol file)"
    )
    p_layout.add_argument(
        "--json", metavar="OUT", help="write JSON to OUT (use '-' for stdout)"
    )

    p_read = sub.add_parser(
        "read", help="read a struct instance out of a dump at an address (like `dt`)"
    )
    p_read.add_argument("dump", help="path to an authorized memory dump (minidump)")
    p_read.add_argument("struct", help="name of the struct to read")
    p_read.add_argument(
        "--at", metavar="ADDR", required=True, help="virtual address of the instance (e.g. 0x...)"
    )
    # layout source (same options as `layout`)
    p_read.add_argument("--symbols", metavar="PATH", help="type-description (symbol) file")
    p_read.add_argument("--pdb", metavar="PATH", help="Windows PDB file")
    p_read.add_argument("--module", metavar="PATH", help="PE module: fetch its PDB, then read")
    p_read.add_argument("--download-dir", metavar="DIR", help="PDB cache dir for --module")
    p_read.add_argument("--signatures", metavar="PATH", help="signature file (requires --code)")
    p_read.add_argument("--code", metavar="PATH", help="code blob for --signatures")
    p_read.add_argument("--arch", default="x64", help="architecture (x64 or x86)")
    p_read.add_argument("--build", help="override the build id")
    p_read.add_argument(
        "--walk",
        metavar="FIELD",
        help="treat FIELD as a next-pointer and walk the linked list of instances",
    )
    p_read.add_argument(
        "--max", type=int, default=16, help="max nodes to walk (default 16)"
    )
    p_read.add_argument(
        "--link-offset",
        type=lambda s: int(s, 0),
        default=0,
        help="subtract from each pointer to get the next node base (embedded _LIST_ENTRY)",
    )
    p_read.add_argument("--json", metavar="OUT", help="write JSON to OUT (use '-' for stdout)")

    p_diff = sub.add_parser(
        "diff", help="diff struct layouts between two builds (PDB or symbol JSON)"
    )
    p_diff.add_argument("--a", metavar="PATH", required=True, help="old build's PDB or .json")
    p_diff.add_argument("--b", metavar="PATH", required=True, help="new build's PDB or .json")
    p_diff.add_argument("--struct", help="limit the diff to one struct")
    p_diff.add_argument("--arch", default="x64", help="architecture (x64 or x86)")
    p_diff.add_argument(
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
    elif fmt == "hive":
        try:
            parsed = hive.parse(data)
        except hive.HiveError as exc:
            print(f"error: malformed hive: {exc}", file=sys.stderr)
            return 4
        report = schema.from_hive(args.artifact, len(data), parsed)
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
            {
                "name": f.name,
                "offset": f.offset,
                "size": f.size,
                "bit_offset": f.bit_offset,
                "bit_width": f.bit_width,
            }
            for f in layout.fields.values()
        ],
    }


def _load_json(path: str, label: str) -> dict | int:
    try:
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)
    except OSError as exc:
        print(f"error: cannot read {label}: {exc}", file=sys.stderr)
        return 2
    except json.JSONDecodeError as exc:
        print(f"error: invalid {label}: {exc}", file=sys.stderr)
        return 2


def _symbol_layout(args):
    doc = _load_json(args.symbols, "symbol file")
    if isinstance(doc, int):
        return doc
    module = doc.get("module", "<unknown>")
    build = args.build or str(doc.get("build", ""))
    try:
        source = symbols.source_from_doc(doc)
        return engine.SymbolLayoutProvider(source).layout(
            module, build, args.struct, args.arch
        )
    except symbols.SymbolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4


def _pdb_layout(args):
    from structhound.recover import pdb as pdb_backend
    from structhound.recover.types import arch_by_name

    module = os.path.basename(args.pdb)
    build = args.build or ""
    try:
        arch_obj = arch_by_name(args.arch)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    try:
        source = pdb_backend.PdbSymbolSource(
            args.pdb, module=module, build=build, arch=arch_obj
        )
        # Fail fast with a clear message if the file can't be read/parsed.
        source.struct_names()
    except OSError as exc:
        print(f"error: cannot read PDB: {exc}", file=sys.stderr)
        return 2
    except symbols.SymbolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    return engine.SymbolLayoutProvider(source).layout(
        module, build, args.struct, args.arch
    )


def _module_layout(args):
    from structhound import pe, symsrv

    try:
        ref = pe.read_pdb_ref_file(args.module)
    except OSError as exc:
        print(f"error: cannot read module: {exc}", file=sys.stderr)
        return 2
    except pe.PEError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    dest = args.download_dir or os.path.join(os.getcwd(), ".symbols")
    try:
        pdb_path = symsrv.download_pdb(ref, dest)
    except symsrv.SymbolServerError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 5
    print(f"fetched {ref.pdb_name} ({ref.signature}) -> {pdb_path}", file=sys.stderr)

    # Hand off to the PDB path exactly as if the user had passed --pdb.
    args.pdb = pdb_path
    args.build = args.build or ref.signature
    return _pdb_layout(args)


def _signature_layout(args):
    if not args.code:
        print("error: --signatures requires --code", file=sys.stderr)
        return 2
    doc = _load_json(args.signatures, "signature file")
    if isinstance(doc, int):
        return doc
    try:
        with open(args.code, "rb") as fh:
            code = fh.read()
    except OSError as exc:
        print(f"error: cannot read code blob: {exc}", file=sys.stderr)
        return 2
    try:
        sigset = signatures.signatureset_from_doc(doc)
    except signatures.SignatureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    module = sigset.module
    build = args.build or str(doc.get("build", ""))
    code_source = engine.DictCodeSource()
    code_source.register(module, build, code)
    return engine.SignatureLayoutProvider(sigset, code_source).layout(
        module, build, args.struct, args.arch
    )


def _resolve_layout(args):
    """Resolve a ResolvedLayout from whichever source flag was given, or an int error code."""
    if not args.symbols and not args.pdb and not args.module and not args.signatures:
        print(
            "error: provide --symbols, --pdb, --module, or --signatures with --code",
            file=sys.stderr,
        )
        return 2
    try:
        if args.module:
            return _module_layout(args)
        if args.pdb:
            return _pdb_layout(args)
        if args.symbols:
            return _symbol_layout(args)
        return _signature_layout(args)
    except engine.LayoutUnavailable as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    except ValueError as exc:  # unknown arch
        print(f"error: {exc}", file=sys.stderr)
        return 2


def _run_layout(args) -> int:
    resolved = _resolve_layout(args)
    if isinstance(resolved, int):  # an error code bubbled up from a helper
        return resolved

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


def _run_read(args) -> int:
    from structhound import memory
    from structhound.artifacts import minidump

    try:
        va = int(args.at, 0)
    except ValueError:
        print(f"error: invalid address {args.at!r}", file=sys.stderr)
        return 2

    try:
        with open(args.dump, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        print(f"error: cannot read dump: {exc}", file=sys.stderr)
        return 2
    if not minidump.is_minidump(data):
        print("error: not a minidump (only minidumps carry memory today)", file=sys.stderr)
        return 3
    try:
        dump = minidump.parse(data)
    except minidump.MinidumpError as exc:
        print(f"error: malformed minidump: {exc}", file=sys.stderr)
        return 4
    if not dump.memory_ranges:
        print("error: this dump contains no memory ranges to read", file=sys.stderr)
        return 4

    resolved = _resolve_layout(args)
    if isinstance(resolved, int):
        return resolved

    reader = memory.MemoryReader(data, dump.memory_ranges)
    try:
        if args.walk:
            nodes = reader.walk(
                resolved.layout, va, args.walk, max_nodes=args.max, link_offset=args.link_offset
            )
        else:
            nodes = [(va, reader.read_struct(resolved.layout, va))]
    except memory.MemoryError_ as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4

    def _fields_json(values):
        return [
            {
                "name": v.name,
                "offset": v.offset,
                "size": v.size,
                "value": v.value,
                "hex": v.hex,
                "bit_offset": v.bit_offset,
                "bit_width": v.bit_width,
                "bit_value": v.bit_value,
            }
            for v in values
        ]

    if args.json is not None:
        payload = json.dumps(
            {
                "struct": resolved.layout.name,
                "walk": args.walk,
                "nodes": [
                    {"address": addr, "fields": _fields_json(vals)} for addr, vals in nodes
                ],
            },
            indent=2,
        )
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as out:
                out.write(payload)
            print(f"wrote {args.json}", file=sys.stderr)
    else:
        name = resolved.layout.name
        source = resolved.provenance.method.value
        if args.walk:
            print(f"{name} list via '{args.walk}'  ({len(nodes)} node(s), source: {source})")
        for i, (addr, values) in enumerate(nodes):
            prefix = f"[{i}] " if args.walk else ""
            print(f"\n{prefix}{name} @ {addr:#x}")
            print(f"  {'offset':>6}  {'size':>4}  {'value':>20}  field")
            for v in values:
                if v.bit_width is not None:
                    hi = (v.bit_offset or 0) + v.bit_width - 1
                    shown = f"{v.bit_value:#x}" if v.bit_value is not None else v.hex
                    label = f"{v.name} (bits {v.bit_offset}..{hi})"
                else:
                    shown = f"{v.value:#x}" if v.value is not None else v.hex
                    label = v.name
                print(f"  {v.offset:>6}  {v.size:>4}  {shown:>20}  {label}")
    return 0


def _load_structs(path: str, arch: str):
    """Load a ``name -> Struct`` map from a PDB or a symbol-JSON file (by extension)."""
    if path.lower().endswith(".json"):
        doc = _load_json(path, "symbol file")
        if isinstance(doc, int):
            return doc
        return symbols.structs_from_doc(doc)
    from structhound.recover import pdb as pdb_backend
    from structhound.recover.types import arch_by_name

    return pdb_backend.parse_pdb(path, arch_by_name(arch)).structs


def _run_diff(args) -> int:
    from structhound import diff as diffmod
    from structhound.recover.symbols import SymbolError

    try:
        old = _load_structs(args.a, args.arch)
        if isinstance(old, int):
            return old
        new = _load_structs(args.b, args.arch)
        if isinstance(new, int):
            return new
    except OSError as exc:
        print(f"error: cannot read input: {exc}", file=sys.stderr)
        return 2
    except SymbolError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 4
    except ValueError as exc:  # unknown arch
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = diffmod.diff_structs(old, new, args.arch, only=args.struct)

    if args.json is not None:
        payload = json.dumps(diffmod.to_dict(result), indent=2)
        if args.json == "-":
            print(payload)
        else:
            with open(args.json, "w", encoding="utf-8") as out:
                out.write(payload)
            print(f"wrote {args.json}", file=sys.stderr)
    else:
        print(diffmod.render(result))
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

    if args.command == "read":
        return _run_read(args)

    if args.command == "diff":
        return _run_diff(args)

    build_parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
