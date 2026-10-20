# StructHound

**A build-resilient parser for Windows forensic artifacts — it recovers structure
layouts from the binaries themselves instead of trusting hand-maintained offset tables
that go stale on every new Windows build.**

[![CI](https://github.com/farouqhassan/structhound/actions/workflows/ci.yml/badge.svg)](https://github.com/farouqhassan/structhound/actions)

---

## The problem

Forensic and IR tooling that interprets Windows memory and offline artifacts depends on
*undocumented* internal structures. Microsoft reorders, resizes, and inserts fields in
those structures between builds, so the usual approach — a static table of per-build
field offsets — breaks the moment a new build ships. The analyst gets empty or wrong
output and has to wait for someone to reverse the new layout by hand and patch a table.

**StructHound's core idea:** don't store offsets, store *types* and **compute** offsets.
Even when Microsoft inserts a field, recomputing from type information yields the correct
layout — including on a build the tool has never seen.

```
            insert an 8-byte field between builds...
build 22621:  Flags(0)  Handle(8)   Count(16)                 size 24
build 26100:  Flags(0)  Extra(8)    Handle(16)  Count(24)     size 32
                                     ^^^^^^^^^^  ^^^^^^^^
hardcoded offset table (built for 22621):   BROKEN on 26100
StructHound (computes from types):          correct on both
```

## Install

```bash
git clone <your-fork-url> structhound
cd structhound
pip install -e ".[dev]"
```

Pure standard library — no runtime dependencies. Python 3.10+.

## Quickstart

Three self-contained demos, no real data required:

```bash
python examples/demo_across_builds.py   # why computed offsets beat a static table
python examples/demo_signature.py        # recovering offsets with no symbols at all
pytest -q                                # the full test suite (synthetic fixtures)
```

### Parse an artifact

```bash
structhound parse capture.dmp            # minidump: identify + enumerate modules
structhound parse SOFTWARE               # registry hive: walk the key tree
structhound parse capture.dmp --json -   # machine-readable output
```

### Resolve a structure's layout

```bash
# From type information (exact, build-resilient):
structhound layout EXAMPLE_STRUCT --symbols examples/example_build_26100.json

# From a real Windows PDB (native backend — offsets are recomputed, not read):
structhound layout EXAMPLE_STRUCT --pdb path/to/module.pdb

# From a live module: fetch its PDB from Microsoft's symbol server, then resolve:
structhound layout _UNICODE_STRING --module C:\Windows\System32\ntdll.dll

# From code, when no symbols exist (confidence-scored):
structhound layout EXAMPLE_STRUCT --signatures sigs.json --code module.bin
```

### Read a struct instance out of a dump

```bash
# Like WinDbg's `dt type address`, but offsets are recomputed from types:
structhound read crash.dmp _SOME_STRUCT --at 0x7ff8004200a0 --module C:\path\to\mod.dll
```

Try `python examples/demo_read_from_dump.py` for a self-contained run.

Follow a pointer field to walk a linked list of structs:

```bash
structhound read crash.dmp _SOME_NODE --at 0x... --walk Next --module mod.dll
# embedded _LIST_ENTRY lists: add --link-offset <offset of the link field in the node>
```

See `python examples/demo_walk_list.py`.

### Diff a structure across builds

```bash
# What changed between two builds of a module? (PDBs or symbol-JSON on either side)
structhound diff --a old/ntdll.pdb --b new/ntdll.pdb
structhound diff --a examples/example_build_22621.json --b examples/example_build_26100.json
```

```
EXAMPLE_STRUCT  (size 24 -> 32)
  + Extra                    @8 (size 8) added
  ~ Handle                   @8 -> @16 (+8)
  ~ Count                    @16 -> @24 (+8)
```

That shift is precisely what silently breaks a hardcoded offset table — and what
StructHound recomputes correctly. Try `python examples/demo_cross_build_diff.py`.

### Proof on real data

`python examples/validate_real_pdb.py` runs the whole chain against a real Microsoft PDB:
it reads `ntdll.dll`'s debug id, downloads the matching `ntdll.pdb`, recomputes every
struct's field offsets from types, and checks them against the PDB's own records —
**190 structs, 897/897 offsets correct**, including a packed struct (`_KTSS64`). Because
StructHound only ever emits *recomputed* offsets, that agreement is what it would carry
onto a build no static offset table has seen.

Example output:

```
Struct   : EXAMPLE_STRUCT  [x64]
Size     : 32 bytes (align 8)
Source   : symbol (confidence 1.00) - computed from type information for build 26100

    offset    size  field
         0       4  Flags
         8       8  Extra
        16       8  Handle
        24       4  Count
```

## How it works

```
input artifact ──▶ structure recovery ──▶ typed view ──▶ report
 (dump / hive)      (symbol | signature)   (offsets)      (JSON / console)
```

**Layout-recovery engine** (`structhound/recover/`). A small C/MSVC struct-layout engine
computes field offsets by applying natural-alignment rules — handling nested structs,
fixed arrays, pointer sizes per architecture, and `#pragma pack`. Three providers feed
it, tried in order of trust by `LayoutResolver`:

1. **Symbol-driven** — computes offsets from type information (a `SymbolSource`). Exact,
   and adapts across builds. Types come either from a JSON type-description file or, via
   the **native PDB backend** (`--pdb`), straight from a real Windows PDB — both implement
   the same interface and feed the same layout engine. The PDB backend reads field *types*
   and recomputes offsets; it never trusts the PDB's recorded offsets (a test cross-checks
   that the recomputation matches them).
2. **Hardcoded table** — the legacy baseline, kept as a fallback. Exact only for builds
   explicitly in the table.
3. **Signature-based** — when no symbols exist, scans code for instruction patterns and
   reads offsets out of the encoded displacements (e.g. `mov rax,[rcx+0x10]` → `0x10`).

**Provenance on everything.** Every resolved layout reports which method produced it and
a confidence score, so an analyst never has to guess whether output is trustworthy.
Signature recovery is never treated as certain (capped at 0.95) and its confidence rises
with agreement across matches and corroboration by independent signatures.

**Artifact readers** (`structhound/artifacts/`). Format detection is by magic bytes.
Supported today:

| Format | What it reads |
|---|---|
| Minidump (`.dmp`) | Header, stream directory, module list with versions |
| Registry hive (regf) | Key tree (nk/vk, lf/lh/li/ri lists), common value types |

## Limitations & roadmap

- Type information comes from a JSON file, the native PDB backend (`--pdb`), or a module
  fetched from the symbol server (`--module`). The PDB reader covers the common CodeView
  records (structs/classes, members, pointers, arrays, modifiers, enums, base types) and
  infers packing; structs containing unions or bitfield members are reported as
  unsupported rather than mis-laid-out.
- Hive reader does not yet handle big-data (`db`) values or transaction logs.
- Signature scanning is a straightforward linear scan — fine for triage, not yet tuned
  for very large modules.

See `docs/DESIGN.md` for the full architecture writeup and `CHANGELOG.md` for milestones.

## Scope & ethics

This is defensive/forensic research tooling for systems you own or are explicitly
authorized to analyze (lab VMs, IR engagements, pentests with a signed scope). It ships
**no** acquisition, injection, or process-access component — input is always a
pre-existing, authorized artifact file. All test data is synthesized in the suite; no
real captured data is included.

## License

MIT — see `LICENSE`.
