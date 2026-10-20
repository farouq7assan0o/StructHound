# Changelog

## Unreleased

- **M12 — Bit ranges in output.** `layout` now annotates bitfield members with their bit
  range (`a : bits 0..0`) in console and carries `bit_offset`/`bit_width` in JSON. `read`
  extracts each bitfield's actual value from its storage unit and shows the bit range and
  value, in console and JSON (`bit_value`).
- **M11 — Union & bitfield support.** The layout engine gained a `Union` type (members
  share offset 0) and a `BitField` type with MSVC-style bit packing (new storage unit on
  overflow, base-type change, or a plain member); `FieldInfo` now carries bit offset/width.
  The PDB backend decodes `LF_UNION` and `LF_BITFIELD` and folds anonymous scalar unions
  (overlapping sibling members) into inline unions. On real `ntdll.pdb` this lifted
  coverage from 190 to **215 structs modeled with 1051/1051 offsets still matching** the
  PDB's records — `_IO_STATUS_BLOCK`, `_NT_TIB64`, etc. now resolve correctly.
- **M10 — Pointer-following / linked-list walk.** `structhound read ... --walk <FIELD>`
  treats a pointer field as a next-pointer and walks the chain of instances, reading each
  with the computed layout. Stops safely on null, a cycle (circular list back to the
  head), an uncaptured address, or `--max`. `--link-offset` backs a pointer out to the
  node base for embedded `_LIST_ENTRY`-style links (CONTAINING_RECORD). See
  `examples/demo_walk_list.py`.
- **M9 — Read struct instances from a dump.** The minidump reader now parses memory
  streams (`MemoryListStream`/`Memory64ListStream`) into virtual-address ranges, and a
  memory reader (`structhound.memory`) applies a computed layout to read a struct instance
  straight out of the dump — the forensic equivalent of WinDbg's `dt type address`, but
  with offsets recomputed from types so they stay correct across builds. CLI:
  `structhound read <dump> <struct> --at 0x... [--pdb/--symbols/--module ...]`. See
  `examples/demo_read_from_dump.py`.
- **M8 — Cross-build struct diff.** `structhound diff --a <old> --b <new>` reports, per
  structure, exactly what changed between two builds: fields added/removed, fields that
  moved to a new offset, fields that resized, and overall size — with offsets recomputed
  from types on both sides, so it reflects real layout changes (the same ones that break
  a hardcoded offset table). Inputs can be PDBs or symbol-JSON files; `--struct` scopes
  it to one structure. See `structhound/diff.py` and `examples/demo_cross_build_diff.py`.
- **M7 — Symbol-server fetch + real-data validation.** A minimal PE reader
  (`structhound.pe`) extracts a module's CodeView PDB id (GUID + age), a symbol-server
  client (`structhound.symsrv`) downloads the matching PDB from Microsoft's public store,
  and `structhound layout <struct> --module <dll>` ties them together: it fetches a
  module's PDB and resolves a struct in one step. Validated against a real `ntdll.pdb`:
  190 structs modeled, **897/897 field offsets recomputed correctly** vs. the PDB's own
  records. Two refinements fell out of that run — packing is inferred when natural
  alignment doesn't reproduce the recorded layout (so packed structs like `_KTSS64` are
  correct), and structs with overlapping members (unions) are detected and skipped rather
  than reported with wrong offsets. See `examples/validate_real_pdb.py`.
- **M6 — Native PDB symbol backend.** A real `SymbolSource` (`structhound.recover.pdb`)
  that reads struct type information directly from a Windows PDB: it parses the MSF
  container and TPI stream, decodes the CodeView type records (structures/classes,
  field lists/members, pointers, arrays, modifiers, enums, built-in base/pointer types),
  and maps them onto the existing `types.py` model. Offsets are recomputed by the layout
  engine, never read from the PDB — a test cross-checks the recomputation against the
  PDB's own recorded member offsets. Exposed via `structhound layout <struct> --pdb
  <file>`; the JSON type-description loader remains as a fallback. Pure standard library
  (documented, empty `pdb` optional extra). Tests synthesize a valid MSF container so no
  binary fixture or compiler is required in CI.

## 0.1.0

First functional release. Five milestones:

- **M1 — Artifact reader.** Windows minidump container reader (header, stream directory,
  module list), format detection by magic bytes, a versioned JSON schema and console
  renderer, and the `structhound parse` command.
- **M2 — Symbol-driven layout recovery.** A C/MSVC struct-layout engine (alignment,
  padding, nested structs, arrays, packing), a `SymbolSource` abstraction with a JSON
  type-description loader, layout providers carrying provenance and confidence, a
  `LayoutResolver`, and `structhound layout`.
- **M3 — Signature-based fallback.** A wildcard byte-pattern scanner that recovers field
  offsets from instruction displacements, with a confidence model (agreement +
  corroboration, capped at 0.95), added as the third provider in the resolver chain.
- **M4 — Second artifact + second structure.** A registry hive (regf) reader that
  enumerates the key tree and decodes common value types, and a second, more complex
  struct proving the layout engine generalizes across structures and architectures.
- **M5 — Polish.** Packaging (`python -m structhound`, console script, metadata), MIT
  license, CI, linting, and a rewritten README.
