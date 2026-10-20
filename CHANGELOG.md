# Changelog

## Unreleased

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
