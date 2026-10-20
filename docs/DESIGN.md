# StructHound — Design & Roadmap

## Why this is hard (and therefore worth building)

The project is deliberately not a "wrapper that calls an API and formats output." The
real engineering lives in **recovering undocumented structure layouts automatically**
instead of hardcoding them. That is a mix of binary parsing, symbol resolution, and
signature-based structure discovery — the part that makes existing tools brittle.

## Core differentiator: the recovery engine

Existing parsers store a table like `{build 19041: offset 0x108, build 22621: 0x110}`.
StructHound instead computes the layout for whatever build it is handed:

1. **Symbol-driven path (preferred).** When symbols for the relevant module are
   available (offline via a symbol store, or already present in the artifact set),
   resolve field offsets directly from type information. Deterministic and exact.
2. **Signature-based fallback.** When symbols are unavailable, locate the structure by
   stable byte/instruction patterns around known reference points, then derive field
   positions from those anchors. Less certain; always reported with a confidence level.

Every parsed value carries provenance: which path produced the layout, and how
confident the recovery was. An analyst should never be guessing whether output is
trustworthy.

## Module breakdown

| Module | Responsibility |
|---|---|
| `recover/` | Layout recovery (symbol + signature engines), confidence scoring |
| `artifacts/` | Readers for supported offline artifact formats |
| `crypto/` | Documented Windows key-protection primitives |
| `providers/` | Per-structure interpreters → typed Python objects |
| `report/` | JSON schema + human-readable rendering |
| `cli.py` | Argument parsing, orchestration |

## Roadmap (rough, ~several weeks of real work)

- **M1 — Skeleton + artifact reader. [done]** Minidump container reader (header, stream
  directory, module list), format detection by magic bytes, versioned JSON schema +
  console renderer, `structhound parse`.
- **M2 — Symbol-driven recovery. [done]** C/MSVC struct-layout engine (alignment,
  padding, nested structs, arrays, packing), a `SymbolSource` abstraction with a JSON
  type-description loader (the format a PDB/DIA backend would emit), layout providers
  with provenance + confidence, a `LayoutResolver` that prefers symbols then falls back,
  and `structhound layout`. The across-builds claim is proven by
  `examples/demo_across_builds.py` and `tests/test_recover.py`: a field inserted between
  builds 22621 and 26100 breaks the hardcoded table while the symbol path stays correct.
- **M3 — Signature fallback + confidence. [done]** A wildcard byte-pattern scanner that
  recovers field offsets from instruction displacements in a code blob, a confidence
  model driven by agreement and corroboration (capped at 0.95), and a
  `SignatureLayoutProvider` + `CodeSource` that slot in as the third provider in
  `LayoutResolver` (symbol -> hardcoded -> signature). CLI:
  `structhound layout <struct> --signatures <sigs.json> --code <blob>`. See
  `examples/demo_signature.py`.
- **M4 — Second artifact source + second structure. [done]** A registry hive (regf)
  reader — base block, hbin cells, nk/vk and lf/lh/li/ri subkey lists — that enumerates
  the key tree and decodes common value types, wired into `parse` and the report
  (`details.registry`). Plus a second, more complex struct (`COMPLEX_NODE`: nested
  struct + array, arch-dependent) proving the layout engine is not special-cased — see
  `examples/example2_struct.json` and `tests/test_generalization.py`.
- **M5 — Polish. [done]** Packaging (`python -m structhound`, console script, project
  metadata, `setuptools` package discovery), MIT license, a CI workflow (lint + test on
  Python 3.10-3.12), a pinned ruff rule set, a CHANGELOG, and a portfolio-ready README.
- **M6 — Native PDB symbol backend. [done]** A real `SymbolSource` that reads struct type
  information straight out of a Windows PDB, closing the gap left by M2 (where symbol type
  info came from a JSON stand-in). It parses the MSF container, locates the TPI stream, and
  decodes the CodeView type records (`LF_STRUCTURE`/`LF_CLASS`, `LF_FIELDLIST`/`LF_MEMBER`,
  `LF_POINTER`, `LF_ARRAY`, `LF_MODIFIER`, `LF_ENUM`, and built-in base/pointer types),
  mapping them onto the existing `types.py` model. Crucially it does **not** read offsets
  from the PDB — it hands the layout engine the field *types* and recomputes every offset,
  then a test cross-checks the recomputation against the PDB's own recorded member offsets.
  Slots in behind the unchanged `SymbolLayoutProvider`/`LayoutResolver`; the JSON loader
  remains as a fallback. CLI: `structhound layout <struct> --pdb <file>`. See
  `structhound/recover/pdb.py`, `tests/test_pdb.py`, and `tests/_pdbgen.py`.
- **M7 — Symbol-server fetch + real-data validation. [done]** A minimal PE reader
  (`structhound/pe.py`) extracts a module's CodeView `RSDS` record (PDB name, GUID, age);
  a symbol-server client (`structhound/symsrv.py`) builds the Microsoft store URL and
  downloads the PDB; `structhound layout --module <dll>` chains the two into the M6
  backend. Running it against a real `ntdll.pdb` recomputed **897/897 member offsets
  across 190 structs** with zero mismatches. Two findings from that run were folded back
  in: the backend infers a struct's packing when natural alignment does not reproduce the
  recorded layout (handling packed structs such as `_KTSS64`), and it rejects structs with
  overlapping members (unions) instead of emitting wrong offsets. The recorded offsets are
  used only as an ingest-time gate — emitted offsets are always recomputed, so cross-build
  adaptation is unaffected. See `examples/validate_real_pdb.py` and
  `tests/test_pe_symsrv.py`.

### Why a native PDB reader (M6 dependency evaluation)

The obvious options were rejected for a cross-platform, pip-installable tool:

- **`pdbparse`** — a Python-2-era, unmaintained package with old `construct`/`pefile`
  pins; it does not install on modern CPython.
- **Microsoft DIA** — Windows-only, requires `msdia*.dll` + COM, and is neither
  pip-installable nor usable in cross-platform CI.

So the backend parses the needed subset of the MSF/TPI format in pure standard library,
in keeping with the rest of StructHound (no runtime dependency; an empty `pdb` optional
group documents that). Unions and bitfield members are intentionally out of scope and
reported as unsupported rather than silently mis-laid-out. Because real PDBs can't be
committed and CI may lack a C compiler, the tests synthesize a valid MSF container holding
genuine CodeView records (`tests/_pdbgen.py`); an optional test parses a real on-disk PDB
when `STRUCTHOUND_TEST_PDB`/`STRUCTHOUND_TEST_STRUCT` point at one, and is skipped
otherwise.

## Definition of done (for the portfolio claim)

Hand the tool a memory capture from a Windows build that is **not** in any offset table,
and have it produce correct, provenance-tagged output where a hardcoded-offset parser
produces nothing. That before/after is the demo and the LinkedIn story.

## Testing & ethics

- Test data is generated in isolated lab VMs the author controls, or synthesized — never
  captured from systems without authorization.
- No process-access, injection, or live-acquisition component ships in this repo; input
  is always a pre-existing, authorized artifact file.
