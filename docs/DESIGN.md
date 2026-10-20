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
- **M5 — Polish.** Docs, test fixtures (synthetic/lab-generated), demo writeup.

## Definition of done (for the portfolio claim)

Hand the tool a memory capture from a Windows build that is **not** in any offset table,
and have it produce correct, provenance-tagged output where a hardcoded-offset parser
produces nothing. That before/after is the demo and the LinkedIn story.

## Testing & ethics

- Test data is generated in isolated lab VMs the author controls, or synthesized — never
  captured from systems without authorization.
- No process-access, injection, or live-acquisition component ships in this repo; input
  is always a pre-existing, authorized artifact file.
