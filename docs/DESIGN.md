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

- **M1 — Skeleton + artifact reader.** Parse one offline artifact format end-to-end;
  stable CLI; JSON output schema fixed.
- **M2 — Symbol-driven recovery.** Resolve structure offsets from symbols for a single
  target structure on 2–3 Windows builds. Prove the "works across builds" claim with a
  before/after against a hardcoded table.
- **M3 — Signature fallback + confidence.** Recover the same structure with symbols
  disabled; report confidence.
- **M4 — Second artifact source + second structure.** Show the recovery engine
  generalizes beyond one case.
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
