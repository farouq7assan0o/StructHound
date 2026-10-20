# StructHound

**A build-resilient parser for Windows in-memory, DPAPI, and registry-hive data structures — for digital forensics and incident response.**

## The problem it solves

Forensic and IR tooling that interprets Windows memory and offline artifacts relies on
*undocumented* internal structures. Microsoft changes the layout of these structures
between Windows builds, so existing open-source parsers depend on hand-maintained
offset tables that go stale the moment a new build ships. When that happens, an analyst
working an incident gets empty or wrong output and has to wait for someone to manually
determine the new layout and patch a table.

StructHound's goal is to remove that fragility: instead of trusting a static offset
table, it **derives structure layouts from the target's own binaries** (public symbols
where available, signature-based recovery where not), so it keeps producing correct
results on builds it has never encountered.

## Who it's for

Incident responders and forensic analysts who need to parse memory captures and offline
Windows artifacts reliably across heterogeneous, patched fleets — and authorized
penetration testers validating credential-hygiene findings during engagements.

> **Scope & use:** This is defensive/forensic research tooling intended for systems you
> own or are explicitly authorized to analyze (lab VMs, IR engagements, pentests with a
> signed scope). It is not an operational offensive implant and ships no payload,
> injection, or process-access component.

## Design at a glance

```
input artifact ──▶ structure recovery ──▶ typed view ──▶ decryption ──▶ report
 (dump / hive)      (symbols or sigs)      (parsed)      (DPAPI/etc.)   (JSON/CLI)
```

- **recover/** — determine structure layouts for the target build (symbol-driven first,
  signature-based fallback). The core engineering differentiator.
- **artifacts/** — readers for the supported offline artifact formats.
- **crypto/** — the documented Windows key-protection primitives needed to interpret
  protected values.
- **providers/** — per-structure interpreters that turn raw bytes into typed results.
- **report/** — JSON and human-readable output.
- **cli.py** — entry point.

## Status

- **M1 (done):** minidump container reader, format detection, JSON/console reports —
  `structhound parse <artifact>`.
- **M2 (done):** the layout-recovery engine — computes struct field offsets from type
  information (so it adapts across Windows builds) instead of trusting a static offset
  table; `structhound layout <struct> --symbols <types.json>`. Try
  `python examples/demo_across_builds.py` for the before/after.
- **M3 (done):** signature-based fallback for when symbols are unavailable — recovers
  offsets from instruction displacements in code, with a confidence score, behind the
  resolver chain symbol -> hardcoded -> signature;
  `structhound layout <struct> --signatures <sigs.json> --code <blob>`. Try
  `python examples/demo_signature.py`.

Type information currently comes from a JSON type-description file — the format a native
PDB/DIA extraction step would emit. A PDB backend is the next increment and only has to
implement the `SymbolSource` interface, so nothing downstream changes.

See `docs/DESIGN.md` for the architecture writeup and roadmap.

## License

TBD (see `LICENSE`).
