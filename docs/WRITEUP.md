# StructHound — write-up drafts

Two drafts you can post as-is or trim: a short LinkedIn version and a longer blog
version. Swap in your repo link where marked. Numbers below are what the tool actually
produced against a real `ntdll.pdb` (190 structs, 897/897 offsets) — keep them honest if
you re-run on a different build.

---

## LinkedIn post (short)

Every DFIR tool that reads Windows memory has the same quiet failure mode: it stores
*hardcoded struct offsets per Windows build*. Microsoft inserts a field, the offsets
shift, and the tool silently returns garbage on the next build until a human reverses the
new layout by hand.

So I built **StructHound** — a forensic parser that doesn't store offsets. It stores the
field *types* and **computes** the offsets, applying the same alignment and packing rules
the compiler did. Insert a field upstream, recompute, still correct — including on a build
the tool has never seen.

To check it wasn't just passing its own synthetic tests, I pointed it at a real
`ntdll.pdb` pulled from Microsoft's symbol server: read the field types, recompute every
offset, compare to the PDB's own records.

→ 190 structures, **897 of 897 field offsets correct.**

Then I diffed two real builds — Windows 10 (19041) vs Windows 11 (26100) ntdll — and it
reported exactly what Microsoft moved: **15 structures with changed field layouts, 42
added, 10 removed.** For example `_HEAP_COUNTERS` grew by 8 bytes — two fields inserted at
offset 24, shifting every field after them. A hardcoded offset table built for 19041
reads all of those from the wrong place on 26100. StructHound recomputed them.

That validation also caught two things worth fixing: a packed struct (`_KTSS64`) the
engine now infers packing for, and unions, which it now detects and refuses rather than
reporting wrong offsets.

Pure-Python PE + PDB (MSF/TPI/CodeView) parsing, no third-party deps. Built for IR and
authorized engagements — it ships no acquisition component; you feed it artifacts you're
allowed to analyze.

Code + write-up: https://github.com/farouq7assan0o/StructHound

#DFIR #ReverseEngineering #WindowsInternals #IncidentResponse

---

## Blog / longer version

### The problem nobody puts in the README

Tools that interpret Windows memory — credential parsers, dump analyzers, IR triage
scripts — all depend on *undocumented* internal structures. The usual way to handle that
is a table: "on build 22621, field X is at offset 0x10." It works right up until
Microsoft reorders or inserts a field. Then every offset after it shifts, the table is
wrong, and the tool fails quietly on the next Patch Tuesday until someone reverses the new
layout and patches the table by hand.

I've been on the receiving end of that during engagements. The fix shouldn't be "wait for
a maintainer."

### The idea: compute, don't store

A struct's offsets aren't magic — they fall out of the field *types* plus the compiler's
alignment and packing rules. So StructHound stores the types and recomputes the offsets
every time:

```
            a field is inserted between builds...
build 22621:  Flags(0)  Handle(8)   Count(16)                 size 24
build 26100:  Flags(0)  Extra(8)    Handle(16)  Count(24)     size 32
                                     ^^^^^^^^^^  ^^^^^^^^
hardcoded offset table (built for 22621):   BROKEN on 26100
StructHound (computes from types):          correct on both
```

The core is a small C/MSVC layout engine — alignment, padding, nested structs, arrays,
`#pragma pack` — fed by three sources, tried in order of trust:

1. **Symbols** (a PDB): exact, and build-resilient because the types come from that build.
2. **A hardcoded table**: the legacy baseline, kept only as a fallback.
3. **Signatures**: when there are no symbols, scan code for instructions like
   `mov rax,[rcx+0x10]` and read the offset out of the displacement — with a confidence
   score, never treated as certain.

Every result is tagged with how it was produced and how much to trust it.

### Proving it on real data

Synthetic tests prove the math; they don't prove the tool survives a real Microsoft PDB.
So the validation step reads `ntdll.dll`'s debug directory to get its PDB id, downloads
the matching `ntdll.pdb` from Microsoft's public symbol server, parses every struct, and
does one thing: recompute each field offset from types and compare it to the offset the
PDB itself recorded.

**Result: 190 structures modeled, 897 of 897 field offsets correct.**

Then the real cross-build test. I fetched `ntdll.pdb` for two genuinely different builds —
Windows 10 (19041) and Windows 11 (26100) — and diffed them. StructHound reported exactly
what Microsoft changed: **15 structures with moved/resized fields, 42 added, 10 removed.**
`_HEAP_COUNTERS`, for instance, grew from 120 to 128 bytes because two counters were
inserted at offset 24 — which shifted every field after them (`TotalSegments` 32→40,
`TotalUCRs` 36→44, and so on). That shift is the exact thing that silently breaks a
hardcoded offset table. StructHound recomputed every offset on both sides and told me
what moved.

Getting to 897/897 took two honest fixes that only a real PDB would surface:

- **Packing.** `_KTSS64` is `#pragma pack(4)`; natural alignment put a `uint64` at offset
  8 where the compiler put it at 4. The engine now infers the packing that reproduces the
  recorded layout, so packed structs come out right. (The recorded offsets are used only
  as an ingest-time check — what the tool *emits* is always recomputed, so cross-build
  behavior is unaffected.)
- **Unions.** A union means two members share an offset, which a sequential layout can't
  represent. Rather than emit confident-but-wrong offsets, StructHound detects the overlap
  and refuses the struct — a limitation I'd rather state than hide.

### What it is (and isn't)

It's pure standard library — a from-scratch PE reader and a PDB reader (MSF container →
TPI stream → CodeView type records), because the existing Python PDB libraries don't
install on modern CPython and DIA is Windows/COM-only. No third-party dependencies.

It's defensive/forensic tooling: you point it at artifacts you own or are authorized to
analyze. It ships no acquisition, injection, or process-access component — input is always
a pre-existing file.

Next: widening artifact coverage, and reading struct fields straight out of a dump using
the recomputed layouts.

Code: https://github.com/farouq7assan0o/StructHound
