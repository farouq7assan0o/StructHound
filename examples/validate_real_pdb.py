"""Validate StructHound against a real Microsoft PDB (requires network).

End-to-end proof that the layout engine recomputes *real* Windows structure layouts,
not just synthetic fixtures:

1. read a module's debug info to find its PDB id (GUID + age),
2. fetch that PDB from Microsoft's public symbol server,
3. parse every struct it defines,
4. recompute each field offset from types and compare to the offset the PDB recorded.

Because StructHound only ever emits recomputed offsets, 100% agreement here means it
would stay correct on a build whose offsets no static table has.

Run (Windows, online):
    python examples/validate_real_pdb.py
    python examples/validate_real_pdb.py C:\\Windows\\System32\\kernelbase.dll
"""

from __future__ import annotations

import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from structhound import pe, symsrv  # noqa: E402
from structhound.recover.pdb import parse_pdb  # noqa: E402
from structhound.recover.types import X64  # noqa: E402

DEFAULT_MODULE = r"C:\Windows\System32\ntdll.dll"


def main() -> int:
    module = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODULE
    if not os.path.exists(module):
        print(f"module not found: {module}")
        return 1

    ref = pe.read_pdb_ref_file(module)
    print(f"module : {module}")
    print(f"pdb    : {ref.pdb_name}  ({ref.signature})")

    dest = os.path.join(tempfile.gettempdir(), "structhound-symbols")
    print(f"fetch  : {symsrv.pdb_url(ref)}")
    pdb_path = symsrv.download_pdb(ref, dest)
    print(f"saved  : {pdb_path} ({os.path.getsize(pdb_path)} bytes)\n")

    info = parse_pdb(pdb_path, X64)
    ok = bad = 0
    mismatches = []
    for name, struct in info.structs.items():
        layout = struct.layout(X64)
        for fname, recorded in info.recorded_offsets.get(name, {}).items():
            computed = layout.fields[fname].offset if fname in layout.fields else None
            if computed == recorded:
                ok += 1
            else:
                bad += 1
                mismatches.append(f"{name}.{fname}: computed {computed} != recorded {recorded}")

    print(f"structs modeled : {len(info.structs)}")
    print(f"fields checked  : {ok + bad}")
    print(f"offsets matching: {ok}")
    print(f"mismatches      : {bad}")
    for m in mismatches[:20]:
        print("  -", m)

    # Show a few recovered structs as a sanity read.
    print("\nsample layouts:")
    for name in ("_UNICODE_STRING", "_LIST_ENTRY"):
        if name in info.structs:
            layout = info.structs[name].layout(X64)
            fields = ", ".join(f"{f}@{i.offset}" for f, i in layout.fields.items())
            print(f"  {name} (size {layout.total_size}): {fields}")

    return 0 if bad == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
