"""Demo: read a struct instance out of a dump using a computed layout.

Builds a tiny synthetic minidump holding one struct instance in memory, resolves the
struct's layout (here from the example symbol file), and reads each field out of the dump
at its address — the forensic equivalent of WinDbg's `dt EXAMPLE_STRUCT <addr>`, except
the offsets were recomputed from types so they stay correct across builds.

With a real dump it is the same command:
    structhound read crash.dmp _SOME_STRUCT --at 0x... --module C:\\path\\to\\mod.dll

Run:  python examples/demo_read_from_dump.py
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from structhound import memory  # noqa: E402
from structhound.artifacts import minidump  # noqa: E402
from structhound.recover.types import PRIMITIVES, X64, Pointer, Struct  # noqa: E402

VA = 0x7FF8_0042_0000


def _build_dump() -> bytes:
    # Lay out one EXAMPLE_STRUCT instance in memory:
    #   Flags=0xDEADBEEF, Handle=0x7FF800123456, Count=42
    instance = (
        struct.pack("<I", 0xDEADBEEF)
        + b"\x00\x00\x00\x00"
        + struct.pack("<Q", 0x7FF800123456)
        + struct.pack("<I", 42)
        + b"\x00\x00\x00\x00"
    )
    # Minimal minidump with one memory range at VA (mirrors tests/_fixtures).
    header = struct.Struct("<4sIIIIIQ")
    directory = struct.Struct("<III")
    dir_rva = header.size
    mem_rva = dir_rva + directory.size
    desc = mem_rva + 4
    blob_rva = desc + 16
    buf = bytearray()
    buf += header.pack(b"MDMP", 42899, 1, dir_rva, 0, 0, 0)
    buf += directory.pack(5, 4 + 16, mem_rva)
    buf += struct.pack("<I", 1)
    buf += struct.pack("<QII", VA, len(instance), blob_rva)
    buf += instance
    return bytes(buf)


def main() -> None:
    layout = Struct(
        "EXAMPLE_STRUCT",
        [("Flags", PRIMITIVES["u32"]), ("Handle", Pointer()), ("Count", PRIMITIVES["u32"])],
    ).layout(X64)

    data = _build_dump()
    dump = minidump.parse(data)
    reader = memory.MemoryReader(data, dump.memory_ranges)

    print(f"EXAMPLE_STRUCT @ {VA:#x}\n")
    print(f"  {'offset':>6}  {'size':>4}  {'value':>18}  field")
    for v in reader.read_struct(layout, VA):
        shown = f"{v.value:#x}" if v.value is not None else v.hex
        print(f"  {v.offset:>6}  {v.size:>4}  {shown:>18}  {v.name}")


if __name__ == "__main__":
    main()
