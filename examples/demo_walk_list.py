"""Demo: walk a linked list of structs in a dump by following a pointer field.

Builds a synthetic dump with three NODE structs chained by a `Next` pointer, then walks
the list from the head — reading each node with the computed layout and following `Next`
until it hits null. Cycles, null pointers, uncaptured addresses, and a max count all stop
the walk safely.

With a real dump it is the same command:
    structhound read crash.dmp _SOME_LIST_NODE --at 0x... --walk Flink --module mod.dll
    # embedded _LIST_ENTRY lists: add --link-offset <offset of the link field in the node>

Run:  python examples/demo_walk_list.py
"""

from __future__ import annotations

import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from structhound import memory  # noqa: E402
from structhound.artifacts import minidump  # noqa: E402
from structhound.recover.types import PRIMITIVES, X64, Pointer, Struct  # noqa: E402

BASE = 0x7FF8_00A0_0000


def _node(value: int, next_ptr: int) -> bytes:
    return struct.pack("<I", value) + b"\x00\x00\x00\x00" + struct.pack("<Q", next_ptr)


def _build_dump() -> bytes:
    # Three 16-byte nodes: values 100/200/300, each Next -> the following node, last null.
    blob = _node(100, BASE + 16) + _node(200, BASE + 32) + _node(300, 0)
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
    buf += struct.pack("<QII", BASE, len(blob), blob_rva)
    buf += blob
    return bytes(buf)


def main() -> None:
    layout = Struct(
        "NODE", [("Value", PRIMITIVES["u32"]), ("Next", Pointer())]
    ).layout(X64)

    data = _build_dump()
    dump = minidump.parse(data)
    reader = memory.MemoryReader(data, dump.memory_ranges)

    nodes = reader.walk(layout, BASE, "Next")
    print(f"Walked {len(nodes)} NODE(s) from {BASE:#x} following 'Next':\n")
    for i, (addr, fields) in enumerate(nodes):
        value = next(f.value for f in fields if f.name == "Value")
        nxt = next(f.value for f in fields if f.name == "Next")
        print(f"  [{i}] @{addr:#x}  Value={value}  Next={nxt:#x}")


if __name__ == "__main__":
    main()
