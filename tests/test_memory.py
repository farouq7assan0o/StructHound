"""Tests for reading struct instances out of a dump's memory."""

import json
import struct

import pytest

from structhound import memory
from structhound.artifacts import minidump
from structhound.cli import main
from structhound.recover.types import PRIMITIVES, X64, Pointer, Struct
from tests._fixtures import build_minidump_with_memory

VA = 0x7FF8_0010_0000

# A struct instance: Flags=0x11223344 (u32), pad, Handle=0xCAFEF00D (ptr), Count=7 (u32).
INSTANCE = (
    struct.pack("<I", 0x11223344)
    + b"\x00\x00\x00\x00"
    + struct.pack("<Q", 0xCAFEF00D)
    + struct.pack("<I", 7)
    + b"\x00\x00\x00\x00"
)


def _layout():
    return Struct(
        "EXAMPLE_STRUCT",
        [("Flags", PRIMITIVES["u32"]), ("Handle", Pointer()), ("Count", PRIMITIVES["u32"])],
    ).layout(X64)


def test_minidump_exposes_memory_range():
    dump = minidump.parse(build_minidump_with_memory(VA, INSTANCE))
    assert len(dump.memory_ranges) == 1
    assert dump.memory_ranges[0].va == VA
    assert dump.memory_ranges[0].size == len(INSTANCE)


def test_memory_reader_reads_bytes():
    data = build_minidump_with_memory(VA, INSTANCE)
    dump = minidump.parse(data)
    reader = memory.MemoryReader(data, dump.memory_ranges)
    assert reader.read(VA, 4) == struct.pack("<I", 0x11223344)


def test_read_struct_decodes_fields():
    data = build_minidump_with_memory(VA, INSTANCE)
    dump = minidump.parse(data)
    reader = memory.MemoryReader(data, dump.memory_ranges)
    values = {v.name: v.value for v in reader.read_struct(_layout(), VA)}
    assert values == {"Flags": 0x11223344, "Handle": 0xCAFEF00D, "Count": 7}


def test_read_out_of_range_raises():
    data = build_minidump_with_memory(VA, INSTANCE)
    dump = minidump.parse(data)
    reader = memory.MemoryReader(data, dump.memory_ranges)
    with pytest.raises(memory.MemoryError_):
        reader.read(0x1000, 8)


# --- CLI ----------------------------------------------------------------------

_SYMBOL_DOC = json.dumps(
    {
        "module": "example.dll",
        "build": "1",
        "structs": {
            "EXAMPLE_STRUCT": {
                "fields": [
                    {"name": "Flags", "type": "u32"},
                    {"name": "Handle", "type": "ptr"},
                    {"name": "Count", "type": "u32"},
                ]
            }
        },
    }
)


def test_cli_read_json(tmp_path, capsys):
    dump = tmp_path / "cap.dmp"
    dump.write_bytes(build_minidump_with_memory(VA, INSTANCE))
    syms = tmp_path / "s.json"
    syms.write_text(_SYMBOL_DOC)
    argv = ["read", str(dump), "EXAMPLE_STRUCT", "--at", hex(VA),
            "--symbols", str(syms), "--json", "-"]
    rc = main(argv)
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert len(doc["nodes"]) == 1
    vals = {f["name"]: f["value"] for f in doc["nodes"][0]["fields"]}
    assert vals == {"Flags": 0x11223344, "Handle": 0xCAFEF00D, "Count": 7}


def test_cli_read_uncaptured_address(tmp_path, capsys):
    dump = tmp_path / "cap.dmp"
    dump.write_bytes(build_minidump_with_memory(VA, INSTANCE))
    syms = tmp_path / "s.json"
    syms.write_text(_SYMBOL_DOC)
    rc = main(["read", str(dump), "EXAMPLE_STRUCT", "--at", "0x1000", "--symbols", str(syms)])
    assert rc == 4
    assert "not captured" in capsys.readouterr().err


# --- pointer-following / linked-list walk --------------------------------------

NODE_VA = 0x7FF8_0020_0000


def _node(value: int, next_ptr: int) -> bytes:
    # NODE { u32 Value @0; (pad) ptr Next @8 }  -> 16 bytes
    return struct.pack("<I", value) + b"\x00\x00\x00\x00" + struct.pack("<Q", next_ptr)


def _node_layout():
    return Struct("NODE", [("Value", PRIMITIVES["u32"]), ("Next", Pointer())]).layout(X64)


def _list_dump(nexts):
    """Three contiguous nodes (Values 10/20/30) with the given Next pointers."""
    blob = b"".join(_node(v, n) for v, n in zip((10, 20, 30), nexts))
    return build_minidump_with_memory(NODE_VA, blob)


def _reader(data):
    return memory.MemoryReader(data, minidump.parse(data).memory_ranges)


def test_walk_follows_next_until_null():
    data = _list_dump([NODE_VA + 16, NODE_VA + 32, 0])
    nodes = _reader(data).walk(_node_layout(), NODE_VA, "Next")
    assert [addr for addr, _ in nodes] == [NODE_VA, NODE_VA + 16, NODE_VA + 32]
    assert [dict((f.name, f.value) for f in fv)["Value"] for _, fv in nodes] == [10, 20, 30]


def test_walk_stops_on_cycle():
    # Node2 points back to the head -> circular; walk must terminate, not loop.
    data = _list_dump([NODE_VA + 16, NODE_VA + 32, NODE_VA])
    nodes = _reader(data).walk(_node_layout(), NODE_VA, "Next")
    assert len(nodes) == 3


def test_walk_respects_max():
    data = _list_dump([NODE_VA + 16, NODE_VA + 32, 0])
    nodes = _reader(data).walk(_node_layout(), NODE_VA, "Next", max_nodes=2)
    assert len(nodes) == 2


def test_walk_link_offset_for_embedded_list():
    # Next points 8 bytes into the following node; link_offset backs it out to the base.
    data = _list_dump([NODE_VA + 16 + 8, NODE_VA + 32 + 8, 0])
    nodes = _reader(data).walk(_node_layout(), NODE_VA, "Next", link_offset=8)
    assert [addr for addr, _ in nodes] == [NODE_VA, NODE_VA + 16, NODE_VA + 32]


def test_walk_unknown_field_raises():
    data = _list_dump([0, 0, 0])
    with pytest.raises(memory.MemoryError_):
        _reader(data).walk(_node_layout(), NODE_VA, "Nope")


_NODE_DOC = json.dumps(
    {
        "module": "m.dll",
        "build": "1",
        "structs": {
            "NODE": {"fields": [{"name": "Value", "type": "u32"}, {"name": "Next", "type": "ptr"}]}
        },
    }
)


def test_cli_walk_json(tmp_path, capsys):
    dump = tmp_path / "cap.dmp"
    dump.write_bytes(_list_dump([NODE_VA + 16, NODE_VA + 32, 0]))
    syms = tmp_path / "n.json"
    syms.write_text(_NODE_DOC)
    argv = ["read", str(dump), "NODE", "--at", hex(NODE_VA),
            "--symbols", str(syms), "--walk", "Next", "--json", "-"]
    assert main(argv) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["walk"] == "Next"
    values = [n["fields"][0]["value"] for n in doc["nodes"]]
    assert values == [10, 20, 30]
