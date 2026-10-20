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
    vals = {f["name"]: f["value"] for f in doc["fields"]}
    assert vals == {"Flags": 0x11223344, "Handle": 0xCAFEF00D, "Count": 7}


def test_cli_read_uncaptured_address(tmp_path, capsys):
    dump = tmp_path / "cap.dmp"
    dump.write_bytes(build_minidump_with_memory(VA, INSTANCE))
    syms = tmp_path / "s.json"
    syms.write_text(_SYMBOL_DOC)
    rc = main(["read", str(dump), "EXAMPLE_STRUCT", "--at", "0x1000", "--symbols", str(syms)])
    assert rc == 4
    assert "not captured" in capsys.readouterr().err
