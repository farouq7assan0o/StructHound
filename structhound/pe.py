"""Minimal PE reader for one job: find which PDB belongs to a module.

A Windows PE (``.dll``/``.exe``) records, in its debug directory, a CodeView ``RSDS``
record naming the PDB that carries its symbols — a GUID, an age, and the PDB file name.
That triple is exactly what Microsoft's public symbol server is keyed on, so reading it
lets StructHound fetch the right PDB for a module it finds in a dump or on disk.

This parses just enough of the PE format (headers, section table, debug directory) to
extract that record. It is not a general PE library.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

IMAGE_DIRECTORY_ENTRY_DEBUG = 6
IMAGE_DEBUG_TYPE_CODEVIEW = 2


class PEError(Exception):
    """Raised when the bytes are not a parseable PE or carry no CodeView record."""


@dataclass
class PdbRef:
    """Identifies the PDB that belongs to a module."""

    pdb_name: str  # base name, e.g. "ntdll.pdb"
    guid: bytes  # raw 16-byte GUID as stored
    age: int

    @property
    def signature(self) -> str:
        """The symbol-server directory key: GUID (mixed-endian) + age, uppercase hex."""
        d1, d2, d3 = struct.unpack_from("<IHH", self.guid, 0)
        tail = self.guid[8:16].hex().upper()
        return f"{d1:08X}{d2:04X}{d3:04X}{tail}{self.age:X}"


def _rva_to_offset(rva: int, sections: list[tuple[int, int, int, int]]) -> int:
    for va, vsize, raw_ptr, raw_size in sections:
        span = max(vsize, raw_size)
        if va <= rva < va + span:
            return rva - va + raw_ptr
    raise PEError(f"RVA {rva:#x} not in any section")


def read_pdb_ref(data: bytes) -> PdbRef:
    """Extract the CodeView :class:`PdbRef` from PE file bytes."""
    if data[:2] != b"MZ":
        raise PEError("not a PE (missing MZ)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise PEError("not a PE (missing PE signature)")

    coff = e_lfanew + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20

    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:  # PE32+
        num_dirs_off, dirs_off = opt + 108, opt + 112
    elif magic == 0x10B:  # PE32
        num_dirs_off, dirs_off = opt + 92, opt + 96
    else:
        raise PEError(f"unknown optional header magic {magic:#06x}")

    num_dirs = struct.unpack_from("<I", data, num_dirs_off)[0]
    if num_dirs <= IMAGE_DIRECTORY_ENTRY_DEBUG:
        raise PEError("no debug data directory")
    dbg_rva, dbg_size = struct.unpack_from(
        "<II", data, dirs_off + IMAGE_DIRECTORY_ENTRY_DEBUG * 8
    )
    if dbg_rva == 0 or dbg_size == 0:
        raise PEError("module has no debug directory")

    # Section table follows the optional header.
    sec_off = opt + opt_size
    sections: list[tuple[int, int, int, int]] = []
    for i in range(num_sections):
        base = sec_off + i * 40
        vsize, va, raw_size, raw_ptr = struct.unpack_from("<IIII", data, base + 8)
        sections.append((va, vsize, raw_ptr, raw_size))

    dbg_off = _rva_to_offset(dbg_rva, sections)
    for i in range(dbg_size // 28):
        entry = dbg_off + i * 28
        dtype = struct.unpack_from("<I", data, entry + 12)[0]
        size_of_data = struct.unpack_from("<I", data, entry + 16)[0]
        ptr_raw = struct.unpack_from("<I", data, entry + 24)[0]
        if dtype != IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        cv = data[ptr_raw : ptr_raw + size_of_data]
        if cv[:4] != b"RSDS":
            raise PEError("CodeView record is not RSDS (PDB 7.0)")
        guid = cv[4:20]
        age = struct.unpack_from("<I", cv, 20)[0]
        name = cv[24:].split(b"\x00", 1)[0].decode("latin-1")
        pdb_name = name.replace("\\", "/").rsplit("/", 1)[-1]
        return PdbRef(pdb_name=pdb_name, guid=guid, age=age)

    raise PEError("no CodeView debug entry found")


def read_pdb_ref_file(path: str) -> PdbRef:
    with open(path, "rb") as fh:
        return read_pdb_ref(fh.read())
