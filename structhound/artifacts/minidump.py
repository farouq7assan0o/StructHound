"""Reader for the Windows minidump (.dmp) container format.

The minidump layout is publicly documented by Microsoft (MINIDUMP_HEADER,
MINIDUMP_DIRECTORY, MINIDUMP_MODULE_LIST, ...). This module parses the container
structure only — the header, the stream directory, and the module list — which is
enough to identify the capture and enumerate loaded modules with their versions.

Module version/build information is what later milestones hand to the layout-recovery
engine, so getting a reliable module list out of a dump is the foundation for everything
else.

Only pre-existing, authorized artifact files are read. Nothing here acquires memory.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

MINIDUMP_SIGNATURE = 0x504D444D  # b"MDMP" little-endian

# Stream type identifiers we care about (full set is larger).
STREAM_MODULE_LIST = 4
STREAM_MEMORY_LIST = 5
STREAM_MEMORY64_LIST = 9

_HEADER = struct.Struct("<4sIIIIIQ")  # sig, version, n_streams, dir_rva, checksum, ts, flags
_DIRECTORY = struct.Struct("<III")  # stream_type, data_size, rva
_MODULE_FIXED = struct.Struct("<QIIII")  # base, size, checksum, timestamp, name_rva
_VS_FIXEDFILEINFO = struct.Struct("<13I")
_LOCATION = struct.Struct("<II")  # data_size, rva
_RESERVED = struct.Struct("<QQ")


class MinidumpError(Exception):
    """Raised when the bytes are not a valid/parseable minidump."""


@dataclass
class Module:
    name: str
    base: int
    size: int
    timestamp: int
    file_version: str  # "major.minor.build.revision"

    @property
    def end(self) -> int:
        return self.base + self.size


@dataclass
class MemoryRange:
    """A span of process virtual memory captured in the dump."""

    va: int  # virtual address where this span starts
    size: int
    file_offset: int  # where the bytes live in the dump file


@dataclass
class Minidump:
    version: int
    stream_count: int
    timestamp: int
    flags: int
    modules: list[Module] = field(default_factory=list)
    memory_ranges: list[MemoryRange] = field(default_factory=list)


def is_minidump(data: bytes) -> bool:
    return len(data) >= 4 and struct.unpack_from("<I", data, 0)[0] == MINIDUMP_SIGNATURE


def _read_string(data: bytes, rva: int) -> str:
    """MINIDUMP_STRING: uint32 byte-length, then UTF-16LE characters."""
    if rva + 4 > len(data):
        raise MinidumpError(f"module name RVA {rva:#x} out of bounds")
    (length,) = struct.unpack_from("<I", data, rva)
    start = rva + 4
    end = start + length
    if end > len(data):
        raise MinidumpError(f"module name at {rva:#x} runs past end of dump")
    return data[start:end].decode("utf-16-le", errors="replace")


def _format_version(fixed: tuple[int, ...]) -> str:
    # VS_FIXEDFILEINFO order: sig, strucver, fileverMS, fileverLS, prodverMS, prodverLS, ...
    file_ver_ms, file_ver_ls = fixed[2], fixed[3]
    major = (file_ver_ms >> 16) & 0xFFFF
    minor = file_ver_ms & 0xFFFF
    build = (file_ver_ls >> 16) & 0xFFFF
    revision = file_ver_ls & 0xFFFF
    return f"{major}.{minor}.{build}.{revision}"


def _parse_module(data: bytes, offset: int) -> Module:
    base, size, _checksum, timestamp, name_rva = _MODULE_FIXED.unpack_from(data, offset)
    fixed = _VS_FIXEDFILEINFO.unpack_from(data, offset + _MODULE_FIXED.size)
    name = _read_string(data, name_rva)
    return Module(
        name=name,
        base=base,
        size=size,
        timestamp=timestamp,
        file_version=_format_version(fixed),
    )


def _module_record_size() -> int:
    # fixed + VS_FIXEDFILEINFO + CvRecord(loc) + MiscRecord(loc) + Reserved0/1
    return (
        _MODULE_FIXED.size
        + _VS_FIXEDFILEINFO.size
        + _LOCATION.size * 2
        + _RESERVED.size
    )


def parse(data: bytes) -> Minidump:
    """Parse the container structure of a minidump and return a Minidump."""
    if len(data) < _HEADER.size:
        raise MinidumpError("data too small to be a minidump")

    sig, version, n_streams, dir_rva, _checksum, timestamp, flags = _HEADER.unpack_from(data, 0)
    if struct.unpack("<I", sig)[0] != MINIDUMP_SIGNATURE:
        raise MinidumpError("bad minidump signature")

    dump = Minidump(
        version=version & 0xFFFF,
        stream_count=n_streams,
        timestamp=timestamp,
        flags=flags,
    )

    for i in range(n_streams):
        entry_off = dir_rva + i * _DIRECTORY.size
        if entry_off + _DIRECTORY.size > len(data):
            raise MinidumpError("stream directory runs past end of dump")
        stream_type, _data_size, rva = _DIRECTORY.unpack_from(data, entry_off)
        if stream_type == STREAM_MODULE_LIST:
            dump.modules = _parse_module_list(data, rva)
        elif stream_type == STREAM_MEMORY_LIST:
            dump.memory_ranges += _parse_memory_list(data, rva)
        elif stream_type == STREAM_MEMORY64_LIST:
            dump.memory_ranges += _parse_memory64_list(data, rva)

    return dump


def _parse_memory_list(data: bytes, rva: int) -> list[MemoryRange]:
    """MINIDUMP_MEMORY_LIST: count(u32), then [StartVA(u64), DataSize(u32), Rva(u32)]."""
    if rva + 4 > len(data):
        raise MinidumpError("memory list RVA out of bounds")
    (count,) = struct.unpack_from("<I", data, rva)
    ranges: list[MemoryRange] = []
    off = rva + 4
    for _ in range(count):
        va, size, data_rva = struct.unpack_from("<QII", data, off)
        ranges.append(MemoryRange(va=va, size=size, file_offset=data_rva))
        off += 16
    return ranges


def _parse_memory64_list(data: bytes, rva: int) -> list[MemoryRange]:
    """MINIDUMP_MEMORY64_LIST: count(u64), base_rva(u64), then [StartVA(u64), Size(u64)].

    Unlike the 32-bit list, the bytes are stored contiguously from base_rva, so each
    range's file offset is the running sum of the preceding ranges' sizes.
    """
    if rva + 16 > len(data):
        raise MinidumpError("memory64 list RVA out of bounds")
    count, base_rva = struct.unpack_from("<QQ", data, rva)
    ranges: list[MemoryRange] = []
    off = rva + 16
    file_off = base_rva
    for _ in range(count):
        va, size = struct.unpack_from("<QQ", data, off)
        ranges.append(MemoryRange(va=va, size=size, file_offset=file_off))
        file_off += size
        off += 16
    return ranges


def _parse_module_list(data: bytes, rva: int) -> list[Module]:
    if rva + 4 > len(data):
        raise MinidumpError("module list RVA out of bounds")
    (count,) = struct.unpack_from("<I", data, rva)
    record_size = _module_record_size()
    modules: list[Module] = []
    base = rva + 4
    for i in range(count):
        off = base + i * record_size
        if off + record_size > len(data):
            raise MinidumpError("module record runs past end of dump")
        modules.append(_parse_module(data, off))
    return modules
