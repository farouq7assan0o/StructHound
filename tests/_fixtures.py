"""Build minimal synthetic minidumps in memory for tests.

No real captured data is used anywhere in the test suite — these bytes are assembled
by hand to exercise the parser.
"""

from __future__ import annotations

import struct

SIGNATURE = 0x504D444D
STREAM_MODULE_LIST = 4


def _vs_fixedfileinfo(major: int, minor: int, build: int, revision: int) -> bytes:
    file_ver_ms = (major << 16) | minor
    file_ver_ls = (build << 16) | revision
    fields = [0] * 13
    fields[2] = file_ver_ms
    fields[3] = file_ver_ls
    return struct.pack("<13I", *fields)


def build_minidump(
    *,
    module_name: str = "ntdll.dll",
    base: int = 0x7FF8_1234_0000,
    size: int = 0x1F_0000,
    timestamp: int = 0x6500_0000,
    version: tuple[int, int, int, int] = (10, 0, 22621, 3296),
) -> bytes:
    """Return bytes for a minidump with exactly one module."""
    header = struct.Struct("<4sIIIIIQ")
    directory = struct.Struct("<III")
    module_fixed = struct.Struct("<QIIII")

    header_size = header.size  # 32
    dir_rva = header_size
    dir_size = directory.size  # 12 for one entry
    module_list_rva = dir_rva + dir_size

    # module list = count(4) + one module record(108)
    module_record_size = module_fixed.size + 52 + 8 + 8 + 16  # 108
    name_rva = module_list_rva + 4 + module_record_size

    buf = bytearray()
    # header
    buf += header.pack(b"MDMP", 42899, 1, dir_rva, 0, 0x1234, 0)
    # stream directory (one entry -> module list)
    buf += directory.pack(STREAM_MODULE_LIST, 4 + module_record_size, module_list_rva)
    # module list
    buf += struct.pack("<I", 1)  # module count
    buf += module_fixed.pack(base, size, 0, timestamp, name_rva)
    buf += _vs_fixedfileinfo(*version)
    buf += struct.pack("<II", 0, 0)  # CvRecord location
    buf += struct.pack("<II", 0, 0)  # MiscRecord location
    buf += struct.pack("<QQ", 0, 0)  # Reserved0, Reserved1
    # module name (MINIDUMP_STRING: byte length + UTF-16LE)
    name_bytes = module_name.encode("utf-16-le")
    buf += struct.pack("<I", len(name_bytes))
    buf += name_bytes

    assert len(buf) == name_rva + 4 + len(name_bytes)
    return bytes(buf)
