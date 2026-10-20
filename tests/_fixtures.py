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


def build_minidump_with_memory(va: int, blob: bytes) -> bytes:
    """A minidump whose single MemoryListStream exposes `blob` at virtual address `va`."""
    header = struct.Struct("<4sIIIIIQ")
    directory = struct.Struct("<III")

    dir_rva = header.size  # 32
    mem_list_rva = dir_rva + directory.size  # 44
    desc_off = mem_list_rva + 4  # after count u32
    blob_rva = desc_off + 16  # after one MINIDUMP_MEMORY_DESCRIPTOR

    buf = bytearray()
    buf += header.pack(b"MDMP", 42899, 1, dir_rva, 0, 0, 0)
    buf += directory.pack(5, 4 + 16, mem_list_rva)  # STREAM_MEMORY_LIST
    buf += struct.pack("<I", 1)  # one range
    buf += struct.pack("<QII", va, len(blob), blob_rva)
    buf += blob
    return bytes(buf)


# --- registry hive -------------------------------------------------------------

def _round8(n: int) -> int:
    return (n + 7) & ~7


def build_hive() -> bytes:
    """Return a minimal valid regf hive:

        [ROOT]  Val (REG_DWORD) = 0x12345678
          [SUB]  Str (REG_SZ) = "hello"
    """
    HBIN = 0x1000
    buf = bytearray(0x2000)

    # --- base block ---
    struct.pack_into("<4s", buf, 0x00, b"regf")
    struct.pack_into("<II", buf, 0x04, 1, 1)  # sequence numbers
    struct.pack_into("<II", buf, 0x14, 1, 3)  # major, minor
    struct.pack_into("<II", buf, 0x1C, 0, 1)  # file type, format
    struct.pack_into("<I", buf, 0x28, 0x1000)  # hive bins data size
    struct.pack_into("<I", buf, 0x2C, 1)  # clustering factor
    hive_name = "TESTHIVE".encode("utf-16-le")
    buf[0x30 : 0x30 + len(hive_name)] = hive_name

    # --- hbin header ---
    struct.pack_into("<4sII", buf, HBIN, b"hbin", 0, 0x1000)

    cursor = 0x20  # first cell, right after the 32-byte hbin header

    def put(payload: bytes) -> int:
        nonlocal cursor
        rel = cursor
        clen = _round8(4 + len(payload))
        struct.pack_into("<i", buf, HBIN + rel, -clen)  # negative = allocated
        buf[HBIN + rel + 4 : HBIN + rel + 4 + len(payload)] = payload
        cursor += clen
        return rel

    def nk(name, *, subkey_count, subkeys_list, value_count, values_list) -> bytes:
        rec = bytearray(0x4C + len(name))
        struct.pack_into("<2sH", rec, 0x00, b"nk", 0x0020)  # 0x20 = comp (ascii) name
        struct.pack_into("<I", rec, 0x10, 0xFFFFFFFF)  # parent (unused by parser)
        struct.pack_into("<I", rec, 0x14, subkey_count)
        struct.pack_into("<I", rec, 0x1C, subkeys_list)
        struct.pack_into("<I", rec, 0x20, 0xFFFFFFFF)
        struct.pack_into("<I", rec, 0x24, value_count)
        struct.pack_into("<I", rec, 0x28, values_list)
        struct.pack_into("<I", rec, 0x2C, 0xFFFFFFFF)
        struct.pack_into("<I", rec, 0x30, 0xFFFFFFFF)
        struct.pack_into("<H", rec, 0x48, len(name))
        rec[0x4C : 0x4C + len(name)] = name
        return bytes(rec)

    def vk(name, *, data_size, data_offset, dtype) -> bytes:
        rec = bytearray(0x14 + len(name))
        struct.pack_into("<2sH", rec, 0x00, b"vk", len(name))
        struct.pack_into("<I", rec, 0x04, data_size)
        struct.pack_into("<I", rec, 0x08, data_offset)
        struct.pack_into("<I", rec, 0x0C, dtype)
        struct.pack_into("<H", rec, 0x10, 0x0001)  # ascii name
        rec[0x14 : 0x14 + len(name)] = name
        return bytes(rec)

    # root value: REG_DWORD stored inline (high bit set), value = 0x12345678
    root_val_off = put(vk(b"Val", data_size=0x80000004, data_offset=0x12345678, dtype=4))
    root_vallist_off = put(struct.pack("<I", root_val_off))

    # SUB value: REG_SZ "hello" in a separate data cell
    sz_data = "hello\x00".encode("utf-16-le")
    sub_data_off = put(sz_data)
    sub_val_off = put(vk(b"Str", data_size=len(sz_data), data_offset=sub_data_off, dtype=1))
    sub_vallist_off = put(struct.pack("<I", sub_val_off))
    sub_nk_off = put(
        nk(b"SUB", subkey_count=0, subkeys_list=0xFFFFFFFF,
           value_count=1, values_list=sub_vallist_off)
    )

    # root subkey list (lf) -> SUB
    lf = bytearray(4 + 8)
    struct.pack_into("<2sH", lf, 0x00, b"lf", 1)
    struct.pack_into("<II", lf, 0x04, sub_nk_off, 0)
    root_subkeys_off = put(bytes(lf))

    root_nk_off = put(
        nk(b"ROOT", subkey_count=1, subkeys_list=root_subkeys_off,
           value_count=1, values_list=root_vallist_off)
    )

    struct.pack_into("<I", buf, 0x24, root_nk_off)  # base block root cell offset
    return bytes(buf)


# --- PE module with a CodeView (RSDS) debug record -----------------------------

def build_pe_with_pdb(
    *,
    pdb_name: str = "ntdll.pdb",
    guid: bytes = bytes(range(16)),
    age: int = 1,
) -> bytes:
    """Return a minimal PE32+ whose debug directory points at a PDB (RSDS record)."""
    buf = bytearray(0x1500)
    e_lfanew = 0x80

    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, e_lfanew)
    buf[e_lfanew : e_lfanew + 4] = b"PE\x00\x00"

    coff = e_lfanew + 4
    opt_size = 0xF0
    struct.pack_into("<HH", buf, coff, 0x8664, 1)  # machine, num_sections
    struct.pack_into("<H", buf, coff + 16, opt_size)

    opt = coff + 20
    struct.pack_into("<H", buf, opt, 0x20B)  # PE32+ magic
    struct.pack_into("<I", buf, opt + 108, 16)  # NumberOfRvaAndSizes
    dirs = opt + 112
    struct.pack_into("<II", buf, dirs + 6 * 8, 0x1000, 28)  # debug dir: RVA, size

    # one section: RVA 0x1000..0x2000 maps to file 0x400
    sec = opt + opt_size
    buf[sec : sec + 8] = b".rdata\x00\x00"
    struct.pack_into("<IIII", buf, sec + 8, 0x1000, 0x1000, 0x1000, 0x400)

    # IMAGE_DEBUG_DIRECTORY at file 0x400
    dbg = 0x400
    cv_ptr = 0x420
    cv = b"RSDS" + guid + struct.pack("<I", age) + pdb_name.encode("latin-1") + b"\x00"
    struct.pack_into("<I", buf, dbg + 12, 2)  # type = CODEVIEW
    struct.pack_into("<I", buf, dbg + 16, len(cv))  # SizeOfData
    struct.pack_into("<I", buf, dbg + 24, cv_ptr)  # PointerToRawData
    buf[cv_ptr : cv_ptr + len(cv)] = cv

    return bytes(buf)
