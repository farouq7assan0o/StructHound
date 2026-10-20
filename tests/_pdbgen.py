"""Synthesize a minimal but real MSF/PDB container for tests.

Real PDBs can't be committed and there's no C compiler available in CI, so instead of vendoring a
binary we *build* a valid MSF 7.00 container in memory whose TPI stream holds genuine CodeView type
records. The native reader in :mod:`structhound.recover.pdb` parses it through the full
MSF -> TPI -> types path, so this exercises the real backend end to end, cross-platform, with no
external dependency.

The one struct it describes::

    struct EXAMPLE_STRUCT {   // x64 natural-alignment offsets
        uint32_t Flags;       // @0
        void    *Handle;      // @8   (built-in T_64PVOID)
        SUB      Sub;         // @16  struct SUB { uint64_t Value; }
        uint8_t  Pad[16];     // @24
    };                        // sizeof == 40
"""

from __future__ import annotations

import struct

# CodeView leaves (kept local so the generator is independent of the reader's constants)
LF_STRUCTURE = 0x1505
LF_FIELDLIST = 0x1203
LF_ARRAY = 0x1503
LF_MEMBER = 0x150D

# built-in base types
T_UINT4 = 0x0075
T_UQUAD = 0x0023
T_UCHAR = 0x0020
T_64PVOID = 0x0603  # built-in 64-bit pointer to void

BLOCK_SIZE = 4096
TPI_HEADER_SIZE = 56
TYPE_INDEX_BEGIN = 0x1000


def _numeric(value: int) -> bytes:
    if value < 0x8000:
        return struct.pack("<H", value)
    if value <= 0xFFFF:
        return struct.pack("<HH", 0x8002, value)  # LF_USHORT
    return struct.pack("<HI", 0x8004, value)  # LF_ULONG


def _cstr(name: str) -> bytes:
    return name.encode("latin-1") + b"\x00"


def _pad_to_4(body: bytes) -> bytes:
    """Pad to a 4-byte boundary with descending LF_PAD bytes (0xF0|n ... 0xF1)."""
    p = (-len(body)) % 4
    return body + bytes(0xF0 + (p - i) for i in range(p))


def _record(leaf: int, body: bytes) -> bytes:
    inner = struct.pack("<H", leaf) + body
    # Pad so the record length is == 2 (mod 4): with the 2-byte length prefix the stored
    # record is then 4-byte aligned, as the TPI stream requires.
    p = (2 - len(inner)) % 4
    inner += bytes(0xF0 + (p - i) for i in range(p))
    # record length counts everything after the u16 length field
    return struct.pack("<H", len(inner)) + inner


def _member(name: str, type_index: int, offset: int) -> bytes:
    body = struct.pack("<HI", 0, type_index) + _numeric(offset) + _cstr(name)
    return _pad_to_4(struct.pack("<H", LF_MEMBER) + body)


def build_tpi_stream() -> bytes:
    records: list[bytes] = []

    # 0x1000: field list for SUB -> { Value: uint64 @0 }
    sub_fieldlist = _member("Value", T_UQUAD, 0)
    records.append(_record(LF_FIELDLIST, sub_fieldlist))

    # 0x1001: struct SUB
    sub_struct = (
        struct.pack("<HHIII", 1, 0, TYPE_INDEX_BEGIN + 0, 0, 0)
        + _numeric(8)
        + _cstr("SUB")
    )
    records.append(_record(LF_STRUCTURE, sub_struct))

    # 0x1002: array uint8[16]
    array_body = struct.pack("<II", T_UCHAR, T_UQUAD) + _numeric(16) + _cstr("")
    records.append(_record(LF_ARRAY, array_body))

    # 0x1003: field list for EXAMPLE_STRUCT
    example_fieldlist = (
        _member("Flags", T_UINT4, 0)
        + _member("Handle", T_64PVOID, 8)
        + _member("Sub", TYPE_INDEX_BEGIN + 1, 16)
        + _member("Pad", TYPE_INDEX_BEGIN + 2, 24)
    )
    records.append(_record(LF_FIELDLIST, example_fieldlist))

    # 0x1004: struct EXAMPLE_STRUCT
    example_struct = (
        struct.pack("<HHIII", 4, 0, TYPE_INDEX_BEGIN + 3, 0, 0)
        + _numeric(40)
        + _cstr("EXAMPLE_STRUCT")
    )
    records.append(_record(LF_STRUCTURE, example_struct))

    region = b"".join(records)
    header = struct.pack(
        "<IIIII",
        20040203,  # version (impv)
        TPI_HEADER_SIZE,
        TYPE_INDEX_BEGIN,
        TYPE_INDEX_BEGIN + len(records),
        len(region),
    )
    header += b"\x00" * (TPI_HEADER_SIZE - len(header))
    return header + region


def build_tpi_pack_union() -> bytes:
    """A TPI with two tricky structs, to exercise pack inference and union rejection.

        struct PACKED4 { uint32_t A; uint64_t B; }  // B recorded @4 => #pragma pack(4)
        struct UNIONY  { uint32_t X; uint32_t Y; }   // X and Y both @0 => a union
    """
    records: list[bytes] = []

    # 0x1000: field list for PACKED4 (B at offset 4, not the natural 8)
    records.append(_record(LF_FIELDLIST, _member("A", T_UINT4, 0) + _member("B", T_UQUAD, 4)))
    # 0x1001: struct PACKED4
    records.append(
        _record(
            LF_STRUCTURE,
            struct.pack("<HHIII", 2, 0, TYPE_INDEX_BEGIN + 0, 0, 0)
            + _numeric(12)
            + _cstr("PACKED4"),
        )
    )
    # 0x1002: field list for UNIONY (X and Y both at offset 0)
    records.append(_record(LF_FIELDLIST, _member("X", T_UINT4, 0) + _member("Y", T_UINT4, 0)))
    # 0x1003: struct UNIONY
    records.append(
        _record(
            LF_STRUCTURE,
            struct.pack("<HHIII", 2, 0, TYPE_INDEX_BEGIN + 2, 0, 0)
            + _numeric(4)
            + _cstr("UNIONY"),
        )
    )

    region = b"".join(records)
    header = struct.pack(
        "<IIIII",
        20040203,
        TPI_HEADER_SIZE,
        TYPE_INDEX_BEGIN,
        TYPE_INDEX_BEGIN + len(records),
        len(region),
    )
    header += b"\x00" * (TPI_HEADER_SIZE - len(header))
    return header + region


LF_BITFIELD = 0x1205


def build_tpi_bitfield() -> bytes:
    """A TPI with one struct of three bitfields in a single u32 unit.

        struct BITS { uint32_t a:1; uint32_t b:3; uint32_t c:4; }
    """
    records: list[bytes] = []

    def bitfield(base_ti: int, length: int, position: int) -> bytes:
        return _record(LF_BITFIELD, struct.pack("<IBB", base_ti, length, position))

    records.append(bitfield(T_UINT4, 1, 0))  # 0x1000 a
    records.append(bitfield(T_UINT4, 3, 1))  # 0x1001 b
    records.append(bitfield(T_UINT4, 4, 4))  # 0x1002 c
    fieldlist = (
        _member("a", TYPE_INDEX_BEGIN + 0, 0)
        + _member("b", TYPE_INDEX_BEGIN + 1, 0)
        + _member("c", TYPE_INDEX_BEGIN + 2, 0)
    )
    records.append(_record(LF_FIELDLIST, fieldlist))  # 0x1003
    records.append(
        _record(
            LF_STRUCTURE,
            struct.pack("<HHIII", 3, 0, TYPE_INDEX_BEGIN + 3, 0, 0) + _numeric(4) + _cstr("BITS"),
        )
    )  # 0x1004

    region = b"".join(records)
    header = struct.pack(
        "<IIIII",
        20040203,
        TPI_HEADER_SIZE,
        TYPE_INDEX_BEGIN,
        TYPE_INDEX_BEGIN + len(records),
        len(region),
    )
    header += b"\x00" * (TPI_HEADER_SIZE - len(header))
    return header + region


def build_pdb_bytes(tpi: bytes | None = None) -> bytes:
    """Assemble a full MSF container with streams [old-dir, pdb-info, TPI]."""
    if tpi is None:
        tpi = build_tpi_stream()
    streams = [b"", b"", tpi]

    def nblocks(size: int) -> int:
        return -(-size // BLOCK_SIZE)

    # block 0 = superblock, blocks 1,2 = free-block maps (reserved), data starts at 3
    next_block = 3
    stream_blocks: list[list[int]] = []
    for s in streams:
        n = nblocks(len(s))
        stream_blocks.append(list(range(next_block, next_block + n)))
        next_block += n

    directory = struct.pack("<I", len(streams))
    directory += b"".join(struct.pack("<I", len(s)) for s in streams)
    for blocks in stream_blocks:
        directory += b"".join(struct.pack("<I", b) for b in blocks)

    dir_blocks = list(range(next_block, next_block + nblocks(len(directory))))
    next_block += len(dir_blocks)
    block_map_addr = next_block
    next_block += 1  # the block-map block itself
    num_blocks = next_block

    image = bytearray(num_blocks * BLOCK_SIZE)

    # superblock
    magic = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
    image[0 : len(magic)] = magic
    struct.pack_into(
        "<IIIIII",
        image,
        32,
        BLOCK_SIZE,
        1,  # free-block-map block
        num_blocks,
        len(directory),
        0,
        block_map_addr,
    )
    # mark the two FPM blocks all-free (not read by our parser, but keeps the file honest)
    for fpm in (1, 2):
        image[fpm * BLOCK_SIZE : (fpm + 1) * BLOCK_SIZE] = b"\xff" * BLOCK_SIZE

    def write_blocks(blocks: list[int], payload: bytes) -> None:
        for i, blk in enumerate(blocks):
            chunk = payload[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
            image[blk * BLOCK_SIZE : blk * BLOCK_SIZE + len(chunk)] = chunk

    for blocks, s in zip(stream_blocks, streams):
        write_blocks(blocks, s)
    write_blocks(dir_blocks, directory)

    block_map = b"".join(struct.pack("<I", b) for b in dir_blocks)
    image[block_map_addr * BLOCK_SIZE : block_map_addr * BLOCK_SIZE + len(block_map)] = block_map

    return bytes(image)
