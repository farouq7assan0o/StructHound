"""Reader for the Windows registry hive (regf) format.

Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT, ...) are a core offline forensic
artifact. The on-disk format is publicly documented:

- a 4096-byte base block ("regf") with the root cell offset and hive metadata
- hive bins ("hbin") holding variable-size cells
- key nodes ("nk"), subkey lists ("lf"/"lh"/"li"/"ri"), value lists, and values ("vk")

This reader enumerates the key tree and values generically. It intentionally does not
interpret any specific hive's security-sensitive contents — it is a structural parser,
the same shape of tool as the minidump reader.

Supported enough for forensic triage of normal hives; big-data ("db") values and
transaction logs are out of scope for now (noted where encountered).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

HBIN_DATA_START = 0x1000
REGF_SIGNATURE = b"regf"

# Value data types we decode for display (others are shown as raw hex).
REG_TYPES = {
    0: "REG_NONE",
    1: "REG_SZ",
    2: "REG_EXPAND_SZ",
    3: "REG_BINARY",
    4: "REG_DWORD",
    5: "REG_DWORD_BIG_ENDIAN",
    7: "REG_MULTI_SZ",
    11: "REG_QWORD",
}


class HiveError(Exception):
    """Raised when the bytes are not a parseable regf hive."""


@dataclass
class Value:
    name: str
    type: int
    type_name: str
    data: bytes
    repr: str


@dataclass
class KeyNode:
    name: str
    values: list[Value] = field(default_factory=list)
    subkeys: list[KeyNode] = field(default_factory=list)
    truncated: bool = False  # subkeys omitted due to depth/count limits


@dataclass
class Hive:
    filename: str
    major_version: int
    minor_version: int
    root: KeyNode
    key_count: int


def is_hive(data: bytes) -> bool:
    return len(data) >= 4 and data[:4] == REGF_SIGNATURE


def _u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]


class _Reader:
    def __init__(self, data: bytes, max_depth: int, max_keys: int):
        self.data = data
        self.max_depth = max_depth
        self.max_keys = max_keys
        self.key_count = 0

    def cell(self, cell_offset: int) -> bytes:
        """Return the bytes of a cell's payload (after its 4-byte size field)."""
        pos = HBIN_DATA_START + cell_offset
        if pos + 4 > len(self.data):
            raise HiveError(f"cell offset {cell_offset:#x} out of bounds")
        (size,) = struct.unpack_from("<i", self.data, pos)
        length = abs(size)
        if length < 4 or pos + length > len(self.data):
            raise HiveError(f"bad cell size at {cell_offset:#x}")
        return self.data[pos + 4 : pos + length]

    def _decode_name(self, raw: bytes, ascii_flag: bool) -> str:
        if ascii_flag:
            return raw.decode("latin-1", errors="replace")
        return raw.decode("utf-16-le", errors="replace")

    def read_key(self, cell_offset: int, depth: int) -> KeyNode:
        self.key_count += 1
        nk = self.cell(cell_offset)
        if nk[:2] != b"nk":
            raise HiveError(f"expected nk at {cell_offset:#x}")

        flags = _u16(nk, 0x02)
        ascii_name = bool(flags & 0x0020)
        subkey_count = _u32(nk, 0x14)
        subkeys_list = _u32(nk, 0x1C)
        value_count = _u32(nk, 0x24)
        values_list = _u32(nk, 0x28)
        name_len = _u16(nk, 0x48)
        name = self._decode_name(nk[0x4C : 0x4C + name_len], ascii_name)

        node = KeyNode(name=name or "(root)")

        if value_count and values_list != 0xFFFFFFFF:
            node.values = self._read_values(values_list, value_count)

        if subkey_count and subkeys_list != 0xFFFFFFFF:
            if depth >= self.max_depth or self.key_count >= self.max_keys:
                node.truncated = True
            else:
                for off in self._subkey_offsets(subkeys_list):
                    if self.key_count >= self.max_keys:
                        node.truncated = True
                        break
                    node.subkeys.append(self.read_key(off, depth + 1))
        return node

    def _subkey_offsets(self, list_offset: int) -> list[int]:
        cell = self.cell(list_offset)
        sig = cell[:2]
        count = _u16(cell, 0x02)
        offsets: list[int] = []
        if sig in (b"lf", b"lh"):
            for i in range(count):
                offsets.append(_u32(cell, 0x04 + i * 8))
        elif sig == b"li":
            for i in range(count):
                offsets.append(_u32(cell, 0x04 + i * 4))
        elif sig == b"ri":
            for i in range(count):
                sublist = _u32(cell, 0x04 + i * 4)
                offsets.extend(self._subkey_offsets(sublist))
        else:
            raise HiveError(f"unknown subkey list signature {sig!r}")
        return offsets

    def _read_values(self, list_offset: int, count: int) -> list[Value]:
        cell = self.cell(list_offset)
        values: list[Value] = []
        for i in range(count):
            vk_off = _u32(cell, i * 4)
            if vk_off == 0xFFFFFFFF:
                continue
            values.append(self._read_value(vk_off))
        return values

    def _read_value(self, cell_offset: int) -> Value:
        vk = self.cell(cell_offset)
        if vk[:2] != b"vk":
            raise HiveError(f"expected vk at {cell_offset:#x}")
        name_len = _u16(vk, 0x02)
        data_size = _u32(vk, 0x04)
        data_offset = _u32(vk, 0x08)
        data_type = _u32(vk, 0x0C)
        flags = _u16(vk, 0x10)
        ascii_name = bool(flags & 0x0001)
        name = self._decode_name(vk[0x14 : 0x14 + name_len], ascii_name) or "(Default)"

        inline = bool(data_size & 0x80000000)
        size = data_size & 0x7FFFFFFF
        if inline:
            raw = struct.pack("<I", data_offset)[:size]
        else:
            raw = self.cell(data_offset)[:size]

        return Value(
            name=name,
            type=data_type,
            type_name=REG_TYPES.get(data_type, f"0x{data_type:x}"),
            data=raw,
            repr=_render_value(data_type, raw),
        )


def _render_value(data_type: int, raw: bytes) -> str:
    try:
        if data_type in (1, 2):  # REG_SZ / REG_EXPAND_SZ
            return raw.decode("utf-16-le", errors="replace").rstrip("\x00")
        if data_type == 4 and len(raw) >= 4:  # REG_DWORD
            return str(struct.unpack_from("<I", raw)[0])
        if data_type == 11 and len(raw) >= 8:  # REG_QWORD
            return str(struct.unpack_from("<Q", raw)[0])
        if data_type == 7:  # REG_MULTI_SZ
            text = raw.decode("utf-16-le", errors="replace").rstrip("\x00")
            return ", ".join(p for p in text.split("\x00") if p)
    except Exception:  # pragma: no cover - defensive
        pass
    hexed = raw[:16].hex()
    return f"0x{hexed}" + ("..." if len(raw) > 16 else "")


def parse(data: bytes, *, max_depth: int = 6, max_keys: int = 1000) -> Hive:
    """Parse a regf hive and return a :class:`Hive` with the enumerated key tree."""
    if len(data) < HBIN_DATA_START:
        raise HiveError("data too small to be a hive")
    if data[:4] != REGF_SIGNATURE:
        raise HiveError("bad regf signature")

    major = _u32(data, 0x14)
    minor = _u32(data, 0x18)
    root_cell = _u32(data, 0x24)
    filename = data[0x30:0x70].decode("utf-16-le", errors="replace").rstrip("\x00")

    reader = _Reader(data, max_depth=max_depth, max_keys=max_keys)
    root = reader.read_key(root_cell, depth=0)
    return Hive(
        filename=filename,
        major_version=major,
        minor_version=minor,
        root=root,
        key_count=reader.key_count,
    )
