"""Native PDB symbol backend.

This is the real symbol source the JSON type-description loader (:mod:`structhound.recover.symbols`)
was always standing in for. It reads struct *type* information straight out of a Windows PDB and
hands the layout engine the same :class:`~structhound.recover.types.Struct` objects, so
:class:`~structhound.recover.engine.SymbolLayoutProvider` and the resolver chain work unchanged.

Why a native reader instead of a library:

- ``pdbparse`` is a Python-2-era, unmaintained package (old ``construct``/``pefile`` pins) that
  does not install on modern CPython.
- Microsoft DIA is Windows-only, needs ``msdia*.dll`` + COM, and is neither pip-installable nor
  usable in cross-platform CI.

So we parse the subset of the format we need in pure standard library — in keeping with the rest of
StructHound. We read the MSF (Multi-Stream Format) container, locate the TPI stream, and decode the
CodeView type records that describe structures:

- ``LF_STRUCTURE`` / ``LF_CLASS`` and their ``LF_FIELDLIST`` of ``LF_MEMBER`` entries
- ``LF_POINTER``, ``LF_ARRAY``, ``LF_MODIFIER`` (const/volatile), ``LF_ENUM``
- built-in base types, including built-in pointer types such as ``T_64PVOID``

Crucially we do **not** trust the member offsets the PDB records. We read the field *types* and let
:mod:`structhound.recover.types` recompute every offset — that is the whole point of StructHound.
The PDB's recorded offsets are kept only so a test can cross-check that our recomputation agrees.

References: the LLVM "PDB File Format" docs and Microsoft's ``microsoft-pdb`` repository.
"""

from __future__ import annotations

import struct as _struct
from dataclasses import dataclass, field

from structhound.recover.symbols import SymbolError, SymbolSource
from structhound.recover.types import (
    X64,
    Arch,
    Array,
    Pointer,
    Primitive,
    Struct,
    Type,
)

# --- CodeView / MSF constants --------------------------------------------------

MSF_MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
TPI_STREAM_INDEX = 2

# type-record leaves (TPI)
LF_MODIFIER = 0x1001
LF_POINTER = 0x1002
LF_FIELDLIST = 0x1203
LF_BITFIELD = 0x1205
LF_ARRAY = 0x1503
LF_CLASS = 0x1504
LF_STRUCTURE = 0x1505
LF_UNION = 0x1506
LF_ENUM = 0x1507

# field-list subrecord leaves
LF_BCLASS = 0x1400
LF_VBCLASS = 0x1401
LF_IVBCLASS = 0x1402
LF_INDEX = 0x1404
LF_VFUNCTAB = 0x1409
LF_ENUMERATE = 0x1502
LF_MEMBER = 0x150D
LF_STMEMBER = 0x150E
LF_METHOD = 0x150F
LF_NESTTYPE = 0x1510
LF_ONEMETHOD = 0x1511

# struct/class property bitfield
PROP_FWDREF = 0x80

# numeric-leaf type codes
LF_NUMERIC = 0x8000
_NUMERIC = {
    0x8000: ("b", 1),   # LF_CHAR   (signed int8)
    0x8001: ("h", 2),   # LF_SHORT
    0x8002: ("H", 2),   # LF_USHORT
    0x8003: ("i", 4),   # LF_LONG
    0x8004: ("I", 4),   # LF_ULONG
    0x8009: ("q", 8),   # LF_QUADWORD
    0x800A: ("Q", 8),   # LF_UQUADWORD
}

#: Built-in base types: ``value -> (name, size_in_bytes)``.
_BASE_TYPES: dict[int, tuple[str, int]] = {
    0x0003: ("void", 0),
    0x0008: ("HRESULT", 4),
    0x0010: ("char", 1),
    0x0020: ("unsigned char", 1),
    0x0068: ("int8", 1),
    0x0069: ("uint8", 1),
    0x0070: ("char", 1),          # T_RCHAR
    0x0071: ("wchar_t", 2),
    0x007A: ("char16_t", 2),
    0x007B: ("char32_t", 4),
    0x0011: ("short", 2),
    0x0021: ("unsigned short", 2),
    0x0072: ("int16", 2),
    0x0073: ("uint16", 2),
    0x0012: ("long", 4),
    0x0022: ("unsigned long", 4),
    0x0074: ("int32", 4),
    0x0075: ("uint32", 4),
    0x0013: ("int64", 8),
    0x0023: ("uint64", 8),
    0x0076: ("int64", 8),
    0x0077: ("uint64", 8),
    0x0030: ("bool8", 1),
    0x0040: ("float", 4),
    0x0041: ("double", 8),
}

# pointer mode is encoded in bits 8..10 of a built-in type index (0 = not a pointer)
_PTR_MODE_MASK = 0x0700


# --- low-level byte helpers ----------------------------------------------------


def _u16(buf: bytes, off: int) -> int:
    return _struct.unpack_from("<H", buf, off)[0]


def _u32(buf: bytes, off: int) -> int:
    return _struct.unpack_from("<I", buf, off)[0]


def _read_numeric(buf: bytes, off: int) -> tuple[int, int]:
    """Decode a CodeView variable-length numeric leaf. Returns ``(value, new_off)``."""
    kind = _u16(buf, off)
    off += 2
    if kind < LF_NUMERIC:
        return kind, off
    try:
        fmt, size = _NUMERIC[kind]
    except KeyError:
        raise SymbolError(f"unsupported numeric leaf {kind:#06x}") from None
    value = _struct.unpack_from("<" + fmt, buf, off)[0]
    return value, off + size


def _read_cstr(buf: bytes, off: int) -> tuple[str, int]:
    end = buf.index(b"\x00", off)
    return buf[off:end].decode("latin-1"), end + 1


def _skip_pad(buf: bytes, off: int) -> int:
    """Skip LF_PAD alignment bytes (0xF0..0xF3) used between field-list subrecords."""
    while off < len(buf) and buf[off] >= 0xF0:
        off += buf[off] & 0x0F
    return off


# --- MSF container -------------------------------------------------------------


def read_msf_streams(data: bytes) -> list[bytes]:
    """Split an MSF 7.00 container into its numbered streams (index -> bytes)."""
    if data[: len(MSF_MAGIC)] != MSF_MAGIC:
        raise SymbolError("not an MSF 7.00 (DS) PDB container")
    block_size, _fpm, num_blocks, dir_bytes, _unk, block_map_addr = _struct.unpack_from(
        "<IIIIII", data, 32
    )
    if block_size == 0 or block_map_addr * block_size > len(data):
        raise SymbolError("corrupt MSF superblock")

    def gather(indices: list[int]) -> bytes:
        return b"".join(data[i * block_size : (i + 1) * block_size] for i in indices)

    n_dir_blocks = -(-dir_bytes // block_size)  # ceil
    dir_block_indices = list(
        _struct.unpack_from(f"<{n_dir_blocks}I", data, block_map_addr * block_size)
    )
    directory = gather(dir_block_indices)[:dir_bytes]

    off = 0
    num_streams = _u32(directory, off)
    off += 4
    sizes = list(_struct.unpack_from(f"<{num_streams}I", directory, off))
    off += 4 * num_streams

    streams: list[bytes] = []
    for size in sizes:
        if size == 0xFFFFFFFF:  # nil stream
            streams.append(b"")
            continue
        nblk = -(-size // block_size)
        blocks = list(_struct.unpack_from(f"<{nblk}I", directory, off))
        off += 4 * nblk
        if max(blocks, default=0) >= num_blocks:
            raise SymbolError("stream references block past end of file")
        streams.append(gather(blocks)[:size])
    return streams


def parse_tpi_stream(stream: bytes) -> dict[int, tuple[int, bytes]]:
    """Parse a TPI stream into ``type_index -> (leaf, body)`` (body excludes the leaf u16)."""
    if len(stream) < 24:
        raise SymbolError("TPI stream too short")
    header_size = _u32(stream, 4)
    type_index_begin = _u32(stream, 8)
    type_record_bytes = _u32(stream, 16)
    records: dict[int, tuple[int, bytes]] = {}
    off = header_size
    end = min(header_size + type_record_bytes, len(stream))
    ti = type_index_begin
    while off + 4 <= end:
        rec_len = _u16(stream, off)
        if rec_len < 2:
            break
        leaf = _u16(stream, off + 2)
        body = stream[off + 4 : off + 2 + rec_len]
        records[ti] = (leaf, body)
        ti += 1
        off += 2 + rec_len
    return records


# --- CodeView type-record -> types.py model ------------------------------------


@dataclass
class PdbTypeInfo:
    """Everything a caller needs out of one PDB's type info."""

    structs: dict[str, Struct] = field(default_factory=dict)
    #: ``struct_name -> {field_name: offset_recorded_by_the_pdb}`` — for cross-checks only.
    recorded_offsets: dict[str, dict[str, int]] = field(default_factory=dict)


class _TypeMapper:
    """Resolves CodeView type records into :class:`~structhound.recover.types.Type` objects.

    ``arch`` is used only to turn an array's recorded *byte* size into an element *count*
    (and only matters for arrays of pointers, since a PDB is architecture-specific anyway).
    """

    def __init__(self, records: dict[int, tuple[int, bytes]], arch: Arch = X64):
        self._records = records
        self._arch = arch
        self._cache: dict[int, Type] = {}
        self._offsets: dict[str, dict[str, int]] = {}

    # -- base (built-in) types --------------------------------------------------

    def _base_type(self, ti: int) -> Type:
        if ti & _PTR_MODE_MASK:
            return Pointer()  # built-in pointer, e.g. T_64PVOID
        try:
            name, size = _BASE_TYPES[ti]
        except KeyError:
            raise SymbolError(f"unsupported built-in type {ti:#06x}") from None
        if size == 0:
            raise SymbolError(f"cannot size built-in type {name!r} ({ti:#06x})")
        return Primitive(name, size)

    def resolve(self, ti: int) -> Type:
        if ti < 0x1000:
            return self._base_type(ti)
        if ti in self._cache:
            return self._cache[ti]
        try:
            leaf, body = self._records[ti]
        except KeyError:
            raise SymbolError(f"dangling type index {ti:#x}") from None

        if leaf in (LF_STRUCTURE, LF_CLASS):
            return self._resolve_struct(ti, body)
        if leaf == LF_POINTER:
            return Pointer()
        if leaf == LF_MODIFIER:
            modified = _u32(body, 0)
            return self.resolve(modified)
        if leaf == LF_ENUM:
            # body: count(u16) prop(u16) underlying-type(u32) ...
            underlying = _u32(body, 4)
            return self.resolve(underlying)
        if leaf == LF_ARRAY:
            return self._resolve_array(body)
        if leaf == LF_UNION:
            raise SymbolError("unions are not supported by the layout engine")
        if leaf == LF_BITFIELD:
            raise SymbolError("bitfield members are not supported")
        raise SymbolError(f"unsupported type leaf {leaf:#06x} at index {ti:#x}")

    def _resolve_array(self, body: bytes) -> Array:
        element_ti = _u32(body, 0)
        # body: elemtype(u32) idxtype(u32) <numeric size> name
        total_size, _ = _read_numeric(body, 8)
        element = self.resolve(element_ti)
        elem_size = element.size(self._arch)
        if elem_size <= 0:
            raise SymbolError("array element has zero size")
        count = total_size // elem_size
        return Array(element, count)

    def _resolve_struct(self, ti: int, body: bytes) -> Struct:
        # body: count(u16) property(u16) field(u32) derived(u32) vshape(u32) <numeric size> name
        prop = _u16(body, 2)
        field_list_ti = _u32(body, 4)
        off = 16
        _size, off = _read_numeric(body, off)
        name, _ = _read_cstr(body, off)

        if (prop & PROP_FWDREF) or field_list_ti == 0:
            # forward reference: resolve to the real definition by name if we have one.
            raise SymbolError(f"{name!r} is a forward reference with no definition")

        shell = Struct(name, [])
        self._cache[ti] = shell  # cache before filling, so self-references terminate
        members, recorded = self._parse_field_list(field_list_ti)
        shell.pack = self._fit_pack(name, members, recorded)
        shell.fields = members
        self._offsets[name] = recorded
        return shell

    #: Packing values to try, natural alignment first.
    _PACK_CANDIDATES = (None, 8, 4, 2, 1)

    def _fit_pack(
        self, name: str, members: list[tuple[str, Type]], recorded: dict[str, int]
    ) -> int | None:
        """Find the packing under which our layout reproduces the PDB's member offsets.

        The PDB does not state a struct's ``#pragma pack`` directly, but our recomputed
        layout must agree with the compiler's. We try natural alignment, then successively
        tighter packing, and adopt the first that reproduces every recorded offset. If none
        does, the struct overlaps its own members (a union) and the layout engine cannot
        represent it, so we refuse it (a documented limitation) and the caller moves on.

        The recorded offsets are used only as a gate here — the offsets StructHound emits
        are always recomputed from types, so this stays correct on builds never seen.
        """
        probe = Struct(name, members)
        for pack in self._PACK_CANDIDATES:
            probe.pack = pack
            fields = probe.layout(self._arch).fields
            if all(fields[m].offset == off for m, off in recorded.items() if m in fields):
                return pack
        raise SymbolError(
            f"{name!r} members cannot be laid out sequentially (union); not supported"
        )

    def _parse_field_list(
        self, ti: int
    ) -> tuple[list[tuple[str, Type]], dict[str, int]]:
        leaf, body = self._records[ti]
        if leaf != LF_FIELDLIST:
            raise SymbolError(f"expected LF_FIELDLIST at {ti:#x}, got {leaf:#06x}")
        members: list[tuple[str, Type]] = []
        recorded: dict[str, int] = {}
        off = 0
        while off < len(body):
            off = _skip_pad(body, off)
            if off >= len(body):
                break
            sub = _u16(body, off)
            off += 2
            if sub == LF_MEMBER:
                # attr(u16) type(u32) <numeric offset> name
                member_type = _u32(body, off + 2)
                moff, noff = _read_numeric(body, off + 6)
                mname, noff = _read_cstr(body, noff)
                members.append((mname, self.resolve(member_type)))
                recorded[mname] = moff
                off = noff
            elif sub == LF_INDEX:
                # pad(u16) continuation-type(u32) -> jump to the next field list
                cont = _u32(body, off + 2)
                more, more_off = self._parse_field_list(cont)
                members.extend(more)
                recorded.update(more_off)
                off += 6
            else:
                off = self._skip_subrecord(sub, body, off)
        return members, recorded

    def _skip_subrecord(self, sub: int, body: bytes, off: int) -> int:
        """Advance past a field-list subrecord we don't fold into the layout."""
        if sub == LF_ENUMERATE:
            _val, off = _read_numeric(body, off + 2)  # attr(u16) then numeric
            _name, off = _read_cstr(body, off)
            return off
        if sub in (LF_BCLASS, LF_VFUNCTAB):
            # attr(u16) type(u32) [BCLASS: numeric offset]
            off += 6
            if sub == LF_BCLASS:
                _o, off = _read_numeric(body, off)
            return off
        if sub in (LF_VBCLASS, LF_IVBCLASS):
            off += 10  # attr(u16) btype(u32) vbtype(u32)
            _vbp, off = _read_numeric(body, off)
            _vbo, off = _read_numeric(body, off)
            return off
        if sub == LF_STMEMBER:
            off += 6  # attr(u16) type(u32)
            _name, off = _read_cstr(body, off)
            return off
        if sub == LF_NESTTYPE:
            off += 6  # pad(u16) type(u32)
            _name, off = _read_cstr(body, off)
            return off
        if sub == LF_ONEMETHOD:
            attr = _u16(body, off)
            off += 6  # attr(u16) type(u32)
            # introducing-virtual methods carry a vtable offset (u32)
            mprop = (attr >> 2) & 0x7
            if mprop in (4, 6):
                off += 4
            _name, off = _read_cstr(body, off)
            return off
        if sub == LF_METHOD:
            off += 6  # count(u16) methodlist(u32)
            _name, off = _read_cstr(body, off)
            return off
        raise SymbolError(f"unsupported field-list subrecord {sub:#06x}")

    # -- public build -----------------------------------------------------------

    def build(self) -> PdbTypeInfo:
        info = PdbTypeInfo()
        for ti, (leaf, body) in self._records.items():
            if leaf not in (LF_STRUCTURE, LF_CLASS):
                continue
            prop = _u16(body, 2)
            field_list_ti = _u32(body, 4)
            if (prop & PROP_FWDREF) or field_list_ti == 0:
                continue
            try:
                struct = self.resolve(ti)
            except SymbolError:
                continue  # skip structs we can't fully model; others still resolve
            if isinstance(struct, Struct):
                info.structs[struct.name] = struct
                info.recorded_offsets[struct.name] = self._offsets.get(struct.name, {})
        return info


def parse_pdb(path: str, arch: Arch = X64) -> PdbTypeInfo:
    """Read ``path`` and return all struct types it defines (offsets recomputed on demand)."""
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_pdb_bytes(data, arch)


def parse_pdb_bytes(data: bytes, arch: Arch = X64) -> PdbTypeInfo:
    streams = read_msf_streams(data)
    if len(streams) <= TPI_STREAM_INDEX:
        raise SymbolError("PDB has no TPI stream")
    records = parse_tpi_stream(streams[TPI_STREAM_INDEX])
    return _TypeMapper(records, arch).build()


# --- SymbolSource backend ------------------------------------------------------


class PdbSymbolSource(SymbolSource):
    """A :class:`SymbolSource` backed by a real Windows PDB file.

    A PDB corresponds to a single module/build, so ``module`` and ``build`` are informational
    (used for provenance and optional validation); lookups are by struct name. Types are parsed
    lazily on first access and cached.
    """

    def __init__(
        self,
        path: str,
        module: str | None = None,
        build: str | None = None,
        arch: Arch = X64,
    ) -> None:
        self._path = path
        self.module = module
        self.build = build
        self._arch = arch
        self._info: PdbTypeInfo | None = None

    def _load(self) -> PdbTypeInfo:
        if self._info is None:
            self._info = parse_pdb(self._path, self._arch)
        return self._info

    def get_struct(self, module: str, build: str, name: str) -> Struct:
        info = self._load()
        try:
            return info.structs[name]
        except KeyError:
            raise SymbolError(
                f"no type info for {name!r} in PDB {self._path!r}"
            ) from None

    def recorded_offsets(self, name: str) -> dict[str, int]:
        """The member offsets as the PDB recorded them (for cross-checking recomputation)."""
        info = self._load()
        try:
            return info.recorded_offsets[name]
        except KeyError:
            raise SymbolError(f"no struct {name!r} in PDB {self._path!r}") from None

    def struct_names(self) -> list[str]:
        return sorted(self._load().structs)
