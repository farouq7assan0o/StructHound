"""A minimal C/MSVC struct-layout engine.

This is the heart of StructHound's "works across builds" claim. Instead of storing field
*offsets* (which shift whenever a field is added, removed, or resized), we store field
*types* and compute offsets by applying standard natural-alignment rules — optionally
clamped by a struct's packing value. Recomputing from types means a layout stays correct
on a build we have never seen, as long as we can obtain its type information.

Supported type forms:

- primitives (fixed size/alignment)
- pointers (size/alignment depend on the target architecture)
- fixed-length arrays
- nested structs

Rules implemented (natural alignment, MSVC-compatible for the common cases):

- a member is placed at the next offset that is a multiple of its alignment
- a struct's alignment is the max of its members' alignments (>= 1)
- the struct's total size is rounded up to its alignment (tail padding)
- a ``pack`` value clamps every member's alignment (and the struct's) to at most ``pack``
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Arch:
    name: str
    pointer_size: int


X64 = Arch("x64", 8)
X86 = Arch("x86", 4)

_ARCHES = {a.name: a for a in (X64, X86)}


def arch_by_name(name: str) -> Arch:
    try:
        return _ARCHES[name]
    except KeyError:
        raise ValueError(f"unknown architecture {name!r}") from None


class Type:
    """Base class: a type knows its size and alignment for a given architecture."""

    def size(self, arch: Arch) -> int:  # pragma: no cover - abstract
        raise NotImplementedError

    def align(self, arch: Arch) -> int:  # pragma: no cover - abstract
        raise NotImplementedError


@dataclass(frozen=True)
class Primitive(Type):
    name: str
    _size: int

    def size(self, arch: Arch) -> int:
        return self._size

    def align(self, arch: Arch) -> int:
        return self._size


@dataclass(frozen=True)
class Pointer(Type):
    name: str = "ptr"

    def size(self, arch: Arch) -> int:
        return arch.pointer_size

    def align(self, arch: Arch) -> int:
        return arch.pointer_size


@dataclass(frozen=True)
class Array(Type):
    element: Type
    count: int

    def size(self, arch: Arch) -> int:
        return self.element.size(arch) * self.count

    def align(self, arch: Arch) -> int:
        return self.element.align(arch)


#: Built-in primitive aliases usable from the symbol/type DSL.
PRIMITIVES: dict[str, Primitive] = {
    "u8": Primitive("u8", 1),
    "i8": Primitive("i8", 1),
    "u16": Primitive("u16", 2),
    "i16": Primitive("i16", 2),
    "u32": Primitive("u32", 4),
    "i32": Primitive("i32", 4),
    "u64": Primitive("u64", 8),
    "i64": Primitive("i64", 8),
}


@dataclass(frozen=True)
class FieldInfo:
    name: str
    offset: int
    size: int


@dataclass
class StructLayout:
    name: str
    arch: str
    total_size: int
    align: int
    fields: dict[str, FieldInfo]

    def offset(self, field_name: str) -> int:
        return self.fields[field_name].offset


def _round_up(value: int, multiple: int) -> int:
    if multiple <= 1:
        return value
    rem = value % multiple
    return value if rem == 0 else value + (multiple - rem)


class Struct(Type):
    """An ordered set of named fields. ``pack`` clamps member alignment if set."""

    def __init__(self, name: str, fields: list[tuple[str, Type]], pack: int | None = None):
        self.name = name
        self.fields = fields
        self.pack = pack

    def _member_align(self, t: Type, arch: Arch) -> int:
        a = t.align(arch)
        return min(a, self.pack) if self.pack else a

    def layout(self, arch: Arch) -> StructLayout:
        offset = 0
        struct_align = 1
        resolved: dict[str, FieldInfo] = {}
        for fname, ftype in self.fields:
            malign = self._member_align(ftype, arch)
            struct_align = max(struct_align, malign)
            offset = _round_up(offset, malign)
            resolved[fname] = FieldInfo(fname, offset, ftype.size(arch))
            offset += ftype.size(arch)
        total = _round_up(offset, struct_align)
        return StructLayout(self.name, arch.name, total, struct_align, resolved)

    def size(self, arch: Arch) -> int:
        return self.layout(arch).total_size

    def align(self, arch: Arch) -> int:
        return self.layout(arch).align
