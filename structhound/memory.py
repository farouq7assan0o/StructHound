"""Read typed struct instances out of a captured memory image.

This closes the loop: once StructHound has a correct, build-resilient layout for a struct,
it can read an instance of that struct straight out of a dump's memory and present each
field as a typed value — the forensic equivalent of WinDbg's ``dt type address``.

It reads whatever struct you point it at, at an address you supply, from an artifact you
are authorized to analyze. It is a structural reader: fields are decoded by size (1/2/4/8
-> integer, anything else -> raw bytes), which is all the layout records.
"""

from __future__ import annotations

from dataclasses import dataclass

from structhound.artifacts.minidump import MemoryRange
from structhound.recover.types import StructLayout


class MemoryError_(Exception):
    """Raised when an address is not present in the captured memory."""


@dataclass
class FieldValue:
    name: str
    offset: int
    size: int
    value: int | None  # integer value for 1/2/4/8-byte fields, else None
    hex: str


class MemoryReader:
    """Maps virtual addresses to dump bytes and reads struct instances."""

    def __init__(self, data: bytes, ranges: list[MemoryRange]):
        self._data = data
        self._ranges = sorted(ranges, key=lambda r: r.va)

    def read(self, va: int, n: int) -> bytes:
        """Read ``n`` bytes at virtual address ``va`` (must be within one range)."""
        for r in self._ranges:
            if r.va <= va and va + n <= r.va + r.size:
                start = r.file_offset + (va - r.va)
                chunk = self._data[start : start + n]
                if len(chunk) != n:
                    raise MemoryError_(f"range for {va:#x} is truncated in the dump file")
                return chunk
        raise MemoryError_(f"address {va:#x} (+{n}) is not captured in this dump")

    def read_struct(self, layout: StructLayout, va: int) -> list[FieldValue]:
        """Read every field of ``layout`` at ``va`` and return typed values."""
        span = layout.total_size or max(
            (f.offset + f.size for f in layout.fields.values()), default=0
        )
        buf = self.read(va, span)
        out: list[FieldValue] = []
        for f in layout.fields.values():
            raw = buf[f.offset : f.offset + f.size]
            value = int.from_bytes(raw, "little") if f.size in (1, 2, 4, 8) else None
            preview = raw[:16].hex() + ("..." if len(raw) > 16 else "")
            hexstr = ("0x" + preview) if preview else ""
            out.append(FieldValue(f.name, f.offset, f.size, value, hexstr))
        return out
