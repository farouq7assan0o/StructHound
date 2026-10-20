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

    def walk(
        self,
        layout: StructLayout,
        va: int,
        link_field: str,
        max_nodes: int = 16,
        link_offset: int = 0,
    ) -> list[tuple[int, list[FieldValue]]]:
        """Follow ``link_field`` from node to node, reading ``layout`` at each.

        The next node's base address is ``<pointer value> - link_offset``; use a non-zero
        ``link_offset`` for embedded ``_LIST_ENTRY``-style links, where the pointer targets
        the link field inside the next node rather than the node's base (CONTAINING_RECORD).

        Stops on: a null pointer, an address already visited (cycle / circular list back to
        the head), an address not captured in the dump, or ``max_nodes``.
        """
        if link_field not in layout.fields:
            raise MemoryError_(f"no field {link_field!r} in {layout.name}")

        nodes: list[tuple[int, list[FieldValue]]] = []
        seen: set[int] = set()
        cur = va
        for _ in range(max_nodes):
            if cur == 0 or cur in seen:
                break
            try:
                fields = self.read_struct(layout, cur)
            except MemoryError_:
                break
            nodes.append((cur, fields))
            seen.add(cur)
            ptr = next((f.value for f in fields if f.name == link_field), None)
            if ptr is None:
                raise MemoryError_(f"link field {link_field!r} is not a readable pointer")
            cur = ptr - link_offset
        return nodes

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
