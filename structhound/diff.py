"""Diff a structure's layout between two builds.

This is the thesis made operational. Give StructHound two sets of type information for the
same module from different Windows builds and it reports, per structure, exactly what
changed: fields added or removed, fields that moved to a new offset, fields that changed
size, and the struct's overall size. Offsets on both sides are *recomputed from types* by
the layout engine, so the diff reflects real layout changes — the same changes that
silently break a hardcoded offset table.

Answers the question a researcher has every patch cycle: "what moved in this build?"
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from structhound.recover.types import Arch, Struct, StructLayout, arch_by_name


class ChangeKind(str, Enum):
    ADDED = "added"
    REMOVED = "removed"
    MOVED = "moved"
    RESIZED = "resized"
    MOVED_RESIZED = "moved+resized"


@dataclass
class FieldChange:
    name: str
    kind: ChangeKind
    old_offset: int | None = None
    new_offset: int | None = None
    old_size: int | None = None
    new_size: int | None = None


@dataclass
class StructDiff:
    name: str
    old_size: int
    new_size: int
    changes: list[FieldChange] = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return bool(self.changes) or self.old_size != self.new_size


@dataclass
class TypeDiff:
    changed: list[StructDiff] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)


def diff_layouts(name: str, old: StructLayout, new: StructLayout) -> StructDiff:
    """Diff one struct's layout between two builds."""
    changes: list[FieldChange] = []

    # Walk the new layout in declaration order: additions, moves, resizes.
    for fname, nf in new.fields.items():
        of = old.fields.get(fname)
        if of is None:
            changes.append(
                FieldChange(fname, ChangeKind.ADDED, new_offset=nf.offset, new_size=nf.size)
            )
            continue
        moved = of.offset != nf.offset
        resized = of.size != nf.size
        if moved and resized:
            kind = ChangeKind.MOVED_RESIZED
        elif moved:
            kind = ChangeKind.MOVED
        elif resized:
            kind = ChangeKind.RESIZED
        else:
            continue
        changes.append(
            FieldChange(fname, kind, of.offset, nf.offset, of.size, nf.size)
        )

    # Fields that existed before and are gone now.
    for fname, of in old.fields.items():
        if fname not in new.fields:
            changes.append(
                FieldChange(fname, ChangeKind.REMOVED, old_offset=of.offset, old_size=of.size)
            )

    return StructDiff(name, old.total_size, new.total_size, changes)


def diff_structs(
    old: dict[str, Struct],
    new: dict[str, Struct],
    arch: Arch | str = "x64",
    only: str | None = None,
) -> TypeDiff:
    """Diff two ``name -> Struct`` maps. ``only`` limits the diff to a single struct."""
    if isinstance(arch, str):
        arch = arch_by_name(arch)

    names_old, names_new = set(old), set(new)
    common = names_old & names_new
    if only is not None:
        common &= {only}

    result = TypeDiff()
    for name in sorted(common):
        d = diff_layouts(name, old[name].layout(arch), new[name].layout(arch))
        if d.changed:
            result.changed.append(d)

    if only is None:
        result.added = sorted(names_new - names_old)
        result.removed = sorted(names_old - names_new)
    return result


# --- rendering -----------------------------------------------------------------


def _fmt_change(c: FieldChange) -> str:
    if c.kind is ChangeKind.ADDED:
        return f"  + {c.name:<24} @{c.new_offset} (size {c.new_size}) added"
    if c.kind is ChangeKind.REMOVED:
        return f"  - {c.name:<24} was @{c.old_offset} (size {c.old_size}) removed"
    delta = (c.new_offset or 0) - (c.old_offset or 0)
    sign = f"+{delta}" if delta >= 0 else str(delta)
    detail = f"@{c.old_offset} -> @{c.new_offset} ({sign})"
    if c.kind in (ChangeKind.RESIZED, ChangeKind.MOVED_RESIZED):
        detail += f", size {c.old_size} -> {c.new_size}"
    return f"  ~ {c.name:<24} {detail}"


def render(result: TypeDiff) -> str:
    lines: list[str] = []
    lines.append(f"Changed structs: {len(result.changed)}")
    for d in result.changed:
        if d.old_size != d.new_size:
            size = f"size {d.old_size} -> {d.new_size}"
        else:
            size = f"size {d.new_size}"
        lines.append(f"\n{d.name}  ({size})")
        for c in d.changes:
            lines.append(_fmt_change(c))
    if result.added:
        lines.append(
            f"\nStructs only in new build ({len(result.added)}): " + ", ".join(result.added)
        )
    if result.removed:
        lines.append(
            f"\nStructs only in old build ({len(result.removed)}): " + ", ".join(result.removed)
        )
    return "\n".join(lines)


def to_dict(result: TypeDiff) -> dict:
    return {
        "changed": [
            {
                "name": d.name,
                "old_size": d.old_size,
                "new_size": d.new_size,
                "changes": [
                    {
                        "name": c.name,
                        "kind": c.kind.value,
                        "old_offset": c.old_offset,
                        "new_offset": c.new_offset,
                        "old_size": c.old_size,
                        "new_size": c.new_size,
                    }
                    for c in d.changes
                ],
            }
            for d in result.changed
        ],
        "added": result.added,
        "removed": result.removed,
    }
