"""Fixed JSON output schema for StructHound.

The schema is versioned (``schema_version``) so downstream consumers can rely on it even
as the tool grows. Every parsed value will eventually carry provenance; the ``notes``
list is where recovery confidence and warnings surface.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from structhound import __version__
from structhound.artifacts.hive import Hive, KeyNode
from structhound.artifacts.minidump import Minidump

SCHEMA_VERSION = 1


@dataclass
class Report:
    artifact_path: str
    artifact_format: str
    artifact_size: int
    summary: dict = field(default_factory=dict)
    modules: list[dict] = field(default_factory=list)
    #: format-specific structured payload, e.g. {"registry": {...}} for hives
    details: dict = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "tool": "structhound",
            "tool_version": __version__,
            "artifact": {
                "path": self.artifact_path,
                "format": self.artifact_format,
                "size": self.artifact_size,
            },
            "summary": self.summary,
            "modules": self.modules,
            "details": self.details,
            "notes": self.notes,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


def from_minidump(path: str, size: int, dump: Minidump) -> Report:
    """Build a :class:`Report` from a parsed minidump."""
    return Report(
        artifact_path=path,
        artifact_format="minidump",
        artifact_size=size,
        summary={
            "minidump_version": dump.version,
            "stream_count": dump.stream_count,
            "timestamp": dump.timestamp,
            "flags": dump.flags,
            "module_count": len(dump.modules),
        },
        modules=[
            {
                "name": m.name,
                "base": m.base,
                "size": m.size,
                "end": m.end,
                "timestamp": m.timestamp,
                "file_version": m.file_version,
            }
            for m in dump.modules
        ],
    )


def _key_to_dict(node: KeyNode) -> dict:
    return {
        "name": node.name,
        "values": [
            {"name": v.name, "type": v.type_name, "value": v.repr} for v in node.values
        ],
        "subkeys": [_key_to_dict(sk) for sk in node.subkeys],
        "truncated": node.truncated,
    }


def from_hive(path: str, size: int, hive: Hive) -> Report:
    """Build a :class:`Report` from a parsed registry hive."""
    return Report(
        artifact_path=path,
        artifact_format="hive",
        artifact_size=size,
        summary={
            "hive_name": hive.filename,
            "version": f"{hive.major_version}.{hive.minor_version}",
            "root_key": hive.root.name,
            "keys_enumerated": hive.key_count,
        },
        details={"registry": _key_to_dict(hive.root)},
    )
