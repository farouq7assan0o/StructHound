"""Readers for supported offline artifact formats (authorized inputs only).

`detect` sniffs the format by magic bytes so the CLI does not have to guess from the
file extension. New formats register here as later milestones add them.
"""

from __future__ import annotations

from structhound.artifacts import hive, minidump

#: Known formats in detection order: (name, predicate).
_DETECTORS = [
    ("minidump", minidump.is_minidump),
    ("hive", hive.is_hive),
]


class UnknownArtifact(Exception):
    """Raised when no registered reader recognizes the artifact."""


def detect(data: bytes) -> str:
    """Return the format name for ``data`` or raise :class:`UnknownArtifact`."""
    for name, predicate in _DETECTORS:
        if predicate(data):
            return name
    raise UnknownArtifact("unrecognized artifact format")
