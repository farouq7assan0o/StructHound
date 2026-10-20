"""Signature-based offset recovery.

When type information (symbols) is unavailable, field offsets can often still be
recovered by locating a stable instruction pattern in a module's code and reading the
offset out of the displacement encoded in that instruction. For example the x64 encoding
of ``mov rax, [rcx+0x10]`` is ``48 8B 81 10 00 00 00`` — the trailing little-endian
dword is the field offset ``0x10``.

This is inherently less certain than symbols, so every recovered offset carries a
confidence < 1.0 derived from:

- **agreement** — do all matches of all this field's signatures extract the same offset?
- **corroboration** — how many *distinct* signatures independently agree on the winner?

A single noisy match is weak; several independent signatures agreeing is strong (but
still never treated as certain).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

MAX_SIGNATURE_CONFIDENCE = 0.95


class SignatureError(Exception):
    """Raised when a signature spec is malformed."""


@dataclass
class BytePattern:
    """A byte pattern with ``??`` wildcards, e.g. ``"48 8B 81 ?? ?? ?? ??"``."""

    mask: bytes
    value: bytes

    @classmethod
    def parse(cls, text: str) -> "BytePattern":
        mask = bytearray()
        value = bytearray()
        for tok in text.split():
            if tok in ("??", "?"):
                mask.append(0x00)
                value.append(0x00)
            else:
                try:
                    byte = int(tok, 16)
                except ValueError:
                    raise SignatureError(f"invalid pattern token {tok!r}") from None
                if not 0 <= byte <= 0xFF:
                    raise SignatureError(f"pattern byte out of range: {tok!r}")
                mask.append(0xFF)
                value.append(byte)
        if not mask:
            raise SignatureError("empty byte pattern")
        return cls(bytes(mask), bytes(value))

    def __len__(self) -> int:
        return len(self.mask)

    def scan(self, blob: bytes) -> list[int]:
        """Return every start index in ``blob`` where the pattern matches."""
        plen = len(self.mask)
        hits: list[int] = []
        for i in range(0, len(blob) - plen + 1):
            if all((blob[i + j] & self.mask[j]) == self.value[j] for j in range(plen)):
                hits.append(i)
        return hits


@dataclass
class FieldSignature:
    """One way to locate a field's offset in code."""

    pattern: BytePattern
    disp_at: int  # byte offset of the displacement within a match
    disp_size: int  # 1, 2, or 4
    signed: bool = False

    def extract(self, blob: bytes, match_pos: int) -> int:
        start = match_pos + self.disp_at
        raw = blob[start : start + self.disp_size]
        if len(raw) != self.disp_size:
            raise SignatureError("displacement runs past end of code blob")
        return int.from_bytes(raw, "little", signed=self.signed)


@dataclass
class RecoveredField:
    name: str
    offset: int
    confidence: float
    detail: str


@dataclass
class StructSignatureSet:
    """Signatures for the fields of one or more structs in a module."""

    module: str
    arch: str
    # struct name -> field name -> list of signatures
    structs: dict[str, dict[str, list[FieldSignature]]] = field(default_factory=dict)

    def fields_for(self, struct: str) -> dict[str, list[FieldSignature]]:
        if struct not in self.structs:
            raise SignatureError(f"no signatures for struct {struct!r}")
        return self.structs[struct]


def score(total_matches: int, winner_votes: int, distinct_sigs_agreeing: int) -> float:
    """Confidence for a recovered offset. See module docstring for the rationale."""
    if total_matches == 0:
        return 0.0
    agreement = winner_votes / total_matches
    conf = 0.5 * agreement + 0.15 * min(distinct_sigs_agreeing, 3)
    return round(min(conf, MAX_SIGNATURE_CONFIDENCE), 2)


def recover_field(
    blob: bytes, field_name: str, sigs: list[FieldSignature]
) -> RecoveredField | None:
    """Recover one field's offset from all its signatures, or ``None`` if unmatched."""
    # (offset_value) -> set of signature indices that produced it
    by_offset: dict[int, set[int]] = {}
    all_votes: Counter[int] = Counter()
    for sig_idx, sig in enumerate(sigs):
        for pos in sig.pattern.scan(blob):
            off = sig.extract(blob, pos)
            all_votes[off] += 1
            by_offset.setdefault(off, set()).add(sig_idx)

    total = sum(all_votes.values())
    if total == 0:
        return None

    winner, winner_votes = all_votes.most_common(1)[0]
    distinct = len(by_offset[winner])
    confidence = score(total, winner_votes, distinct)

    if len(all_votes) > 1:
        others = {o: v for o, v in all_votes.items() if o != winner}
        detail = (
            f"{distinct} signature(s) agree on {winner:#x}; "
            f"conflicting candidates {others}"
        )
    else:
        detail = f"{distinct} signature(s) agree on {winner:#x} ({total} match(es))"

    return RecoveredField(field_name, winner, confidence, detail)


def recover_struct(
    blob: bytes, field_sigs: dict[str, list[FieldSignature]]
) -> tuple[dict[str, RecoveredField], list[str]]:
    """Recover all fields. Returns (resolved, unresolved_field_names)."""
    resolved: dict[str, RecoveredField] = {}
    unresolved: list[str] = []
    for name, sigs in field_sigs.items():
        rf = recover_field(blob, name, sigs)
        if rf is None:
            unresolved.append(name)
        else:
            resolved[name] = rf
    return resolved, unresolved


def _field_sig_from_spec(spec: dict) -> FieldSignature:
    try:
        return FieldSignature(
            pattern=BytePattern.parse(spec["pattern"]),
            disp_at=int(spec["disp_at"]),
            disp_size=int(spec["disp_size"]),
            signed=bool(spec.get("signed", False)),
        )
    except KeyError as exc:
        raise SignatureError(f"signature missing field {exc}") from None


def signatureset_from_doc(doc: dict) -> StructSignatureSet:
    structs: dict[str, dict[str, list[FieldSignature]]] = {}
    for sname, sdef in doc.get("structs", {}).items():
        fields: dict[str, list[FieldSignature]] = {}
        for fname, specs in sdef.get("fields", {}).items():
            fields[fname] = [_field_sig_from_spec(s) for s in specs]
        structs[sname] = fields
    return StructSignatureSet(
        module=doc.get("module", "<unknown>"),
        arch=doc.get("arch", "x64"),
        structs=structs,
    )
