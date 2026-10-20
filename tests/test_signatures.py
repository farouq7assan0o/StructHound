"""Tests for signature-based offset recovery and confidence scoring."""

import pytest

from structhound.recover import engine, signatures
from structhound.recover.signatures import BytePattern, FieldSignature


def _mov(modrm: int, disp: int) -> bytes:
    """A fake `mov reg,[rcx+disp32]`-style instruction: 48 8B <modrm> <disp32>."""
    return bytes([0x48, 0x8B, modrm]) + disp.to_bytes(4, "little")


FILLER = b"\x90\x90\x90\x90"  # nops between instructions


# --- byte pattern --------------------------------------------------------------

def test_pattern_scan_with_wildcards():
    blob = FILLER + _mov(0x81, 0x10) + FILLER
    pat = BytePattern.parse("48 8B 81 ?? ?? ?? ??")
    hits = pat.scan(blob)
    assert hits == [len(FILLER)]


def test_pattern_rejects_bad_token():
    with pytest.raises(signatures.SignatureError):
        BytePattern.parse("48 ZZ")


def test_extract_little_endian_displacement():
    blob = _mov(0x81, 0x1234)
    sig = FieldSignature(BytePattern.parse("48 8B 81 ?? ?? ?? ??"), disp_at=3, disp_size=4)
    assert sig.extract(blob, 0) == 0x1234


# --- scoring -------------------------------------------------------------------

@pytest.mark.parametrize(
    "total,votes,sigs,expected",
    [
        (1, 1, 1, 0.65),  # single unique match
        (2, 2, 2, 0.80),  # two independent signatures agree
        (3, 3, 3, 0.95),  # capped
        (2, 1, 1, 0.40),  # conflict: two matches disagree
        (0, 0, 0, 0.00),  # no matches
    ],
)
def test_score_values(total, votes, sigs, expected):
    assert signatures.score(total, votes, sigs) == expected


# --- field recovery ------------------------------------------------------------

def test_recover_single_signature():
    blob = FILLER + _mov(0x81, 0x10) + FILLER
    sigs = [FieldSignature(BytePattern.parse("48 8B 81 ?? ?? ?? ??"), 3, 4)]
    rf = signatures.recover_field(blob, "Handle", sigs)
    assert rf.offset == 0x10
    assert rf.confidence == 0.65


def test_recover_corroborated_higher_confidence():
    # Two different instruction encodings that both reference offset 0x10.
    alt = bytes([0x4C, 0x8B, 0x81]) + (0x10).to_bytes(4, "little")
    blob = FILLER + _mov(0x81, 0x10) + FILLER + alt
    sigs = [
        FieldSignature(BytePattern.parse("48 8B 81 ?? ?? ?? ??"), 3, 4),
        FieldSignature(BytePattern.parse("4C 8B 81 ?? ?? ?? ??"), 3, 4),
    ]
    rf = signatures.recover_field(blob, "Handle", sigs)
    assert rf.offset == 0x10
    assert rf.confidence == 0.80  # higher than a lone signature


def test_recover_conflict_low_confidence():
    blob = _mov(0x81, 0x10) + FILLER + _mov(0x81, 0x20)
    sigs = [FieldSignature(BytePattern.parse("48 8B 81 ?? ?? ?? ??"), 3, 4)]
    rf = signatures.recover_field(blob, "Handle", sigs)
    assert rf.confidence == 0.40
    assert "conflicting" in rf.detail


def test_recover_struct_resolved_and_unresolved():
    blob = _mov(0x81, 0x10) + FILLER + _mov(0x89, 0x18)
    field_sigs = {
        "Handle": [FieldSignature(BytePattern.parse("48 8B 81 ?? ?? ?? ??"), 3, 4)],
        "Count": [FieldSignature(BytePattern.parse("48 8B 89 ?? ?? ?? ??"), 3, 4)],
        "Missing": [FieldSignature(BytePattern.parse("DE AD BE EF ?? ?? ?? ??"), 4, 4)],
    }
    resolved, unresolved = signatures.recover_struct(blob, field_sigs)
    assert set(resolved) == {"Handle", "Count"}
    assert unresolved == ["Missing"]
    assert resolved["Count"].offset == 0x18


# --- provider + resolver -------------------------------------------------------

def _sigset_and_code():
    doc = {
        "module": "example.dll",
        "arch": "x64",
        "structs": {
            "EXAMPLE_STRUCT": {
                "fields": {
                    "Handle": [{"pattern": "48 8B 81 ?? ?? ?? ??", "disp_at": 3, "disp_size": 4}],
                    "Count": [{"pattern": "48 8B 89 ?? ?? ?? ??", "disp_at": 3, "disp_size": 4}],
                }
            }
        },
    }
    sigset = signatures.signatureset_from_doc(doc)
    code = FILLER + _mov(0x81, 0x10) + FILLER + _mov(0x89, 0x18) + FILLER
    src = engine.DictCodeSource()
    src.register("example.dll", "99999", code)
    return sigset, src


def test_signature_provider_partial_layout():
    sigset, src = _sigset_and_code()
    provider = engine.SignatureLayoutProvider(sigset, src)
    resolved = provider.layout("example.dll", "99999", "EXAMPLE_STRUCT")
    assert resolved.provenance.method == engine.Method.SIGNATURE
    assert 0.0 < resolved.provenance.confidence < 1.0
    assert resolved.layout.offset("Handle") == 0x10
    assert resolved.layout.offset("Count") == 0x18
    assert resolved.layout.total_size == 0  # unknown from signatures


def test_signature_provider_no_match_unavailable():
    sigset, _ = _sigset_and_code()
    empty = engine.DictCodeSource()
    empty.register("example.dll", "99999", b"\x00" * 64)
    provider = engine.SignatureLayoutProvider(sigset, empty)
    with pytest.raises(engine.LayoutUnavailable):
        provider.layout("example.dll", "99999", "EXAMPLE_STRUCT")


def test_resolver_falls_through_to_signature():
    from structhound.recover import symbols

    sigset, src = _sigset_and_code()
    resolver = engine.LayoutResolver(
        [
            engine.SymbolLayoutProvider(symbols.DictSymbolSource()),  # empty
            engine.HardcodedLayoutProvider({}),  # empty
            engine.SignatureLayoutProvider(sigset, src),
        ]
    )
    resolved = resolver.resolve("example.dll", "99999", "EXAMPLE_STRUCT")
    assert resolved.provenance.method == engine.Method.SIGNATURE
    assert resolved.layout.offset("Handle") == 0x10
