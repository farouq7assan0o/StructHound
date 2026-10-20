"""Generalization: the engine handles a second, more complex struct and both arches.

If offsets were special-cased to the first example, a different struct with a nested
struct, an array, and architecture-dependent pointers would expose it. Expected offsets
below are worked out by hand from the natural-alignment rules.
"""

import json
import os

from structhound.recover import engine, signatures, symbols
from structhound.recover.signatures import BytePattern, FieldSignature

EXAMPLE = os.path.join(os.path.dirname(__file__), "..", "examples", "example2_struct.json")
MODULE = "example2.dll"
BUILD = "26100"
STRUCT = "COMPLEX_NODE"


def _provider():
    with open(EXAMPLE, encoding="utf-8") as fh:
        doc = json.load(fh)
    return engine.SymbolLayoutProvider(symbols.source_from_doc(doc))


def test_complex_struct_x64():
    layout = _provider().layout(MODULE, BUILD, STRUCT, "x64").layout
    assert layout.offset("Tag") == 0
    assert layout.offset("Count") == 4  # u32 aligned up from 2
    assert layout.offset("Link") == 8  # ptr (8) aligned
    assert layout.offset("Header") == 16  # SUBHDR (align 4) after 8-byte ptr
    assert layout.offset("Data") == 24  # after 8-byte SUBHDR
    assert layout.total_size == 32
    assert layout.align == 8


def test_complex_struct_x86():
    layout = _provider().layout(MODULE, BUILD, STRUCT, "x86").layout
    assert layout.offset("Link") == 8  # ptr is 4 bytes here
    assert layout.offset("Header") == 12  # shifts down vs x64
    assert layout.offset("Data") == 20
    assert layout.total_size == 28
    assert layout.align == 4


def test_nested_subhdr_resolves_independently():
    layout = _provider().layout(MODULE, BUILD, "SUBHDR", "x64").layout
    assert layout.offset("Version") == 0
    assert layout.offset("Flags") == 2
    assert layout.offset("Size") == 4
    assert layout.total_size == 8


def test_signature_recovery_generalizes_to_new_struct():
    # mov rax,[rcx+0x8] referencing COMPLEX_NODE.Link at offset 8.
    code = b"\x90\x90" + bytes([0x48, 0x8B, 0x81]) + (0x08).to_bytes(4, "little")
    rf = signatures.recover_field(
        code, "Link", [FieldSignature(BytePattern.parse("48 8B 81 ?? ?? ?? ??"), 3, 4)]
    )
    assert rf.offset == 8
    assert 0.0 < rf.confidence < 1.0
