"""Tests for the layout engine, symbol loading, and providers."""

import pytest

from structhound.recover import engine, symbols
from structhound.recover.types import (
    PRIMITIVES,
    X64,
    X86,
    Array,
    Pointer,
    Struct,
)


# --- layout engine -------------------------------------------------------------

def test_natural_alignment_and_tail_padding():
    s = Struct(
        "S",
        [
            ("flags", PRIMITIVES["u32"]),
            ("handle", Pointer()),
            ("val", PRIMITIVES["u32"]),
        ],
    )
    layout = s.layout(X64)
    assert layout.offset("flags") == 0
    assert layout.offset("handle") == 8  # aligned up from 4
    assert layout.offset("val") == 16
    assert layout.align == 8
    assert layout.total_size == 24  # 20 rounded up to 8


def test_pointer_size_depends_on_arch():
    s = Struct("S", [("a", PRIMITIVES["u32"]), ("p", Pointer())])
    assert s.layout(X64).offset("p") == 8
    assert s.layout(X86).offset("p") == 4


def test_nested_struct_offsets():
    sub = Struct("SUB", [("value", PRIMITIVES["u64"])])
    outer = Struct("OUTER", [("x", PRIMITIVES["u32"]), ("sub", sub)])
    layout = outer.layout(X64)
    assert layout.offset("x") == 0
    assert layout.offset("sub") == 8  # sub has align 8
    assert layout.total_size == 16


def test_array_size():
    s = Struct("S", [("pad", Array(PRIMITIVES["u8"], 10)), ("n", PRIMITIVES["u32"])])
    layout = s.layout(X64)
    assert layout.fields["pad"].size == 10
    assert layout.offset("n") == 12  # 10 rounded up to align 4


def test_pack_clamps_alignment():
    natural = Struct("S", [("a", PRIMITIVES["u8"]), ("b", PRIMITIVES["u32"])])
    packed = Struct("S", [("a", PRIMITIVES["u8"]), ("b", PRIMITIVES["u32"])], pack=1)
    assert natural.layout(X64).offset("b") == 4
    assert packed.layout(X64).offset("b") == 1
    assert packed.layout(X64).total_size == 5


# --- symbol loading ------------------------------------------------------------

def _doc():
    return {
        "module": "example.dll",
        "build": "26100",
        "structs": {
            "EXAMPLE_STRUCT": {
                "fields": [
                    {"name": "Flags", "type": "u32"},
                    {"name": "Extra", "type": "u64"},
                    {"name": "Handle", "type": "ptr"},
                    {"name": "Count", "type": "u32"},
                ]
            }
        },
    }


def test_symbol_source_builds_struct():
    src = symbols.source_from_doc(_doc())
    struct = src.get_struct("example.dll", "26100", "EXAMPLE_STRUCT")
    layout = struct.layout(X64)
    assert layout.offset("Extra") == 8
    assert layout.offset("Handle") == 16
    assert layout.offset("Count") == 24


def test_symbol_source_missing_raises():
    src = symbols.source_from_doc(_doc())
    with pytest.raises(symbols.SymbolError):
        src.get_struct("example.dll", "99999", "EXAMPLE_STRUCT")


def test_nested_and_array_type_specs():
    doc = {
        "module": "m",
        "build": "1",
        "structs": {
            "A": {"fields": [{"name": "v", "type": "u64"}]},
            "B": {
                "fields": [
                    {"name": "a", "type": {"struct": "A"}},
                    {"name": "pad", "type": {"array": "u8", "count": 4}},
                ]
            },
        },
    }
    src = symbols.source_from_doc(doc)
    layout = src.get_struct("m", "1", "B").layout(X64)
    assert layout.offset("a") == 0
    assert layout.offset("pad") == 8


# --- providers + the across-builds claim ---------------------------------------

def _symbol_provider():
    src = symbols.DictSymbolSource()
    # build 22621: no "Extra"
    src.register(
        "example.dll",
        "22621",
        Struct(
            "EXAMPLE_STRUCT",
            [
                ("Flags", PRIMITIVES["u32"]),
                ("Handle", Pointer()),
                ("Count", PRIMITIVES["u32"]),
            ],
        ),
    )
    # build 26100: "Extra" inserted, shifting later fields
    src.register("example.dll", "26100", symbols.source_from_doc(_doc()).get_struct(
        "example.dll", "26100", "EXAMPLE_STRUCT"
    ))
    return engine.SymbolLayoutProvider(src)


def _hardcoded_provider_only_22621():
    table = {
        ("example.dll", "EXAMPLE_STRUCT", "22621"): {
            "total_size": 24,
            "align": 8,
            "fields": {"Flags": (0, 4), "Handle": (8, 8), "Count": (16, 4)},
        }
    }
    return engine.HardcodedLayoutProvider(table)


def test_both_agree_on_known_build():
    sym = _symbol_provider().layout("example.dll", "22621", "EXAMPLE_STRUCT")
    hard = _hardcoded_provider_only_22621().layout("example.dll", "22621", "EXAMPLE_STRUCT")
    assert sym.layout.offset("Handle") == hard.layout.offset("Handle") == 8
    assert sym.layout.offset("Count") == hard.layout.offset("Count") == 16


def test_hardcoded_breaks_on_new_build_symbol_adapts():
    # Hardcoded table has no entry for 26100 -> unavailable (the real failure mode).
    with pytest.raises(engine.LayoutUnavailable):
        _hardcoded_provider_only_22621().layout("example.dll", "26100", "EXAMPLE_STRUCT")

    # Symbol provider computes the shifted offsets correctly.
    sym = _symbol_provider().layout("example.dll", "26100", "EXAMPLE_STRUCT")
    assert sym.layout.offset("Handle") == 16  # shifted from 8
    assert sym.layout.offset("Count") == 24  # shifted from 16
    assert sym.provenance.method == engine.Method.SYMBOL


def test_resolver_prefers_symbol_then_falls_back():
    resolver = engine.LayoutResolver(
        [_symbol_provider(), _hardcoded_provider_only_22621()]
    )
    # Symbol wins on 22621.
    r = resolver.resolve("example.dll", "22621", "EXAMPLE_STRUCT")
    assert r.provenance.method == engine.Method.SYMBOL
    # If symbol lacks a build, resolver falls back to hardcoded.
    resolver2 = engine.LayoutResolver(
        [engine.SymbolLayoutProvider(symbols.DictSymbolSource()),
         _hardcoded_provider_only_22621()]
    )
    r2 = resolver2.resolve("example.dll", "22621", "EXAMPLE_STRUCT")
    assert r2.provenance.method == engine.Method.HARDCODED


def test_unknown_primitive_rejected():
    doc = {"module": "m", "build": "1",
           "structs": {"S": {"fields": [{"name": "x", "type": "weird"}]}}}
    with pytest.raises(symbols.SymbolError):
        symbols.source_from_doc(doc)
