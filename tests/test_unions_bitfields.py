"""Layout-engine tests for unions and bitfields."""

from structhound.recover.types import (
    PRIMITIVES,
    X64,
    BitField,
    Pointer,
    Struct,
    Union,
)

U16 = PRIMITIVES["u16"]
U32 = PRIMITIVES["u32"]


# --- unions --------------------------------------------------------------------

def test_union_members_share_offset_zero():
    u = Union("U", [("Status", U32), ("Pointer", Pointer())])
    layout = u.layout(X64)
    assert layout.offset("Status") == 0
    assert layout.offset("Pointer") == 0
    assert layout.total_size == 8  # max member (pointer)
    assert layout.align == 8


def test_inline_union_promoted_into_struct():
    # struct { u32 x; union { u32 Status; void* Ptr; }; void* Info; }
    inner = Union("", [("Status", U32), ("Ptr", Pointer())], inline=True)
    s = Struct("S", [("x", U32), ("u", inner), ("Info", Pointer())])
    layout = s.layout(X64)
    assert layout.offset("x") == 0
    assert layout.offset("Status") == 8  # union aligned to 8
    assert layout.offset("Ptr") == 8
    assert layout.offset("Info") == 16
    assert layout.total_size == 24


# --- bitfields -----------------------------------------------------------------

def test_bitfields_pack_into_one_unit():
    s = Struct(
        "B",
        [
            ("a", BitField(U32, 1)),
            ("b", BitField(U32, 2)),
            ("c", BitField(U32, 5)),
            ("big", U32),
        ],
    )
    layout = s.layout(X64)
    for name in ("a", "b", "c"):
        assert layout.offset(name) == 0  # same storage unit
    assert layout.fields["a"].bit_offset == 0 and layout.fields["a"].bit_width == 1
    assert layout.fields["b"].bit_offset == 1
    assert layout.fields["c"].bit_offset == 3
    assert layout.offset("big") == 4  # after the 4-byte unit
    assert layout.total_size == 8


def test_bitfield_overflow_starts_new_unit():
    s = Struct("B", [("a", BitField(U16, 12)), ("b", BitField(U16, 8))])
    layout = s.layout(X64)
    assert layout.offset("a") == 0
    assert layout.offset("b") == 2  # 12 + 8 > 16, so b lands in a new u16 unit
    assert layout.fields["b"].bit_offset == 0


def test_bitfield_base_change_starts_new_unit():
    s = Struct("B", [("a", BitField(U32, 4)), ("b", BitField(U16, 4))])
    layout = s.layout(X64)
    assert layout.offset("a") == 0
    assert layout.offset("b") == 4  # different base size -> new unit after a's u32


def test_plain_member_closes_bitfield_unit():
    s = Struct("B", [("flag", BitField(U32, 1)), ("n", U32)])
    layout = s.layout(X64)
    assert layout.offset("flag") == 0
    assert layout.offset("n") == 4


# --- reading bitfield values out of memory -------------------------------------

def test_memory_read_extracts_bitfield_values():
    import struct

    from structhound import memory
    from structhound.artifacts import minidump
    from tests._fixtures import build_minidump_with_memory

    va = 0x7FF8_0030_0000
    # one u32 unit: a(1)=1, b(3)=0b101=5, c(4)=0b1010=10  ->  1 | (5<<1) | (10<<4)
    unit = 1 | (5 << 1) | (10 << 4)
    data = build_minidump_with_memory(va, struct.pack("<I", unit))
    dump = minidump.parse(data)
    reader = memory.MemoryReader(data, dump.memory_ranges)

    layout = Struct(
        "BITS", [("a", BitField(U32, 1)), ("b", BitField(U32, 3)), ("c", BitField(U32, 4))]
    ).layout(X64)
    vals = {v.name: v.bit_value for v in reader.read_struct(layout, va)}
    assert vals == {"a": 1, "b": 5, "c": 10}


def test_layout_console_shows_bit_ranges():
    from structhound.recover.engine import Method, Provenance, ResolvedLayout
    from structhound.report import console

    layout = Struct("B", [("a", BitField(U32, 1)), ("b", BitField(U32, 3))]).layout(X64)
    text = console.render_layout(ResolvedLayout(layout, Provenance(Method.SYMBOL, 1.0, "x")))
    assert "bits 0..0" in text
    assert "bits 1..3" in text
