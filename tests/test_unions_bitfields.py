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
