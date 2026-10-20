"""Tests for the cross-build struct-layout diff."""

import json

from structhound import diff
from structhound.cli import main
from structhound.diff import ChangeKind
from structhound.recover.types import PRIMITIVES, Pointer, Struct

U32 = PRIMITIVES["u32"]
U64 = PRIMITIVES["u64"]


def _old():
    return {
        "EXAMPLE": Struct("EXAMPLE", [("Flags", U32), ("Handle", Pointer()), ("Count", U32)]),
        "GONE": Struct("GONE", [("X", U32)]),
    }


def _new():
    return {
        # Extra inserted -> Handle and Count shift
        "EXAMPLE": Struct(
            "EXAMPLE",
            [("Flags", U32), ("Extra", U64), ("Handle", Pointer()), ("Count", U32)],
        ),
        "FRESH": Struct("FRESH", [("Y", U32)]),
    }


def test_detects_insertion_and_shift():
    result = diff.diff_structs(_old(), _new(), "x64")
    assert [d.name for d in result.changed] == ["EXAMPLE"]
    d = result.changed[0]
    assert d.old_size == 24 and d.new_size == 32
    kinds = {c.name: c.kind for c in d.changes}
    assert kinds["Extra"] is ChangeKind.ADDED
    assert kinds["Handle"] is ChangeKind.MOVED
    assert kinds["Count"] is ChangeKind.MOVED
    moved = next(c for c in d.changes if c.name == "Handle")
    assert (moved.old_offset, moved.new_offset) == (8, 16)


def test_added_and_removed_structs():
    result = diff.diff_structs(_old(), _new(), "x64")
    assert result.added == ["FRESH"]
    assert result.removed == ["GONE"]


def test_removed_field():
    old = {"S": Struct("S", [("A", U32), ("B", U32)])}
    new = {"S": Struct("S", [("A", U32)])}
    d = diff.diff_structs(old, new, "x64").changed[0]
    removed = [c for c in d.changes if c.kind is ChangeKind.REMOVED]
    assert [c.name for c in removed] == ["B"]


def test_resized_field():
    # A field's type changed (pointer -> u32): it resizes 8 -> 4.
    old = {"S": Struct("S", [("A", U32), ("P", Pointer())])}
    new = {"S": Struct("S", [("A", U32), ("P", U32)])}
    d = diff.diff_structs(old, new, "x64").changed[0]
    change = next(c for c in d.changes if c.name == "P")
    assert change.kind in (ChangeKind.MOVED_RESIZED, ChangeKind.RESIZED)
    assert change.old_size == 8 and change.new_size == 4


def test_only_filter_scopes_to_one_struct():
    result = diff.diff_structs(_old(), _new(), "x64", only="EXAMPLE")
    assert [d.name for d in result.changed] == ["EXAMPLE"]
    assert result.added == [] and result.removed == []  # suppressed by `only`


def test_no_changes():
    result = diff.diff_structs(_old(), _old(), "x64")
    assert result.changed == [] and result.added == [] and result.removed == []


def test_to_dict_shape():
    result = diff.diff_structs(_old(), _new(), "x64")
    doc = diff.to_dict(result)
    assert doc["added"] == ["FRESH"]
    example = doc["changed"][0]
    assert example["name"] == "EXAMPLE"
    assert any(c["kind"] == "added" and c["name"] == "Extra" for c in example["changes"])


# --- CLI on the committed example build pair -----------------------------------

A = "examples/example_build_22621.json"
B = "examples/example_build_26100.json"


def test_cli_diff_console(capsys):
    assert main(["diff", "--a", A, "--b", B]) == 0
    out = capsys.readouterr().out
    assert "EXAMPLE_STRUCT" in out
    assert "size 24 -> 32" in out


def test_cli_diff_json(capsys):
    assert main(["diff", "--a", A, "--b", B, "--json", "-"]) == 0
    doc = json.loads(capsys.readouterr().out)
    names = [c["name"] for c in doc["changed"]]
    assert "EXAMPLE_STRUCT" in names
    changes = {c["name"]: c["kind"] for c in doc["changed"][0]["changes"]}
    assert changes["Extra"] == "added"
