"""Tests for the native PDB symbol backend.

Real PDBs can't be committed and CI may lack a C compiler, so the primary coverage comes from a
synthesized MSF container (see ``_pdbgen``) carrying genuine CodeView type records. The backend
reads it through the full MSF -> TPI -> types path. An optional test parses a real on-disk PDB when
one is pointed to via environment variables, and is skipped otherwise.
"""

from __future__ import annotations

import json
import os

import pytest

from structhound.cli import main
from structhound.recover import engine, pdb
from structhound.recover.symbols import SymbolError
from structhound.recover.types import X64, X86
from tests import _pdbgen

# x64 natural-alignment offsets the fixture encodes.
EXPECTED_X64 = {"Flags": 0, "Handle": 8, "Sub": 16, "Pad": 24}


# --- mapping logic, unit-tested on synthetic type records ----------------------


def test_mapper_on_synthetic_records():
    records = pdb.parse_tpi_stream(_pdbgen.build_tpi_stream())
    info = pdb._TypeMapper(records).build()
    assert set(info.structs) == {"EXAMPLE_STRUCT", "SUB"}

    example = info.structs["EXAMPLE_STRUCT"]
    layout = example.layout(X64)
    assert {f.name: f.offset for f in layout.fields.values()} == EXPECTED_X64
    assert layout.fields["Pad"].size == 16  # array uint8[16]
    assert layout.fields["Handle"].size == 8  # built-in pointer
    assert info.structs["SUB"].layout(X64).offset("Value") == 0


# --- full MSF container round-trip + the offset cross-check --------------------


def test_computed_offsets_match_recorded_offsets():
    info = pdb.parse_pdb_bytes(_pdbgen.build_pdb_bytes())
    computed = {
        f.name: f.offset
        for f in info.structs["EXAMPLE_STRUCT"].layout(X64).fields.values()
    }
    recorded = info.recorded_offsets["EXAMPLE_STRUCT"]
    # The whole point: offsets are recomputed from types, and they agree with the PDB's own.
    assert computed == recorded == EXPECTED_X64


def test_layout_recomputes_for_other_arch():
    info = pdb.parse_pdb_bytes(_pdbgen.build_pdb_bytes())
    layout = info.structs["EXAMPLE_STRUCT"].layout(X86)
    assert layout.offset("Flags") == 0
    assert layout.offset("Handle") == 4  # 4-byte pointer on x86, not 8


def test_not_a_pdb_rejected():
    with pytest.raises(SymbolError):
        pdb.parse_pdb_bytes(b"this is not an MSF container")


# --- SymbolSource + provider ---------------------------------------------------


def _write_fixture(tmp_path) -> str:
    path = tmp_path / "example.pdb"
    path.write_bytes(_pdbgen.build_pdb_bytes())
    return str(path)


def test_pdb_symbol_source(tmp_path):
    src = pdb.PdbSymbolSource(_write_fixture(tmp_path), module="example.dll", build="26100")
    struct = src.get_struct("example.dll", "26100", "EXAMPLE_STRUCT")
    assert struct.layout(X64).offset("Sub") == 16
    assert src.struct_names() == ["EXAMPLE_STRUCT", "SUB"]
    assert src.recorded_offsets("EXAMPLE_STRUCT") == EXPECTED_X64


def test_pdb_symbol_source_missing_struct(tmp_path):
    src = pdb.PdbSymbolSource(_write_fixture(tmp_path))
    with pytest.raises(SymbolError):
        src.get_struct("m", "1", "NOPE")


def test_pdb_backs_symbol_layout_provider(tmp_path):
    src = pdb.PdbSymbolSource(_write_fixture(tmp_path))
    provider = engine.SymbolLayoutProvider(src)
    resolved = provider.layout("example.dll", "26100", "EXAMPLE_STRUCT")
    assert resolved.provenance.method == engine.Method.SYMBOL
    assert resolved.layout.offset("Handle") == 8


# --- CLI ----------------------------------------------------------------------


def test_cli_layout_from_pdb(tmp_path, capsys):
    rc = main(["layout", "EXAMPLE_STRUCT", "--pdb", _write_fixture(tmp_path)])
    assert rc == 0
    out = capsys.readouterr().out
    assert "EXAMPLE_STRUCT" in out
    assert "symbol" in out


def test_cli_layout_from_pdb_json(tmp_path, capsys):
    rc = main(
        ["layout", "EXAMPLE_STRUCT", "--pdb", _write_fixture(tmp_path), "--json", "-"]
    )
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["provenance"]["method"] == "symbol"
    offsets = {f["name"]: f["offset"] for f in doc["fields"]}
    assert offsets == EXPECTED_X64


def test_cli_layout_pdb_missing_file(capsys):
    assert main(["layout", "EXAMPLE_STRUCT", "--pdb", "nope.pdb"]) == 2
    assert "cannot read PDB" in capsys.readouterr().err


def test_cli_layout_pdb_unknown_struct(tmp_path, capsys):
    rc = main(["layout", "NOPE", "--pdb", _write_fixture(tmp_path)])
    assert rc == 4


# --- optional real PDB ---------------------------------------------------------

_REAL_PDB = os.environ.get("STRUCTHOUND_TEST_PDB")
_REAL_STRUCT = os.environ.get("STRUCTHOUND_TEST_STRUCT")


@pytest.mark.skipif(
    not (_REAL_PDB and _REAL_STRUCT),
    reason="set STRUCTHOUND_TEST_PDB and STRUCTHOUND_TEST_STRUCT to a real PDB + struct name",
)
def test_real_pdb_offsets_match_recorded():
    src = pdb.PdbSymbolSource(_REAL_PDB)
    struct = src.get_struct("", "", _REAL_STRUCT)
    computed = {f.name: f.offset for f in struct.layout(X64).fields.values()}
    recorded = src.recorded_offsets(_REAL_STRUCT)
    # Every field the engine recomputes must match the offset the PDB recorded for it.
    for name, off in computed.items():
        assert off == recorded[name], f"{name}: computed {off} != recorded {recorded[name]}"
