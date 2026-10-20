"""Smoke + end-to-end tests for the CLI."""

import json

from structhound.cli import build_parser, main
from tests._fixtures import build_hive, build_minidump


def test_version_flag(capsys):
    assert main(["--version"]) == 0
    assert "structhound" in capsys.readouterr().out


def test_parser_has_parse_subcommand():
    parser = build_parser()
    args = parser.parse_args(["parse", "x", "--symbols", "s", "--json", "o.json"])
    assert args.command == "parse"
    assert args.artifact == "x"
    assert args.symbols == "s"
    assert args.json == "o.json"


def test_parse_missing_file(capsys):
    assert main(["parse", "does-not-exist.dmp"]) == 2
    assert "cannot read artifact" in capsys.readouterr().err


def test_parse_unknown_format(tmp_path, capsys):
    p = tmp_path / "junk.bin"
    p.write_bytes(b"not a dump at all")
    assert main(["parse", str(p)]) == 3
    assert "unrecognized" in capsys.readouterr().err


def test_parse_minidump_console(tmp_path, capsys):
    p = tmp_path / "cap.dmp"
    p.write_bytes(build_minidump(module_name="ntdll.dll"))
    assert main(["parse", str(p)]) == 0
    out = capsys.readouterr().out
    assert "ntdll.dll" in out
    assert "Modules (1)" in out


def test_parse_minidump_json_stdout(tmp_path, capsys):
    p = tmp_path / "cap.dmp"
    p.write_bytes(build_minidump(module_name="ntdll.dll"))
    assert main(["parse", str(p), "--json", "-"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["modules"][0]["name"] == "ntdll.dll"
    assert payload["summary"]["module_count"] == 1


def test_parse_hive_console(tmp_path, capsys):
    p = tmp_path / "SOFTWARE"
    p.write_bytes(build_hive())
    assert main(["parse", str(p)]) == 0
    out = capsys.readouterr().out
    assert "[ROOT]" in out
    assert "Val (REG_DWORD)" in out
    assert "[SUB]" in out


def test_parse_hive_json(tmp_path, capsys):
    p = tmp_path / "SOFTWARE"
    p.write_bytes(build_hive())
    assert main(["parse", str(p), "--json", "-"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["artifact"]["format"] == "hive"
    reg = payload["details"]["registry"]
    assert reg["name"] == "ROOT"
    assert reg["subkeys"][0]["name"] == "SUB"


_SYMBOL_DOC = """
{
  "module": "example.dll",
  "build": "26100",
  "structs": {
    "EXAMPLE_STRUCT": {
      "fields": [
        {"name": "Flags",  "type": "u32"},
        {"name": "Extra",  "type": "u64"},
        {"name": "Handle", "type": "ptr"},
        {"name": "Count",  "type": "u32"}
      ]
    }
  }
}
"""


def test_layout_console(tmp_path, capsys):
    f = tmp_path / "syms.json"
    f.write_text(_SYMBOL_DOC)
    assert main(["layout", "EXAMPLE_STRUCT", "--symbols", str(f)]) == 0
    out = capsys.readouterr().out
    assert "EXAMPLE_STRUCT" in out
    assert "symbol" in out


def test_layout_json(tmp_path, capsys):
    f = tmp_path / "syms.json"
    f.write_text(_SYMBOL_DOC)
    assert main(["layout", "EXAMPLE_STRUCT", "--symbols", str(f), "--json", "-"]) == 0
    payload = json.loads(capsys.readouterr().out)
    offsets = {fld["name"]: fld["offset"] for fld in payload["fields"]}
    assert offsets == {"Flags": 0, "Extra": 8, "Handle": 16, "Count": 24}
    assert payload["provenance"]["method"] == "symbol"


def test_layout_unknown_struct(tmp_path, capsys):
    f = tmp_path / "syms.json"
    f.write_text(_SYMBOL_DOC)
    assert main(["layout", "NOPE", "--symbols", str(f)]) == 4
    assert "no type info" in capsys.readouterr().err


def test_layout_requires_a_mode(capsys):
    assert main(["layout", "EXAMPLE_STRUCT"]) == 2
    assert "--symbols" in capsys.readouterr().err


_SIG_DOC = """
{
  "module": "example.dll",
  "arch": "x64",
  "structs": {
    "EXAMPLE_STRUCT": {
      "fields": {
        "Handle": [{"pattern": "48 8B 81 ?? ?? ?? ??", "disp_at": 3, "disp_size": 4}]
      }
    }
  }
}
"""


def test_layout_signature_mode(tmp_path, capsys):
    sig = tmp_path / "sigs.json"
    sig.write_text(_SIG_DOC)
    code = tmp_path / "code.bin"
    # nops + mov rax,[rcx+0x10]
    code.write_bytes(b"\x90\x90\x90\x90" + bytes([0x48, 0x8B, 0x81]) + (0x10).to_bytes(4, "little"))
    argv = ["layout", "EXAMPLE_STRUCT", "--signatures", str(sig),
            "--code", str(code), "--json", "-"]
    assert main(argv) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["provenance"]["method"] == "signature"
    assert payload["provenance"]["confidence"] < 1.0
    f0 = payload["fields"][0]
    assert (f0["name"], f0["offset"], f0["size"]) == ("Handle", 16, 0)


def test_layout_signature_requires_code(tmp_path, capsys):
    sig = tmp_path / "sigs.json"
    sig.write_text(_SIG_DOC)
    assert main(["layout", "EXAMPLE_STRUCT", "--signatures", str(sig)]) == 2
    assert "requires --code" in capsys.readouterr().err
