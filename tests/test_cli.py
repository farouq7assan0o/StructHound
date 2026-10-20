"""Smoke + end-to-end tests for the CLI."""

import json

from structhound.cli import build_parser, main

from tests._fixtures import build_minidump


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
