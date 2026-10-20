"""Smoke tests for the CLI scaffold."""

from structhound.cli import build_parser, main


def test_version_flag(capsys):
    assert main(["--version"]) == 0
    assert "structhound" in capsys.readouterr().out


def test_parse_not_implemented():
    # Scaffold: `parse` is wired but not implemented yet.
    assert main(["parse", "dummy.artifact"]) == 2


def test_parser_has_parse_subcommand():
    parser = build_parser()
    args = parser.parse_args(["parse", "x", "--symbols", "s", "--json", "o.json"])
    assert args.command == "parse"
    assert args.artifact == "x"
    assert args.symbols == "s"
    assert args.json == "o.json"
