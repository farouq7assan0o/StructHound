"""Tests for the registry hive reader."""

import pytest

from structhound import artifacts
from structhound.artifacts import hive

from tests._fixtures import build_hive


def test_detect_hive():
    assert artifacts.detect(build_hive()) == "hive"


def test_parse_hive_metadata():
    h = hive.parse(build_hive())
    assert h.filename == "TESTHIVE"
    assert h.major_version == 1
    assert h.minor_version == 3
    assert h.root.name == "ROOT"
    assert h.key_count == 2  # ROOT + SUB


def test_parse_root_value_dword():
    h = hive.parse(build_hive())
    assert len(h.root.values) == 1
    val = h.root.values[0]
    assert val.name == "Val"
    assert val.type_name == "REG_DWORD"
    assert val.repr == str(0x12345678)


def test_parse_subkey_and_string_value():
    h = hive.parse(build_hive())
    assert [sk.name for sk in h.root.subkeys] == ["SUB"]
    sub = h.root.subkeys[0]
    assert sub.values[0].name == "Str"
    assert sub.values[0].type_name == "REG_SZ"
    assert sub.values[0].repr == "hello"


def test_depth_limit_truncates():
    h = hive.parse(build_hive(), max_depth=0)
    # Root parsed, but its subkeys omitted.
    assert h.root.subkeys == []
    assert h.root.truncated is True


def test_parse_rejects_bad_signature():
    with pytest.raises(hive.HiveError):
        hive.parse(b"nope" + b"\x00" * 0x2000)
