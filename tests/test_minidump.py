"""Tests for the minidump reader and report schema."""

import pytest

from structhound import artifacts
from structhound.artifacts import minidump
from structhound.report import schema
from tests._fixtures import build_minidump


def test_detect_minidump():
    data = build_minidump()
    assert artifacts.detect(data) == "minidump"


def test_detect_unknown():
    with pytest.raises(artifacts.UnknownArtifact):
        artifacts.detect(b"not a dump")


def test_parse_module_fields():
    data = build_minidump(
        module_name="lsasrv.dll",
        base=0x7FF8_ABCD_0000,
        size=0x40_0000,
        version=(10, 0, 22621, 3296),
    )
    dump = minidump.parse(data)
    assert dump.stream_count == 1
    assert len(dump.modules) == 1

    m = dump.modules[0]
    assert m.name == "lsasrv.dll"
    assert m.base == 0x7FF8_ABCD_0000
    assert m.size == 0x40_0000
    assert m.end == 0x7FF8_ABCD_0000 + 0x40_0000
    assert m.file_version == "10.0.22621.3296"


def test_parse_rejects_bad_signature():
    with pytest.raises(minidump.MinidumpError):
        minidump.parse(b"XXXX" + b"\x00" * 64)


def test_report_round_trips_to_json():
    dump = minidump.parse(build_minidump(module_name="kernel32.dll"))
    report = schema.from_minidump("cap.dmp", 1024, dump)
    d = report.to_dict()

    assert d["schema_version"] == schema.SCHEMA_VERSION
    assert d["artifact"]["format"] == "minidump"
    assert d["summary"]["module_count"] == 1
    assert d["modules"][0]["name"] == "kernel32.dll"
    # JSON serialization must not raise.
    assert '"kernel32.dll"' in report.to_json()
