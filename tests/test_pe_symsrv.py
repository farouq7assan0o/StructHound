"""Tests for the PE debug-info reader and symbol-server URL building (no network)."""

import struct

import pytest

from structhound import pe, symsrv
from tests._fixtures import build_pe_with_pdb


def test_read_pdb_ref_basic():
    guid = bytes(range(16))
    data = build_pe_with_pdb(pdb_name="ntdll.pdb", guid=guid, age=1)
    ref = pe.read_pdb_ref(data)
    assert ref.pdb_name == "ntdll.pdb"
    assert ref.guid == guid
    assert ref.age == 1


def test_read_pdb_ref_strips_path():
    data = build_pe_with_pdb(pdb_name="C:\\build\\foo.pdb")
    assert pe.read_pdb_ref(data).pdb_name == "foo.pdb"


def test_signature_is_mixed_endian_guid_plus_age():
    # GUID: Data1/2/3 are little-endian; Data4 is raw; age appended as hex.
    guid = struct.pack("<IHH", 0x11223344, 0x5566, 0x7788) + bytes.fromhex("99aabbccddeeff00")
    ref = pe.PdbRef(pdb_name="x.pdb", guid=guid, age=2)
    assert ref.signature == "112233445566778899AABBCCDDEEFF002"


def test_not_a_pe():
    with pytest.raises(pe.PEError):
        pe.read_pdb_ref(b"not a pe at all")


def test_pdb_url():
    ref = pe.PdbRef(pdb_name="ntdll.pdb", guid=bytes(16), age=1)
    url = symsrv.pdb_url(ref)
    assert url.startswith("https://msdl.microsoft.com/download/symbols/ntdll.pdb/")
    assert url.endswith("/ntdll.pdb")
    assert ref.signature in url


def test_pdb_url_custom_server():
    ref = pe.PdbRef(pdb_name="a.pdb", guid=bytes(16), age=1)
    url = symsrv.pdb_url(ref, server="https://example.test/sym/")
    assert url.startswith("https://example.test/sym/a.pdb/")
