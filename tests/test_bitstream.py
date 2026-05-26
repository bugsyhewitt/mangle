"""Unit tests for the HEVC bitstream primitives."""

from __future__ import annotations

from mangle.bitstream import (
    BitReader,
    BitWriter,
    NalUnit,
    assemble_nal_units,
    ebsp_to_rbsp,
    rbsp_to_ebsp,
    split_nal_units,
)


class TestExpGolomb:
    def test_ue_zero(self):
        # ue(0) is encoded as a single '1' bit.
        assert BitReader(b"\x80").read_ue() == 0

    def test_ue_roundtrip(self):
        for value in [0, 1, 2, 3, 7, 8, 100, 1023, 65535]:
            w = BitWriter()
            w.write_ue(value)
            assert BitReader(w.to_bytes()).read_ue() == value

    def test_se_roundtrip(self):
        for value in [0, 1, -1, 2, -2, 50, -50, 1000, -1000]:
            w = BitWriter()
            w.write_se(value)
            assert BitReader(w.to_bytes()).read_se() == value

    def test_fixed_bits_roundtrip(self):
        w = BitWriter()
        w.write_bits(0b10110, 5)
        w.write_bits(0b011, 3)
        data = w.to_bytes()
        r = BitReader(data)
        assert r.read_bits(5) == 0b10110
        assert r.read_bits(3) == 0b011


class TestEmulationPrevention:
    def test_ebsp_to_rbsp_strips_03(self):
        # 00 00 03 01 -> 00 00 01 (the 03 is removed)
        assert ebsp_to_rbsp(b"\x00\x00\x03\x01") == b"\x00\x00\x01"

    def test_ebsp_to_rbsp_preserves_normal_03(self):
        # 00 01 03 00 has no 00 00 03 sequence -> unchanged
        assert ebsp_to_rbsp(b"\x00\x01\x03\x00") == b"\x00\x01\x03\x00"

    def test_rbsp_to_ebsp_inserts_03(self):
        assert rbsp_to_ebsp(b"\x00\x00\x01") == b"\x00\x00\x03\x01"

    def test_emulation_roundtrip(self):
        for payload in [
            b"\x00\x00\x00\x00\x00",
            b"\x00\x00\x01\x02\x03",
            b"\xff\x00\x00\x02\xab\x00\x00\x00",
            bytes(range(256)),
        ]:
            assert ebsp_to_rbsp(rbsp_to_ebsp(payload)) == payload


class TestNalSplitting:
    def test_split_two_nals(self):
        stream = b"\x00\x00\x00\x01\x40\x01\xaa\x00\x00\x01\x42\x01\xbb"
        nals = split_nal_units(stream)
        assert len(nals) == 2
        assert nals[0].nal_unit_type == 32  # 0x40 >> 1 = 0x20 = 32 (VPS)
        assert nals[0].start_code_len == 4
        assert nals[1].nal_unit_type == 33  # 0x42 >> 1 = 0x21 = 33 (SPS)
        assert nals[1].start_code_len == 3

    def test_assemble_roundtrip(self):
        stream = b"\x00\x00\x00\x01\x40\x01\xaa\x00\x00\x01\x42\x01\xbb"
        nals = split_nal_units(stream)
        assert assemble_nal_units(nals) == stream

    def test_type_name(self):
        nal = NalUnit(start_code_len=4, offset=0, ebsp=b"\x42\x01")
        assert nal.type_name == "SPS_NUT"
        assert nal.is_vcl is False

    def test_vcl_detection(self):
        nal = NalUnit(start_code_len=4, offset=0, ebsp=b"\x26\x01")  # 0x26>>1=19 IDR
        assert nal.nal_unit_type == 19
        assert nal.is_vcl is True
