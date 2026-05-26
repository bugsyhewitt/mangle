"""Unit tests for the HEVC parameter-set parsers and splicing helpers."""

from __future__ import annotations

from pathlib import Path

from mangle.bitstream import ebsp_to_rbsp, split_nal_units
from mangle.hevc import (
    parse_pps,
    parse_slice_header,
    parse_sps,
    splice_fixed_bits,
    splice_ue_field,
)

SEED = Path(__file__).parent / "fixtures" / "clean.h265"


def _nal_rbsp(nal_type: int) -> bytes:
    nals = split_nal_units(SEED.read_bytes())
    nal = next(n for n in nals if n.nal_unit_type == nal_type)
    return ebsp_to_rbsp(nal.ebsp[2:])


def _first_vcl_rbsp_and_type():
    nals = split_nal_units(SEED.read_bytes())
    nal = next(n for n in nals if n.is_vcl)
    return ebsp_to_rbsp(nal.ebsp[2:]), nal.nal_unit_type


class TestSpsParsing:
    def test_dimensions_match_seed(self):
        sps = parse_sps(_nal_rbsp(33))
        assert sps.pic_width_in_luma_samples == 64
        assert sps.pic_height_in_luma_samples == 64

    def test_splice_width_changes_value(self):
        rbsp = _nal_rbsp(33)
        sps = parse_sps(rbsp)
        span = sps.span("pic_width_in_luma_samples")
        new_rbsp = splice_ue_field(rbsp, span, 128)
        assert parse_sps(new_rbsp).pic_width_in_luma_samples == 128
        # height should be unchanged
        assert parse_sps(new_rbsp).pic_height_in_luma_samples == 64

    def test_splice_preserves_prefix(self):
        rbsp = _nal_rbsp(33)
        sps = parse_sps(rbsp)
        span = sps.span("pic_height_in_luma_samples")
        new_rbsp = splice_ue_field(rbsp, span, 96)
        reparsed = parse_sps(new_rbsp)
        assert reparsed.pic_width_in_luma_samples == 64
        assert reparsed.pic_height_in_luma_samples == 96


class TestSpsRpsParsing:
    def test_dpb_and_poc_fields_parsed(self):
        sps = parse_sps(_nal_rbsp(33))
        # The seed is a single intra IDR frame: it parses to the RPS region.
        assert sps.sps_max_dec_pic_buffering_minus1, "DPB sizing not parsed"
        assert sps.log2_max_pic_order_cnt_lsb_minus4 is not None
        assert sps.num_short_term_ref_pic_sets is not None
        assert sps.long_term_ref_pics_present_flag is not None

    def test_rps_field_spans_present(self):
        sps = parse_sps(_nal_rbsp(33))
        # These spans drive the RPS mutators.
        st = sps.span("num_short_term_ref_pic_sets")
        lt = sps.span("long_term_ref_pics_present_flag")
        assert st.bit_length >= 1
        assert lt.bit_length == 1
        assert lt.bit_offset > st.bit_offset


class TestPpsParsing:
    def test_tiles_flag_present(self):
        pps = parse_pps(_nal_rbsp(34))
        assert pps.tiles_enabled_flag in (0, 1)

    def test_splice_tiles_flag(self):
        rbsp = _nal_rbsp(34)
        pps = parse_pps(rbsp)
        span = pps.span("tiles_enabled_flag")
        flipped = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1 - span.value)
        assert parse_pps(flipped).tiles_enabled_flag == 1 - span.value


class TestSliceParsing:
    def test_slice_header_first_flag(self):
        rbsp, nal_type = _first_vcl_rbsp_and_type()
        sh = parse_slice_header(rbsp, nal_type)
        assert sh.first_slice_segment_in_pic_flag == 1
        assert sh.slice_pic_parameter_set_id == 0

    def test_splice_pps_id(self):
        rbsp, nal_type = _first_vcl_rbsp_and_type()
        sh = parse_slice_header(rbsp, nal_type)
        span = sh.span("slice_pic_parameter_set_id")
        new_rbsp = splice_ue_field(rbsp, span, 5)
        assert parse_slice_header(new_rbsp, nal_type).slice_pic_parameter_set_id == 5
