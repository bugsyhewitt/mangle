"""Unit tests for the HEVC parameter-set parsers and splicing helpers."""

from __future__ import annotations

from pathlib import Path

from mangle.bitstream import BitWriter, ebsp_to_rbsp, split_nal_units
from mangle.hevc import (
    SeiMessage,
    parse_pps,
    parse_sei,
    parse_slice_header,
    parse_sps,
    splice_fixed_bits,
    splice_se_field,
    splice_ue_field,
)


def _build_pps_rbsp(
    *,
    tiles_enabled: int = 0,
    loop_filter_across: int = 1,
    ctl_present: int = 0,
    override: int = 0,
    disabled: int = 0,
    beta: int = 0,
    tc: int = 0,
    init_qp: int = 0,
    transform_skip: int = 0,
    scaling_list_present: int = 0,
    pps_extension_present: int = 0,
) -> bytes:
    """Construct a minimal but spec-shaped PPS RBSP through the deblocking block.

    Used to exercise the deblocking-region parse paths that the single-frame
    intra seed (which carries deblocking_filter_control_present_flag == 0) cannot.
    """
    w = BitWriter()
    w.write_ue(0)  # pps_pic_parameter_set_id
    w.write_ue(0)  # pps_seq_parameter_set_id
    w.write_bit(0)  # dependent_slice_segments_enabled_flag
    w.write_bit(0)  # output_flag_present_flag
    w.write_bits(0, 3)  # num_extra_slice_header_bits
    w.write_bit(0)  # sign_data_hiding_enabled_flag
    w.write_bit(0)  # cabac_init_present_flag
    w.write_ue(0)  # num_ref_idx_l0_default_active_minus1
    w.write_ue(0)  # num_ref_idx_l1_default_active_minus1
    w.write_se(init_qp)  # init_qp_minus26
    w.write_bit(0)  # constrained_intra_pred_flag
    w.write_bit(transform_skip)  # transform_skip_enabled_flag
    w.write_bit(0)  # cu_qp_delta_enabled_flag
    w.write_se(0)  # pps_cb_qp_offset
    w.write_se(0)  # pps_cr_qp_offset
    w.write_bit(0)  # pps_slice_chroma_qp_offsets_present_flag
    w.write_bit(0)  # weighted_pred_flag
    w.write_bit(0)  # weighted_bipred_flag
    w.write_bit(0)  # transquant_bypass_enabled_flag
    w.write_bit(tiles_enabled)  # tiles_enabled_flag
    w.write_bit(0)  # entropy_coding_sync_enabled_flag
    w.write_bit(loop_filter_across)  # pps_loop_filter_across_slices_enabled_flag
    w.write_bit(ctl_present)  # deblocking_filter_control_present_flag
    if ctl_present:
        w.write_bit(override)  # deblocking_filter_override_enabled_flag
        w.write_bit(disabled)  # pps_deblocking_filter_disabled_flag
        if not disabled:
            w.write_se(beta)  # pps_beta_offset_div2
            w.write_se(tc)  # pps_tc_offset_div2
    w.write_bit(scaling_list_present)  # pps_scaling_list_data_present_flag
    # When scaling_list_present is set the real scaling_list_data() body would
    # follow; the parser stops at that gate (the body is not modelled), so the
    # remaining flags below are only meaningful when the gate is off.
    w.write_bit(0)  # lists_modification_present_flag
    w.write_ue(0)  # log2_parallel_merge_level_minus2
    w.write_bit(0)  # slice_segment_header_extension_present_flag
    w.write_bit(pps_extension_present)  # pps_extension_present_flag
    w.write_bit(1)  # rbsp_stop_one_bit
    return w.to_bytes()

SEED = Path(__file__).parent / "fixtures" / "clean.h265"


def _nal_rbsp(nal_type: int) -> bytes:
    nals = split_nal_units(SEED.read_bytes())
    nal = next(n for n in nals if n.nal_unit_type == nal_type)
    return ebsp_to_rbsp(nal.ebsp[2:])


def _first_vcl_rbsp_and_type():
    nals = split_nal_units(SEED.read_bytes())
    nal = next(n for n in nals if n.is_vcl)
    return ebsp_to_rbsp(nal.ebsp[2:]), nal.nal_unit_type


SEI_FIXTURE = Path(__file__).parent / "fixtures" / "sei-buffering.hevc"


class TestParseSei:
    """Tests for parse_sei() using the synthetic sei-buffering.hevc fixture."""

    def _sei_rbsp(self) -> bytes:
        data = SEI_FIXTURE.read_bytes()
        nals = split_nal_units(data)
        sei = next(n for n in nals if n.nal_unit_type in (39, 40))
        return ebsp_to_rbsp(sei.ebsp[2:])

    def test_fixture_has_three_messages(self):
        msgs = parse_sei(self._sei_rbsp())
        assert len(msgs) == 3

    def test_payload_types(self):
        msgs = parse_sei(self._sei_rbsp())
        types = [m.payload_type for m in msgs]
        assert types == [0, 1, 6], f"expected [0, 1, 6], got {types}"

    def test_buffering_period_payload_size(self):
        msgs = parse_sei(self._sei_rbsp())
        bp = msgs[0]
        assert isinstance(bp, SeiMessage)
        assert bp.payload_size == 2  # ue(100) encodes to 2 bytes

    def test_pic_timing_payload_size(self):
        msgs = parse_sei(self._sei_rbsp())
        pt = msgs[1]
        assert pt.payload_size == 4

    def test_recovery_point_payload_size(self):
        msgs = parse_sei(self._sei_rbsp())
        rp = msgs[2]
        assert rp.payload_size == 1  # se(5) encodes to 1 byte

    def test_payload_offsets_are_within_rbsp(self):
        rbsp = self._sei_rbsp()
        msgs = parse_sei(rbsp)
        for m in msgs:
            assert m.payload_offset >= 0
            assert m.payload_offset + m.payload_size <= len(rbsp)

    def test_empty_rbsp_returns_empty_list(self):
        assert parse_sei(b"\x80") == []

    def test_trailing_byte_only_returns_empty_list(self):
        assert parse_sei(b"\x80\x00") == []

    def test_single_buffering_period_no_trailer(self):
        # Minimal: payloadType=0 (1 byte), payloadSize=1 (1 byte), payload 0xAA
        rbsp = bytes([0x00, 0x01, 0xAA])
        msgs = parse_sei(rbsp)
        assert len(msgs) == 1
        assert msgs[0].payload_type == 0
        assert msgs[0].payload_size == 1
        assert msgs[0].payload_offset == 2

    def test_high_payload_type_via_ff_prefix(self):
        # payloadType = 255 + 3 = 258, payloadSize = 0
        rbsp = bytes([0xFF, 0x03, 0x00, 0x80])
        msgs = parse_sei(rbsp)
        assert len(msgs) == 1
        assert msgs[0].payload_type == 258
        assert msgs[0].payload_size == 0


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


class TestSpsChromaBitDepthParsing:
    def test_chroma_and_separate_plane_recorded(self):
        sps = parse_sps(_nal_rbsp(33))
        # The bundled seed is 4:4:4 (idc == 3) and so carries the flag bit.
        assert sps.chroma_format_idc == 3
        assert sps.separate_colour_plane_flag == 0

    def test_bit_depth_fields_parsed(self):
        sps = parse_sps(_nal_rbsp(33))
        assert sps.bit_depth_luma_minus8 == 0
        assert sps.bit_depth_chroma_minus8 == 0

    def test_bit_depth_spans_present_and_ordered(self):
        sps = parse_sps(_nal_rbsp(33))
        chroma = sps.span("chroma_format_idc")
        bd_luma = sps.span("bit_depth_luma_minus8")
        bd_chroma = sps.span("bit_depth_chroma_minus8")
        # bit-depth fields follow the chroma/dimension block.
        assert bd_luma.bit_offset > chroma.bit_offset
        assert bd_chroma.bit_offset > bd_luma.bit_offset
        assert sps.has_span("bit_depth_luma_minus8")
        assert sps.has_span("bit_depth_chroma_minus8")

    def test_splice_bit_depth_round_trips(self):
        rbsp = _nal_rbsp(33)
        sps = parse_sps(rbsp)
        span = sps.span("bit_depth_luma_minus8")
        new_rbsp = splice_ue_field(rbsp, span, 16)
        reparsed = parse_sps(new_rbsp)
        assert reparsed.bit_depth_luma_minus8 == 16
        # chroma bit depth untouched
        assert reparsed.bit_depth_chroma_minus8 == 0


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


class TestSpsFeatureFlagParsing:
    def test_feature_flags_parsed(self):
        sps = parse_sps(_nal_rbsp(33))
        # The single intra IDR seed reaches the feature-toggle flag region; both
        # flags are off (which is what lets the parser continue to the RPS region).
        assert sps.scaling_list_enabled_flag == 0
        assert sps.pcm_enabled_flag == 0

    def test_feature_flag_spans_present_and_ordered(self):
        sps = parse_sps(_nal_rbsp(33))
        assert sps.has_span("scaling_list_enabled_flag")
        assert sps.has_span("pcm_enabled_flag")
        sl = sps.span("scaling_list_enabled_flag")
        pcm = sps.span("pcm_enabled_flag")
        assert sl.bit_length == 1
        assert pcm.bit_length == 1
        # scaling_list precedes pcm (amp / sao flags sit between them).
        assert pcm.bit_offset > sl.bit_offset
        # num_short_term_ref_pic_sets must come after both flags (parser advanced).
        num_st = sps.span("num_short_term_ref_pic_sets")
        assert num_st.bit_offset > pcm.bit_offset

    def test_splice_pcm_flag_round_trips(self):
        rbsp = _nal_rbsp(33)
        sps = parse_sps(rbsp)
        span = sps.span("pcm_enabled_flag")
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1)
        reparsed = parse_sps(new_rbsp)
        assert reparsed.pcm_enabled_flag == 1
        # length unchanged: a single u(1) flip never shifts the bitstream.
        assert len(new_rbsp) == len(rbsp)

    def test_scaling_list_flag_recorded_even_when_set(self):
        # When scaling_list_enabled is set the parser bails before the RPS region,
        # but the flag span must still be recorded so a mutator can find it.
        rbsp = _nal_rbsp(33)
        sps = parse_sps(rbsp)
        span = sps.span("scaling_list_enabled_flag")
        flipped = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1)
        reparsed = parse_sps(flipped)
        assert reparsed.scaling_list_enabled_flag == 1
        assert reparsed.has_span("scaling_list_enabled_flag")
        # parser bailed → pcm flag and RPS region not reached
        assert not reparsed.has_span("pcm_enabled_flag")


class TestSpsVuiHrdParsing:
    def test_vui_gate_flags_parsed(self):
        sps = parse_sps(_nal_rbsp(33))
        # The bundled seed declares a VUI block with timing info present and the
        # HRD sub-block absent — exactly the target the sps-vui-hrd mutator needs.
        assert sps.vui_parameters_present_flag == 1
        assert sps.vui_timing_info_present_flag == 1
        assert sps.vui_hrd_parameters_present_flag == 0

    def test_vui_gate_spans_present_and_ordered(self):
        sps = parse_sps(_nal_rbsp(33))
        assert sps.has_span("vui_parameters_present_flag")
        assert sps.has_span("vui_timing_info_present_flag")
        assert sps.has_span("vui_hrd_parameters_present_flag")
        vui = sps.span("vui_parameters_present_flag")
        timing = sps.span("vui_timing_info_present_flag")
        hrd = sps.span("vui_hrd_parameters_present_flag")
        for s in (vui, timing, hrd):
            assert s.bit_length == 1
        # Nesting order: vui < timing < hrd, and all sit after the RPS region.
        assert vui.bit_offset < timing.bit_offset < hrd.bit_offset
        assert vui.bit_offset > sps.span("num_short_term_ref_pic_sets").bit_offset

    def test_splice_hrd_gate_round_trips(self):
        rbsp = _nal_rbsp(33)
        sps = parse_sps(rbsp)
        span = sps.span("vui_hrd_parameters_present_flag")
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1)
        reparsed = parse_sps(new_rbsp)
        assert reparsed.vui_hrd_parameters_present_flag == 1
        # A single u(1) flip never shifts the bitstream length.
        assert len(new_rbsp) == len(rbsp)


class TestSpsExtensionParsing:
    def test_clean_fixture_reaches_extension_gate(self):
        # The bundled seed has a VUI block (timing present, HRD absent); the
        # parser must now walk past the VUI tail to record the SPS extension gate.
        sps = parse_sps(_nal_rbsp(33))
        assert sps.has_span("sps_extension_present_flag")
        assert sps.sps_extension_present_flag == 0  # off → a valid mutation target

    def test_extension_gate_after_vui_gates(self):
        sps = parse_sps(_nal_rbsp(33))
        ext = sps.span("sps_extension_present_flag")
        assert ext.bit_length == 1
        # The extension gate sits after every VUI gate.
        assert ext.bit_offset > sps.span("vui_hrd_parameters_present_flag").bit_offset

    def test_splice_extension_gate_round_trips(self):
        rbsp = _nal_rbsp(33)
        sps = parse_sps(rbsp)
        span = sps.span("sps_extension_present_flag")
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1)
        reparsed = parse_sps(new_rbsp)
        assert reparsed.sps_extension_present_flag == 1
        # A single u(1) flip never shifts the bitstream length.
        assert len(new_rbsp) == len(rbsp)
        # With the extension gate now on, the parser reaches the range-extension
        # flag too (the next bit, which the seed's trailing bits happen to carry).
        assert reparsed.has_span("sps_range_extension_flag")

    def test_no_vui_reaches_extension_immediately(self):
        # When VUI is absent, sps_extension_present_flag follows the VUI gate
        # directly; build such an SPS and confirm the parser records it.
        rbsp = _build_extension_sps_rbsp(vui_present=0, ext_present=1, rext_flag=1)
        sps = parse_sps(rbsp)
        assert sps.sps_extension_present_flag == 1
        assert sps.sps_range_extension_flag == 1

    def test_extension_present_off_leaves_rext_unset(self):
        rbsp = _build_extension_sps_rbsp(vui_present=0, ext_present=0)
        sps = parse_sps(rbsp)
        assert sps.sps_extension_present_flag == 0
        assert not sps.has_span("sps_range_extension_flag")
        assert sps.sps_range_extension_flag is None

    def test_hrd_present_blocks_extension_walk(self):
        # The hrd_parameters() body is unmodelled, so an SPS with the HRD gate on
        # must NOT reach the extension region (the gate is left unset).
        rbsp = _build_extension_sps_rbsp(vui_present=1, hrd_present=1)
        sps = parse_sps(rbsp)
        assert sps.vui_hrd_parameters_present_flag == 1
        assert not sps.has_span("sps_extension_present_flag")


def _build_extension_sps_rbsp(
    *,
    vui_present: int = 1,
    timing_present: int = 1,
    hrd_present: int = 0,
    ext_present: int = 0,
    rext_flag: int = 0,
) -> bytes:
    """A minimal SPS RBSP that parses through to the SPS extension gate region.

    Mirrors the VUI-block prefix used elsewhere in the suite, then emits the VUI
    tail (``bitstream_restriction_flag`` absent) and a configurable extension
    region (H.265 §7.3.2.2.1). When ``hrd_present`` is set the hrd_parameters()
    body is *not* emitted (the parser stops at the gate), so that combination is
    only useful for the "HRD blocks the walk" test.
    """
    w = BitWriter()
    w.write_bits(0, 4)  # sps_video_parameter_set_id
    w.write_bits(0, 3)  # sps_max_sub_layers_minus1 = 0
    w.write_bit(0)      # sps_temporal_id_nesting_flag
    w.write_bits(0, 8)   # profile_tier_level
    w.write_bits(0, 32)
    w.write_bits(0, 48)
    w.write_bits(0, 8)
    w.write_ue(0)        # sps_seq_parameter_set_id
    w.write_ue(1)        # chroma_format_idc (4:2:0)
    w.write_ue(64)       # pic_width_in_luma_samples
    w.write_ue(64)       # pic_height_in_luma_samples
    w.write_bit(0)       # conformance_window_flag
    w.write_ue(0)        # bit_depth_luma_minus8
    w.write_ue(0)        # bit_depth_chroma_minus8
    w.write_ue(4)        # log2_max_pic_order_cnt_lsb_minus4
    w.write_bit(0)       # sps_sub_layer_ordering_info_present_flag
    w.write_ue(0)        # sps_max_dec_pic_buffering_minus1[0]
    w.write_ue(0)        # sps_max_num_reorder_pics[0]
    w.write_ue(0)        # sps_max_latency_increase_plus1[0]
    w.write_ue(0)        # log2_min_luma_coding_block_size_minus3
    w.write_ue(0)        # log2_diff_max_min_luma_coding_block_size
    w.write_ue(0)        # log2_min_luma_transform_block_size_minus2
    w.write_ue(0)        # log2_diff_max_min_luma_transform_block_size
    w.write_ue(0)        # max_transform_hierarchy_depth_inter
    w.write_ue(0)        # max_transform_hierarchy_depth_intra
    w.write_bit(0)       # scaling_list_enabled_flag
    w.write_bit(0)       # amp_enabled_flag
    w.write_bit(0)       # sample_adaptive_offset_enabled_flag
    w.write_bit(0)       # pcm_enabled_flag
    w.write_ue(0)        # num_short_term_ref_pic_sets = 0
    w.write_bit(0)       # long_term_ref_pics_present_flag = 0
    w.write_bit(0)       # sps_temporal_mvp_enabled_flag
    w.write_bit(0)       # strong_intra_smoothing_enabled_flag
    w.write_bit(vui_present)  # vui_parameters_present_flag
    if vui_present:
        w.write_bit(0)   # aspect_ratio_info_present_flag
        w.write_bit(0)   # overscan_info_present_flag
        w.write_bit(0)   # video_signal_type_present_flag
        w.write_bit(0)   # chroma_loc_info_present_flag
        w.write_bit(0)   # neutral_chroma_indication_flag
        w.write_bit(0)   # field_seq_flag
        w.write_bit(0)   # frame_field_info_present_flag
        w.write_bit(0)   # default_display_window_flag
        w.write_bit(timing_present)  # vui_timing_info_present_flag
        if timing_present:
            w.write_bits(1, 32)  # vui_num_units_in_tick
            w.write_bits(1, 32)  # vui_time_scale
            w.write_bit(0)       # vui_poc_proportional_to_timing_flag
            w.write_bit(hrd_present)  # vui_hrd_parameters_present_flag
            if hrd_present:
                # hrd_parameters() body intentionally omitted; the parser stops at
                # the gate and never reaches the extension region.
                w.write_bit(1)   # rbsp_stop_one_bit
                return w.to_bytes()
        w.write_bit(0)   # bitstream_restriction_flag
    w.write_bit(ext_present)  # sps_extension_present_flag
    if ext_present:
        w.write_bit(rext_flag)  # sps_range_extension_flag
        w.write_bit(0)   # sps_multilayer_extension_flag
        w.write_bit(0)   # sps_3d_extension_flag
        w.write_bit(0)   # sps_scc_extension_flag
        w.write_bits(0, 4)  # sps_extension_4bits
    w.write_bit(1)       # rbsp_stop_one_bit
    return w.to_bytes()


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


class TestPpsDeblockingParsing:
    def test_seed_reaches_loop_filter_and_control_flags(self):
        # The single-frame intra seed has no tiles, so the parser reaches the
        # loop-filter-across-slices flag and the deblocking control flag.
        pps = parse_pps(_nal_rbsp(34))
        assert pps.pps_loop_filter_across_slices_enabled_flag in (0, 1)
        assert pps.deblocking_filter_control_present_flag in (0, 1)
        assert pps.has_span("pps_loop_filter_across_slices_enabled_flag")
        assert pps.has_span("deblocking_filter_control_present_flag")

    def test_control_off_leaves_deeper_fields_unset(self):
        rbsp = _build_pps_rbsp(ctl_present=0)
        pps = parse_pps(rbsp)
        assert pps.deblocking_filter_control_present_flag == 0
        assert pps.pps_deblocking_filter_disabled_flag is None
        assert pps.pps_beta_offset_div2 is None
        assert pps.pps_tc_offset_div2 is None
        assert not pps.has_span("pps_beta_offset_div2")

    def test_control_on_parses_beta_and_tc(self):
        rbsp = _build_pps_rbsp(ctl_present=1, disabled=0, beta=3, tc=-2)
        pps = parse_pps(rbsp)
        assert pps.deblocking_filter_control_present_flag == 1
        assert pps.deblocking_filter_override_enabled_flag == 0
        assert pps.pps_deblocking_filter_disabled_flag == 0
        assert pps.pps_beta_offset_div2 == 3
        assert pps.pps_tc_offset_div2 == -2

    def test_disabled_flag_suppresses_offsets(self):
        rbsp = _build_pps_rbsp(ctl_present=1, disabled=1)
        pps = parse_pps(rbsp)
        assert pps.pps_deblocking_filter_disabled_flag == 1
        assert pps.pps_beta_offset_div2 is None
        assert not pps.has_span("pps_beta_offset_div2")

    def test_tiles_enabled_bails_before_deblocking(self):
        # Tile geometry is variable-length and out of scope; the parser must not
        # mis-read it as the deblocking region.
        rbsp = _build_pps_rbsp(tiles_enabled=1)
        pps = parse_pps(rbsp)
        assert pps.tiles_enabled_flag == 1
        assert pps.pps_loop_filter_across_slices_enabled_flag is None
        assert not pps.has_span("pps_loop_filter_across_slices_enabled_flag")

    def test_splice_loop_filter_flag(self):
        rbsp = _build_pps_rbsp(loop_filter_across=1)
        pps = parse_pps(rbsp)
        span = pps.span("pps_loop_filter_across_slices_enabled_flag")
        flipped = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 0)
        assert parse_pps(flipped).pps_loop_filter_across_slices_enabled_flag == 0

    def test_splice_se_beta_offset_out_of_range(self):
        rbsp = _build_pps_rbsp(ctl_present=1, beta=0, tc=0)
        pps = parse_pps(rbsp)
        span = pps.span("pps_beta_offset_div2")
        new_rbsp = splice_se_field(rbsp, span, -64)
        reparsed = parse_pps(new_rbsp)
        assert reparsed.pps_beta_offset_div2 == -64
        # tc must be preserved by the splice.
        assert reparsed.pps_tc_offset_div2 == 0


class TestPpsQpParsing:
    def test_seed_records_qp_and_transform_skip(self):
        # The single-frame intra seed parses through the QP / transform-skip
        # region (those fields precede the tile-config flags).
        pps = parse_pps(_nal_rbsp(34))
        assert pps.init_qp_minus26 is not None
        assert pps.transform_skip_enabled_flag in (0, 1)
        assert pps.has_span("init_qp_minus26")
        assert pps.has_span("transform_skip_enabled_flag")

    def test_init_qp_value_round_trips(self):
        rbsp = _build_pps_rbsp(init_qp=7, transform_skip=0)
        pps = parse_pps(rbsp)
        assert pps.init_qp_minus26 == 7
        assert pps.transform_skip_enabled_flag == 0

    def test_negative_init_qp_round_trips(self):
        rbsp = _build_pps_rbsp(init_qp=-12, transform_skip=1)
        pps = parse_pps(rbsp)
        assert pps.init_qp_minus26 == -12
        assert pps.transform_skip_enabled_flag == 1

    def test_transform_skip_span_is_one_bit(self):
        rbsp = _build_pps_rbsp(transform_skip=1)
        pps = parse_pps(rbsp)
        span = pps.span("transform_skip_enabled_flag")
        assert span.bit_length == 1
        assert span.value == 1

    def test_splice_init_qp_out_of_range_preserves_tail(self):
        # Rewriting init_qp to a far out-of-range se(v) must not disturb the
        # deblocking fields that follow.
        rbsp = _build_pps_rbsp(init_qp=0, ctl_present=1, beta=3, tc=-2)
        pps = parse_pps(rbsp)
        span = pps.span("init_qp_minus26")
        new_rbsp = splice_se_field(rbsp, span, 52)
        reparsed = parse_pps(new_rbsp)
        assert reparsed.init_qp_minus26 == 52
        assert reparsed.pps_beta_offset_div2 == 3
        assert reparsed.pps_tc_offset_div2 == -2

    def test_splice_transform_skip_flip_preserves_tail(self):
        rbsp = _build_pps_rbsp(transform_skip=0, ctl_present=1, beta=1, tc=1)
        pps = parse_pps(rbsp)
        span = pps.span("transform_skip_enabled_flag")
        flipped = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1)
        reparsed = parse_pps(flipped)
        assert reparsed.transform_skip_enabled_flag == 1
        assert reparsed.init_qp_minus26 == 0
        assert reparsed.pps_beta_offset_div2 == 1


class TestPpsExtensionGateParsing:
    def test_seed_reaches_both_extension_gates(self):
        # The single-frame intra seed has no tiles and control-present off, so the
        # parser walks the deblocking tail into the PPS extension gate region.
        pps = parse_pps(_nal_rbsp(34))
        assert pps.pps_scaling_list_data_present_flag in (0, 1)
        assert pps.pps_extension_present_flag in (0, 1)
        assert pps.has_span("pps_scaling_list_data_present_flag")
        assert pps.has_span("pps_extension_present_flag")

    def test_extension_gates_are_single_bits(self):
        pps = parse_pps(_build_pps_rbsp())
        assert pps.span("pps_scaling_list_data_present_flag").bit_length == 1
        assert pps.span("pps_extension_present_flag").bit_length == 1

    def test_extension_gates_follow_deblocking_region(self):
        pps = parse_pps(_build_pps_rbsp())
        names = [s.name for s in pps.spans]
        assert names.index("deblocking_filter_control_present_flag") < names.index(
            "pps_scaling_list_data_present_flag"
        )
        assert names.index("pps_scaling_list_data_present_flag") < names.index(
            "pps_extension_present_flag"
        )

    def test_scaling_list_gate_on_blocks_extension_walk(self):
        # When the scaling-list gate is set its variable-length body follows and is
        # not modelled, so the parser must stop before pps_extension_present_flag.
        rbsp = _build_pps_rbsp(scaling_list_present=1)
        pps = parse_pps(rbsp)
        assert pps.pps_scaling_list_data_present_flag == 1
        assert pps.pps_extension_present_flag is None
        assert not pps.has_span("pps_extension_present_flag")

    def test_extension_present_gate_recorded_when_on(self):
        rbsp = _build_pps_rbsp(pps_extension_present=1)
        pps = parse_pps(rbsp)
        assert pps.pps_extension_present_flag == 1

    def test_tiles_enabled_leaves_extension_gates_unset(self):
        rbsp = _build_pps_rbsp(tiles_enabled=1)
        pps = parse_pps(rbsp)
        assert pps.pps_scaling_list_data_present_flag is None
        assert pps.pps_extension_present_flag is None
        assert not pps.has_span("pps_scaling_list_data_present_flag")

    def test_extension_gates_reached_after_full_deblocking_offsets(self):
        # With control present and offsets present, the deblocking region is its
        # longest form; the parser must still land on the extension gates after it.
        rbsp = _build_pps_rbsp(ctl_present=1, disabled=0, beta=3, tc=-2)
        pps = parse_pps(rbsp)
        assert pps.has_span("pps_scaling_list_data_present_flag")
        assert pps.has_span("pps_extension_present_flag")

    def test_splice_scaling_list_gate_round_trips(self):
        rbsp = _build_pps_rbsp(scaling_list_present=0)
        pps = parse_pps(rbsp)
        span = pps.span("pps_scaling_list_data_present_flag")
        flipped = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1)
        assert parse_pps(flipped).pps_scaling_list_data_present_flag == 1

    def test_splice_extension_present_gate_round_trips(self):
        rbsp = _build_pps_rbsp(pps_extension_present=0)
        pps = parse_pps(rbsp)
        span = pps.span("pps_extension_present_flag")
        flipped = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 1)
        assert parse_pps(flipped).pps_extension_present_flag == 1


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
