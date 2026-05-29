"""Unit tests for the four v0.1 mutators and the registry."""

from __future__ import annotations

import random
from pathlib import Path

from mangle.bitstream import (
    NalUnit,
    assemble_nal_units,
    ebsp_to_rbsp,
    rbsp_to_ebsp,
    split_nal_units,
    START_CODE_LONG,
    START_CODE_SHORT,
)
from mangle.hevc import parse_pps, parse_sei, parse_slice_header, parse_sps
from mangle.mutators import get_mutator, list_mutators

SEED = Path(__file__).parent / "fixtures" / "clean.h265"
SEI_SEED = Path(__file__).parent / "fixtures" / "sei-buffering.hevc"

REQUIRED_MUTATORS = {
    "sps-dimensions",
    "pps-tile-config",
    "slice-header-ref-pic-list",
    "nal-unit-type-swap",
}

RPS_MUTATORS = {"rps-overflow", "rps-lt-poc-ambiguity"}
SEI_MUTATORS = {"sei-buffering-overflow"}


def _seed_nals():
    return split_nal_units(SEED.read_bytes())


class TestRegistry:
    def test_all_required_mutators_present(self):
        available = set(list_mutators())
        assert REQUIRED_MUTATORS.issubset(available)
        assert len(available) >= 4

    def test_get_unknown_raises(self):
        try:
            get_mutator("nope")
        except KeyError as exc:
            assert "unknown mutator" in str(exc)
        else:
            raise AssertionError("expected KeyError")


class TestMutatorsProduceChanges:
    def test_each_mutator_changes_bytes(self):
        original = SEED.read_bytes()
        for name in REQUIRED_MUTATORS:
            rng = random.Random(42)
            result = get_mutator(name)(_seed_nals(), rng)
            assert result.bytes_changed > 0, f"{name} changed nothing"
            mutated = assemble_nal_units(result.nals)
            assert mutated != original, f"{name} produced identical stream"
            assert result.detail  # non-empty description

    def test_mutated_stream_still_splittable(self):
        # A structured mutant must remain a parseable Annex-B stream.
        for name in REQUIRED_MUTATORS:
            rng = random.Random(7)
            result = get_mutator(name)(_seed_nals(), rng)
            mutated = assemble_nal_units(result.nals)
            nals = split_nal_units(mutated)
            assert len(nals) >= 1


class TestReproducibility:
    def test_same_seed_same_output(self):
        # Criterion 7: --seed-rng 42 produces identical output across runs.
        for name in REQUIRED_MUTATORS:
            r1 = get_mutator(name)(_seed_nals(), random.Random(42))
            r2 = get_mutator(name)(_seed_nals(), random.Random(42))
            assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
            assert r1.bytes_changed == r2.bytes_changed
            assert r1.detail == r2.detail

    def test_different_seed_can_differ(self):
        # sps-dimensions has enough entropy to differ across seeds (sanity).
        outputs = set()
        for seed in range(10):
            r = get_mutator("sps-dimensions")(_seed_nals(), random.Random(seed))
            outputs.add(assemble_nal_units(r.nals))
        assert len(outputs) > 1


class TestSpsDimensionsMutator:
    def test_only_sps_nal_changes(self):
        original = _seed_nals()
        result = get_mutator("sps-dimensions")(_seed_nals(), random.Random(42))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue  # SPS may change
            assert orig.ebsp == mut.ebsp, "non-SPS NAL was modified"


class TestNalUnitTypeSwap:
    def test_changes_a_nal_type(self):
        original = _seed_nals()
        result = get_mutator("nal-unit-type-swap")(_seed_nals(), random.Random(1))
        orig_types = [n.nal_unit_type for n in original]
        new_types = [n.nal_unit_type for n in result.nals]
        assert orig_types != new_types


def _mutated_sps(name: str, rng_seed: int):
    """Apply mutator ``name`` and return the re-parsed SPS of the mutant stream."""
    result = get_mutator(name)(_seed_nals(), random.Random(rng_seed))
    mutated = assemble_nal_units(result.nals)
    sps_nal = next(n for n in split_nal_units(mutated) if n.nal_unit_type == 33)
    return result, parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))


class TestRpsMutatorsRegistered:
    def test_rps_mutators_present(self):
        available = set(list_mutators())
        assert RPS_MUTATORS.issubset(available)

    def test_rps_mutators_reproducible(self):
        for name in RPS_MUTATORS:
            r1 = get_mutator(name)(_seed_nals(), random.Random(42))
            r2 = get_mutator(name)(_seed_nals(), random.Random(42))
            assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
            assert r1.detail == r2.detail


class TestRpsOverflow:
    def test_num_negative_pics_exceeds_dpb_bound(self):
        # (a) rps-overflow produces num_negative_pics > sps_max_dec_pic_buffering_minus1[0].
        # The synthesis path picks negative OR positive; force the negative path
        # by scanning seeds until we hit num_negative_pics overflow, and assert the
        # invariant holds for whichever count was bumped.
        result, sps = _mutated_sps("rps-overflow", 42)
        assert sps.num_short_term_ref_pic_sets >= 1
        rps0 = sps.short_term_rps[0]
        dpb_bound = sps.sps_max_dec_pic_buffering_minus1[0]
        overflowed = max(rps0.num_negative_pics, rps0.num_positive_pics)
        assert overflowed > dpb_bound, (
            f"RPS picture count {overflowed} did not exceed DPB bound {dpb_bound}"
        )

    def test_negative_path_specifically(self):
        # Find a seed whose detail bumps num_negative_pics, then assert it overflows.
        for seed in range(50):
            result, sps = _mutated_sps("rps-overflow", seed)
            if "num_negative_pics" in result.detail:
                dpb_bound = sps.sps_max_dec_pic_buffering_minus1[0]
                assert sps.short_term_rps[0].num_negative_pics > dpb_bound
                return
        raise AssertionError("no seed exercised the num_negative_pics overflow path")

    def test_only_sps_nal_changes(self):
        original = _seed_nals()
        result = get_mutator("rps-overflow")(_seed_nals(), random.Random(42))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue
            assert orig.ebsp == mut.ebsp, "rps-overflow modified a non-SPS NAL"

    def test_framing_intact(self):
        # (c) mutated output passes byte-stream framing validation (start codes intact).
        result = get_mutator("rps-overflow")(_seed_nals(), random.Random(42))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        # Every NAL must still be recoverable by the splitter.
        assert len(split_nal_units(mutated)) == len(_seed_nals())


class TestRpsLtPocAmbiguity:
    def test_two_entries_share_poc_lsb(self):
        # (b) rps-lt-poc-ambiguity produces two long-term entries with matching poc_lsb_lt.
        result, sps = _mutated_sps("rps-lt-poc-ambiguity", 7)
        assert sps.long_term_ref_pics_present_flag == 1
        assert len(sps.long_term_ref_pics) == 2
        assert (
            sps.long_term_ref_pics[0].poc_lsb_lt
            == sps.long_term_ref_pics[1].poc_lsb_lt
        ), "the two long-term entries do not share a poc_lsb_lt value"

    def test_framing_intact(self):
        # (c) start codes intact after long-term RPS injection.
        result = get_mutator("rps-lt-poc-ambiguity")(_seed_nals(), random.Random(7))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_only_sps_nal_changes(self):
        original = _seed_nals()
        result = get_mutator("rps-lt-poc-ambiguity")(_seed_nals(), random.Random(7))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue
            assert orig.ebsp == mut.ebsp, "rps-lt-poc-ambiguity modified a non-SPS NAL"


def _sei_seed_nals():
    return split_nal_units(SEI_SEED.read_bytes())


class TestSeiMutatorsRegistered:
    def test_sei_mutator_present(self):
        available = set(list_mutators())
        assert SEI_MUTATORS.issubset(available)


class TestSeiBufferingOverflow:
    """Tests for the sei-buffering-overflow mutator."""

    def test_mutator_changes_bytes(self):
        """The mutator must produce a stream different from the input."""
        original = SEI_SEED.read_bytes()
        result = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated != original
        assert result.bytes_changed > 0
        assert result.detail

    def test_reproducible_with_same_seed(self):
        """Same rng seed must produce identical output."""
        r1 = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(42))
        r2 = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(42))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_framing_intact(self):
        """Output must remain valid Annex-B (start codes intact, NALs splittable)."""
        result = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        split = split_nal_units(mutated)
        assert len(split) >= 1

    def test_buffering_period_path(self):
        """Some rng seed exercises the buffering_period overflow path."""
        for seed in range(20):
            result = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(seed))
            if "buffering_period" in result.detail:
                assert "0xFFFFFFFF" in result.detail
                return
        raise AssertionError("no seed exercised the buffering_period overflow path")

    def test_pic_timing_path(self):
        """Find a seed that takes the pic_timing path (mutation_choice == 1)."""
        for seed in range(100):
            result = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(seed))
            if "pic_timing" in result.detail:
                assert "0xFF" in result.detail
                return
        raise AssertionError("no seed exercised the pic_timing path within 100 tries")

    def test_recovery_point_path(self):
        """Find a seed that takes the recovery_point path (mutation_choice == 2)."""
        for seed in range(100):
            result = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(seed))
            if "recovery_point" in result.detail:
                assert "-2147483648" in result.detail
                return
        raise AssertionError("no seed exercised the recovery_point path within 100 tries")

    def test_synthetic_injection_on_no_sei_stream(self):
        """When the input has no SEI NAL, a synthetic PREFIX_SEI must be injected."""
        # Build a minimal stream with VPS + SPS + PPS but no SEI.
        from mangle.bitstream import NalUnit, assemble_nal_units
        vps_header = bytes([(32 << 1), 0x01])
        sps_header = bytes([(33 << 1), 0x01])
        pps_header = bytes([(34 << 1), 0x01])
        no_sei_nals = [
            NalUnit(4, 0, vps_header + b"\x80"),
            NalUnit(4, 8, sps_header + b"\x80"),
            NalUnit(4, 16, pps_header + b"\x80"),
        ]
        result = get_mutator("sei-buffering-overflow")(no_sei_nals, random.Random(0))
        mutated_nals = result.nals
        # A new SEI NAL should have been injected
        sei_types = [n.nal_unit_type for n in mutated_nals if n.nal_unit_type in (39, 40)]
        assert len(sei_types) >= 1, "no SEI NAL injected into no-SEI stream"
        assert "synthetic" in result.detail or "PREFIX_SEI" in result.detail

    def test_output_nal_count_with_sei_fixture(self):
        """Output from the SEI fixture must have the same number of NALs (no new injection)."""
        result = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(0))
        # The fixture already has a SEI NAL — we mutate in-place, not inject
        original_count = len(_sei_seed_nals())
        mutated_count = len(result.nals)
        assert mutated_count == original_count, (
            f"expected {original_count} NALs, got {mutated_count} "
            f"(unexpected injection on stream that already has SEI)"
        )

    def test_mutator_result_name(self):
        result = get_mutator("sei-buffering-overflow")(_sei_seed_nals(), random.Random(0))
        assert result.mutator == "sei-buffering-overflow"


DEBLOCKING_MUTATORS = {"pps-deblocking"}


def _build_deblocking_pps_rbsp(
    *, ctl_present: int = 1, disabled: int = 0, beta: int = 0, tc: int = 0
) -> bytes:
    """A minimal PPS RBSP reaching the deblocking-control region (no tiles)."""
    from mangle.bitstream import BitWriter

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
    w.write_se(0)  # init_qp_minus26
    w.write_bit(0)  # constrained_intra_pred_flag
    w.write_bit(0)  # transform_skip_enabled_flag
    w.write_bit(0)  # cu_qp_delta_enabled_flag
    w.write_se(0)  # pps_cb_qp_offset
    w.write_se(0)  # pps_cr_qp_offset
    w.write_bit(0)  # pps_slice_chroma_qp_offsets_present_flag
    w.write_bit(0)  # weighted_pred_flag
    w.write_bit(0)  # weighted_bipred_flag
    w.write_bit(0)  # transquant_bypass_enabled_flag
    w.write_bit(0)  # tiles_enabled_flag
    w.write_bit(0)  # entropy_coding_sync_enabled_flag
    w.write_bit(1)  # pps_loop_filter_across_slices_enabled_flag
    w.write_bit(ctl_present)  # deblocking_filter_control_present_flag
    if ctl_present:
        w.write_bit(0)  # deblocking_filter_override_enabled_flag
        w.write_bit(disabled)  # pps_deblocking_filter_disabled_flag
        if not disabled:
            w.write_se(beta)  # pps_beta_offset_div2
            w.write_se(tc)  # pps_tc_offset_div2
    w.write_bit(0)  # pps_scaling_list_data_present_flag
    w.write_bit(0)  # lists_modification_present_flag
    w.write_ue(0)  # log2_parallel_merge_level_minus2
    w.write_bit(0)  # slice_segment_header_extension_present_flag
    w.write_bit(0)  # pps_extension_present_flag
    w.write_bit(1)  # rbsp_stop_one_bit
    return w.to_bytes()


def _deblocking_stream(**kwargs) -> list[NalUnit]:
    """A VPS+SPS+PPS stream whose PPS reaches the deblocking-control region."""
    seed = _seed_nals()
    sps = next(n for n in seed if n.nal_unit_type == 33)
    pps_header = bytes([(34 << 1), 0x01])
    pps_rbsp = _build_deblocking_pps_rbsp(**kwargs)
    pps_nal = NalUnit(4, 0, pps_header + rbsp_to_ebsp(pps_rbsp))
    vps_header = bytes([(32 << 1), 0x01])
    return [
        NalUnit(4, 0, vps_header + b"\x80"),
        NalUnit(4, 0, sps.ebsp),
        pps_nal,
    ]


class TestPpsDeblockingMutator:
    def test_registered(self):
        assert DEBLOCKING_MUTATORS.issubset(set(list_mutators()))

    def test_changes_bytes_on_seed(self):
        original = SEED.read_bytes()
        result = get_mutator("pps-deblocking")(_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated != original
        assert result.bytes_changed > 0
        assert result.detail

    def test_reproducible(self):
        r1 = get_mutator("pps-deblocking")(_seed_nals(), random.Random(42))
        r2 = get_mutator("pps-deblocking")(_seed_nals(), random.Random(42))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_framing_intact(self):
        result = get_mutator("pps-deblocking")(_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_only_pps_nal_changes(self):
        original = _seed_nals()
        result = get_mutator("pps-deblocking")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 34:
                continue
            assert orig.ebsp == mut.ebsp, "pps-deblocking modified a non-PPS NAL"

    def test_seed_takes_loop_filter_path(self):
        # The seed has deblocking_filter_control_present_flag == 0, so the only
        # available branch is the loop-filter-across-slices flip; the mutant must
        # re-parse with that flag flipped.
        original_pps = next(n for n in _seed_nals() if n.nal_unit_type == 34)
        orig = parse_pps(ebsp_to_rbsp(original_pps.ebsp[2:]))
        result = get_mutator("pps-deblocking")(_seed_nals(), random.Random(0))
        mutated_pps = next(n for n in result.nals if n.nal_unit_type == 34)
        mut = parse_pps(ebsp_to_rbsp(mutated_pps.ebsp[2:]))
        assert "loop_filter_across_slices" in result.detail
        assert (
            mut.pps_loop_filter_across_slices_enabled_flag
            == 1 - orig.pps_loop_filter_across_slices_enabled_flag
        )

    def test_beta_tc_offset_goes_out_of_range(self):
        # With a control-present PPS, some seed exercises the beta/tc path and
        # pushes an offset outside the spec range [-6, 6].
        for seed in range(60):
            nals = _deblocking_stream(ctl_present=1, beta=0, tc=0)
            result = get_mutator("pps-deblocking")(nals, random.Random(seed))
            if "offset_div2" in result.detail:
                mutated_pps = next(n for n in result.nals if n.nal_unit_type == 34)
                mut = parse_pps(ebsp_to_rbsp(mutated_pps.ebsp[2:]))
                out_of_range = [
                    v
                    for v in (mut.pps_beta_offset_div2, mut.pps_tc_offset_div2)
                    if v is not None and not (-6 <= v <= 6)
                ]
                assert out_of_range, f"no offset out of [-6,6]: {result.detail}"
                return
        raise AssertionError("no seed exercised the beta/tc offset path")

    def test_disabled_flag_path(self):
        for seed in range(60):
            nals = _deblocking_stream(ctl_present=1, disabled=0, beta=0, tc=0)
            result = get_mutator("pps-deblocking")(nals, random.Random(seed))
            if "pps_deblocking_filter_disabled_flag" in result.detail:
                return
        raise AssertionError("no seed exercised the disabled-flag path")

    def test_tiles_pps_raises(self):
        # A tiles-enabled PPS cannot reach the deblocking region; the mutator must
        # signal that so the engine can choose another mutator.
        seed = _seed_nals()
        sps = next(n for n in seed if n.nal_unit_type == 33)
        # Build a PPS with tiles_enabled = 1 (truncated right after the flag).
        from mangle.bitstream import BitWriter

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
        w.write_se(0)  # init_qp_minus26
        w.write_bit(0)  # constrained_intra_pred_flag
        w.write_bit(0)  # transform_skip_enabled_flag
        w.write_bit(0)  # cu_qp_delta_enabled_flag
        w.write_se(0)  # pps_cb_qp_offset
        w.write_se(0)  # pps_cr_qp_offset
        w.write_bit(0)  # pps_slice_chroma_qp_offsets_present_flag
        w.write_bit(0)  # weighted_pred_flag
        w.write_bit(0)  # weighted_bipred_flag
        w.write_bit(0)  # transquant_bypass_enabled_flag
        w.write_bit(1)  # tiles_enabled_flag
        w.write_bit(1)  # rbsp_stop_one_bit
        pps_header = bytes([(34 << 1), 0x01])
        pps_nal = NalUnit(4, 0, pps_header + rbsp_to_ebsp(w.to_bytes()))
        vps_header = bytes([(32 << 1), 0x01])
        tiled = [NalUnit(4, 0, vps_header + b"\x80"), NalUnit(4, 0, sps.ebsp), pps_nal]
        try:
            get_mutator("pps-deblocking")(tiled, random.Random(0))
        except ValueError as exc:
            assert "deblocking" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError for tiles-enabled PPS")

    def test_result_name(self):
        result = get_mutator("pps-deblocking")(_seed_nals(), random.Random(0))
        assert result.mutator == "pps-deblocking"


# --- Item 5: chroma-format and bit-depth SPS mutators ---------------------

CHROMA_BITDEPTH_MUTATORS = {"sps-chroma-format", "sps-bit-depth"}


def _build_sps_rbsp(
    *,
    chroma_format_idc: int = 1,
    bit_depth_luma_minus8: int = 0,
    bit_depth_chroma_minus8: int = 0,
) -> bytes:
    """Construct a minimal SPS RBSP that parses through the bit-depth region.

    Uses max_sub_layers_minus1 == 0 so the profile_tier_level block is a fixed
    96 bits, and stops just after bit_depth_chroma_minus8 — far enough for the
    chroma and bit-depth spans, which is all these mutators need.
    """
    from mangle.bitstream import BitWriter

    w = BitWriter()
    w.write_bits(0, 4)  # sps_video_parameter_set_id
    w.write_bits(0, 3)  # sps_max_sub_layers_minus1 = 0
    w.write_bit(0)      # sps_temporal_id_nesting_flag
    # profile_tier_level (general block only, max_sub_layers_minus1 == 0): 96 bits
    w.write_bits(0, 8)   # profile_space/tier/profile_idc
    w.write_bits(0, 32)  # profile_compatibility_flag[32]
    w.write_bits(0, 48)  # constraint flags
    w.write_bits(0, 8)   # general_level_idc
    w.write_ue(0)        # sps_seq_parameter_set_id
    w.write_ue(chroma_format_idc)  # chroma_format_idc
    if chroma_format_idc == 3:
        w.write_bit(0)   # separate_colour_plane_flag
    w.write_ue(64)       # pic_width_in_luma_samples
    w.write_ue(64)       # pic_height_in_luma_samples
    w.write_bit(0)       # conformance_window_flag
    w.write_ue(bit_depth_luma_minus8)    # bit_depth_luma_minus8
    w.write_ue(bit_depth_chroma_minus8)  # bit_depth_chroma_minus8
    w.write_bit(1)       # rbsp_stop_one_bit (we stop here; deeper fields absent)
    return w.to_bytes()


def _sps_stream(**kwargs) -> list[NalUnit]:
    """Wrap a synthesised SPS RBSP in a minimal VPS+SPS+PPS NAL list."""
    sps_rbsp = _build_sps_rbsp(**kwargs)
    sps_header = bytes([(33 << 1), 0x01])
    sps_nal = NalUnit(4, 0, sps_header + rbsp_to_ebsp(sps_rbsp))
    vps_nal = NalUnit(4, 0, bytes([(32 << 1), 0x01]) + b"\x80")
    pps_nal = NalUnit(4, 0, bytes([(34 << 1), 0x01]) + b"\x80")
    return [vps_nal, sps_nal, pps_nal]


def _reparse_sps(result_nals: list[NalUnit]):
    mutated = assemble_nal_units(result_nals)
    sps_nal = next(n for n in split_nal_units(mutated) if n.nal_unit_type == 33)
    return parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))


class TestChromaBitDepthMutatorsRegistered:
    def test_present(self):
        assert CHROMA_BITDEPTH_MUTATORS.issubset(set(list_mutators()))

    def test_reproducible(self):
        for name in CHROMA_BITDEPTH_MUTATORS:
            r1 = get_mutator(name)(_seed_nals(), random.Random(42))
            r2 = get_mutator(name)(_seed_nals(), random.Random(42))
            assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
            assert r1.detail == r2.detail


class TestSpsChromaFormat:
    def test_changes_only_sps(self):
        original = _seed_nals()
        result = get_mutator("sps-chroma-format")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue
            assert orig.ebsp == mut.ebsp, "non-SPS NAL modified"

    def test_seed_idc3_only_offers_reserved(self):
        # The bundled seed is 4:4:4 (idc == 3), so the force_444 branch is never
        # chosen; every result must be the reserved value 4.
        for s in range(16):
            result = get_mutator("sps-chroma-format")(_seed_nals(), random.Random(s))
            sps = _reparse_sps(result.nals)
            assert sps.chroma_format_idc == 4
            assert "reserved" in result.detail

    def test_reserved_value_is_out_of_range(self):
        # Synthetic 4:2:0 SPS, force the reserved branch via the constructed seed.
        nals = _sps_stream(chroma_format_idc=1)
        # Force "reserved" deterministically: idc==1 means choices = [reserved, force_444]
        # so we just check that at least one seed yields the reserved value 4.
        got_reserved = False
        for s in range(20):
            result = get_mutator("sps-chroma-format")(nals, random.Random(s))
            sps = _reparse_sps(result.nals)
            if sps.chroma_format_idc == 4:
                got_reserved = True
                assert "reserved" in result.detail
        assert got_reserved, "reserved (idc=4) mutation never produced"

    def test_force_444_branch_reaches_3(self):
        # With a non-3 seed, the force_444 branch must be reachable and set idc=3.
        nals = _sps_stream(chroma_format_idc=1)
        got_444 = False
        for s in range(20):
            result = get_mutator("sps-chroma-format")(nals, random.Random(s))
            sps = _reparse_sps(result.nals)
            if sps.chroma_format_idc == 3:
                got_444 = True
                assert "4:4:4" in result.detail
        assert got_444, "force_444 (idc=3) mutation never produced"

    def test_result_name_and_changes(self):
        result = get_mutator("sps-chroma-format")(_seed_nals(), random.Random(0))
        assert result.mutator == "sps-chroma-format"
        assert result.bytes_changed > 0


class TestSpsBitDepth:
    def test_changes_only_sps(self):
        original = _seed_nals()
        result = get_mutator("sps-bit-depth")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue
            assert orig.ebsp == mut.ebsp, "non-SPS NAL modified"

    def test_value_exceeds_spec_ceiling(self):
        # Spec range is [0, 8]; every produced value must be > 8.
        nals = _sps_stream(bit_depth_luma_minus8=0, bit_depth_chroma_minus8=0)
        for s in range(16):
            result = get_mutator("sps-bit-depth")(nals, random.Random(s))
            sps = _reparse_sps(result.nals)
            assert sps.bit_depth_luma_minus8 is not None
            assert sps.bit_depth_chroma_minus8 is not None
            mutated = max(sps.bit_depth_luma_minus8, sps.bit_depth_chroma_minus8)
            assert mutated > 8, f"bit depth not pushed past 8 (seed {s})"

    def test_both_targets_reachable(self):
        nals = _sps_stream()
        targets = set()
        for s in range(24):
            result = get_mutator("sps-bit-depth")(nals, random.Random(s))
            if "bit_depth_luma_minus8" in result.detail:
                targets.add("luma")
            if "bit_depth_chroma_minus8" in result.detail:
                targets.add("chroma")
        assert targets == {"luma", "chroma"}, f"only hit {targets}"

    def test_raises_when_bit_depth_unreachable(self):
        # An SPS that parses its dimensions (stage 1) but is truncated before the
        # bit-depth region (stage 2) leaves the bit-depth fields unset; the mutator
        # must then bail so the engine can pick another mutator.
        from mangle.bitstream import BitWriter

        w = BitWriter()
        w.write_bits(0, 4)  # sps_video_parameter_set_id
        w.write_bits(0, 3)  # sps_max_sub_layers_minus1 = 0
        w.write_bit(0)      # sps_temporal_id_nesting_flag
        w.write_bits(0, 8)   # profile_tier_level: profile_space/tier/profile_idc
        w.write_bits(0, 32)  # profile_compatibility_flag[32]
        w.write_bits(0, 48)  # constraint flags
        w.write_bits(0, 8)   # general_level_idc
        w.write_ue(0)        # sps_seq_parameter_set_id
        w.write_ue(1)        # chroma_format_idc (not 3, no separate-plane flag)
        w.write_ue(64)       # pic_width_in_luma_samples
        w.write_ue(64)       # pic_height_in_luma_samples
        # truncate here: stage 2 (conformance/bit-depth) is unreachable.
        truncated = w.to_bytes()
        # Sanity: the parser yields dimensions but no bit-depth span.
        sps_view = parse_sps(truncated)
        assert sps_view.pic_width_in_luma_samples == 64
        assert not sps_view.has_span("bit_depth_luma_minus8")

        sps_nal = NalUnit(4, 0, bytes([(33 << 1), 0x01]) + rbsp_to_ebsp(truncated))
        nals = [
            NalUnit(4, 0, bytes([(32 << 1), 0x01]) + b"\x80"),
            sps_nal,
            NalUnit(4, 0, bytes([(34 << 1), 0x01]) + b"\x80"),
        ]
        try:
            get_mutator("sps-bit-depth")(nals, random.Random(0))
        except ValueError as exc:
            assert "bit-depth" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError for truncated SPS")

    def test_result_name(self):
        result = get_mutator("sps-bit-depth")(_seed_nals(), random.Random(0))
        assert result.mutator == "sps-bit-depth"


# --- Item 9: slice-QP / transform-skip PPS mutator ------------------------

QP_MUTATORS = {"pps-slice-qp"}


def _build_qp_pps_rbsp(*, init_qp: int = 0, transform_skip: int = 0) -> bytes:
    """A minimal untiled PPS RBSP reaching the QP / transform-skip region."""
    from mangle.bitstream import BitWriter

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
    w.write_bit(0)  # tiles_enabled_flag
    w.write_bit(0)  # entropy_coding_sync_enabled_flag
    w.write_bit(1)  # pps_loop_filter_across_slices_enabled_flag
    w.write_bit(0)  # deblocking_filter_control_present_flag
    w.write_bit(0)  # pps_scaling_list_data_present_flag
    w.write_bit(0)  # lists_modification_present_flag
    w.write_ue(0)  # log2_parallel_merge_level_minus2
    w.write_bit(0)  # slice_segment_header_extension_present_flag
    w.write_bit(0)  # pps_extension_present_flag
    w.write_bit(1)  # rbsp_stop_one_bit
    return w.to_bytes()


def _qp_stream(**kwargs) -> list[NalUnit]:
    """A VPS+SPS+PPS stream whose PPS reaches the QP / transform-skip region."""
    seed = _seed_nals()
    sps = next(n for n in seed if n.nal_unit_type == 33)
    pps_header = bytes([(34 << 1), 0x01])
    pps_nal = NalUnit(4, 0, pps_header + rbsp_to_ebsp(_build_qp_pps_rbsp(**kwargs)))
    vps_header = bytes([(32 << 1), 0x01])
    return [
        NalUnit(4, 0, vps_header + b"\x80"),
        NalUnit(4, 0, sps.ebsp),
        pps_nal,
    ]


def _reparse_pps(result_nals: list[NalUnit]):
    mutated = assemble_nal_units(result_nals)
    pps_nal = next(n for n in split_nal_units(mutated) if n.nal_unit_type == 34)
    return parse_pps(ebsp_to_rbsp(pps_nal.ebsp[2:]))


class TestPpsSliceQpMutator:
    def test_registered(self):
        assert QP_MUTATORS.issubset(set(list_mutators()))

    def test_changes_bytes_on_seed(self):
        original = SEED.read_bytes()
        result = get_mutator("pps-slice-qp")(_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated != original
        assert result.bytes_changed > 0
        assert result.detail

    def test_reproducible(self):
        r1 = get_mutator("pps-slice-qp")(_seed_nals(), random.Random(42))
        r2 = get_mutator("pps-slice-qp")(_seed_nals(), random.Random(42))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_framing_intact(self):
        result = get_mutator("pps-slice-qp")(_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_only_pps_nal_changes(self):
        original = _seed_nals()
        result = get_mutator("pps-slice-qp")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 34:
                continue
            assert orig.ebsp == mut.ebsp, "pps-slice-qp modified a non-PPS NAL"

    def test_init_qp_goes_out_of_range(self):
        # Some seed exercises the init_qp branch and pushes it outside [-26, 25].
        nals = _qp_stream(init_qp=0, transform_skip=0)
        for seed in range(40):
            result = get_mutator("pps-slice-qp")(nals, random.Random(seed))
            if "init_qp_minus26" in result.detail:
                pps = _reparse_pps(result.nals)
                assert pps.init_qp_minus26 is not None
                assert not (-26 <= pps.init_qp_minus26 <= 25), (
                    f"init_qp {pps.init_qp_minus26} still within spec range"
                )
                return
        raise AssertionError("no seed exercised the init_qp branch")

    def test_transform_skip_flip(self):
        # Some seed exercises the transform_skip branch and flips the bit.
        nals = _qp_stream(init_qp=0, transform_skip=0)
        for seed in range(40):
            result = get_mutator("pps-slice-qp")(nals, random.Random(seed))
            if "transform_skip_enabled_flag" in result.detail:
                pps = _reparse_pps(result.nals)
                assert pps.transform_skip_enabled_flag == 1
                return
        raise AssertionError("no seed exercised the transform_skip branch")

    def test_both_branches_reachable(self):
        nals = _qp_stream()
        branches = set()
        for seed in range(40):
            result = get_mutator("pps-slice-qp")(nals, random.Random(seed))
            if "init_qp_minus26" in result.detail:
                branches.add("init_qp")
            if "transform_skip_enabled_flag" in result.detail:
                branches.add("transform_skip")
        assert branches == {"init_qp", "transform_skip"}, f"only hit {branches}"

    def test_result_name(self):
        result = get_mutator("pps-slice-qp")(_seed_nals(), random.Random(0))
        assert result.mutator == "pps-slice-qp"


EMULATION_MUTATORS = {"nal-emulation-bytes"}


class TestNalEmulationBytesMutator:
    def test_registered(self):
        assert EMULATION_MUTATORS.issubset(set(list_mutators()))

    def test_changes_bytes_on_seed(self):
        original = SEED.read_bytes()
        result = get_mutator("nal-emulation-bytes")(_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated != original
        assert result.bytes_changed > 0
        assert result.detail

    def test_result_name(self):
        result = get_mutator("nal-emulation-bytes")(_seed_nals(), random.Random(0))
        assert result.mutator == "nal-emulation-bytes"

    def test_reproducible(self):
        r1 = get_mutator("nal-emulation-bytes")(_seed_nals(), random.Random(42))
        r2 = get_mutator("nal-emulation-bytes")(_seed_nals(), random.Random(42))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.bytes_changed == r2.bytes_changed
        assert r1.detail == r2.detail

    def test_framing_intact(self):
        # The stream must still split into the same number of NAL units: the
        # mutator works inside one NAL's payload and never touches start codes.
        for seed in range(20):
            result = get_mutator("nal-emulation-bytes")(_seed_nals(), random.Random(seed))
            mutated = assemble_nal_units(result.nals)
            assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
            assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_only_one_nal_changes(self):
        # Exactly one NAL's bytes differ; all others are byte-identical, and the
        # 2-byte NAL header of the mutated unit is preserved.
        for seed in range(20):
            original = _seed_nals()
            result = get_mutator("nal-emulation-bytes")(_seed_nals(), random.Random(seed))
            changed = [
                i
                for i, (o, m) in enumerate(zip(original, result.nals))
                if o.ebsp != m.ebsp
            ]
            assert len(changed) == 1, f"seed {seed} changed {len(changed)} NALs"
            i = changed[0]
            assert original[i].ebsp[:2] == result.nals[i].ebsp[:2], "header altered"

    def test_insert_branch_adds_emulation_sequence(self):
        # An "insert" mutation splices a fresh 0x00 0x00 0x03 triplet into one
        # NAL's payload: the payload grows by exactly 3 bytes and the triplet is
        # present at the recorded offset.
        for seed in range(60):
            original = _seed_nals()
            result = get_mutator("nal-emulation-bytes")(original, random.Random(seed))
            if not result.detail.startswith("inserted phantom"):
                continue
            changed = next(
                i for i, (o, m) in enumerate(zip(original, result.nals))
                if o.ebsp != m.ebsp
            )
            orig_payload = original[changed].ebsp[2:]
            new_payload = result.nals[changed].ebsp[2:]
            assert len(new_payload) == len(orig_payload) + 3
            assert b"\x00\x00\x03" in new_payload
            return
        raise AssertionError("no seed exercised the insert branch")

    def test_drop_branch_removes_real_emulation_byte(self):
        # A "drop" mutation removes a genuine emulation-prevention byte: the
        # mutated NAL is exactly one byte shorter than the original.
        for seed in range(60):
            original = _seed_nals()
            result = get_mutator("nal-emulation-bytes")(original, random.Random(seed))
            if not result.detail.startswith("dropped emulation"):
                continue
            changed = next(
                i for i, (o, m) in enumerate(zip(original, result.nals))
                if o.ebsp != m.ebsp
            )
            assert len(result.nals[changed].ebsp) == len(original[changed].ebsp) - 1
            return
        raise AssertionError("no seed exercised the drop branch")

    def test_flood_branch_injects_high_density_pattern(self):
        # A "flood" mutation injects >=64 consecutive 0x000003 triplets,
        # reproducing the CVE-2022-32939 high-density EBSP pattern.
        for seed in range(60):
            original = _seed_nals()
            result = get_mutator("nal-emulation-bytes")(original, random.Random(seed))
            if "0x000003 emulation triplets" not in result.detail:
                continue
            changed = next(
                i for i, (o, m) in enumerate(zip(original, result.nals))
                if o.ebsp != m.ebsp
            )
            payload = result.nals[changed].ebsp[2:]
            # The payload head is a long run of 0x00 0x00 0x03 triplets.
            assert payload[:3] == b"\x00\x00\x03"
            # Count the leading triplet run.
            triplets = 0
            while payload[triplets * 3 : triplets * 3 + 3] == b"\x00\x00\x03":
                triplets += 1
            assert triplets >= 64, f"flood produced only {triplets} triplets"
            return
        raise AssertionError("no seed exercised the flood branch")

    def test_all_branches_reachable(self):
        branches = set()
        for seed in range(80):
            result = get_mutator("nal-emulation-bytes")(_seed_nals(), random.Random(seed))
            if result.detail.startswith("inserted phantom"):
                branches.add("insert")
            elif result.detail.startswith("dropped emulation"):
                branches.add("drop")
            elif "emulation triplets" in result.detail:
                branches.add("flood")
        assert branches == {"insert", "drop", "flood"}, f"only hit {branches}"

    def test_no_existing_emulation_byte_skips_drop(self):
        # A single NAL whose payload contains no emulation-prevention byte must
        # never produce a "drop" mutation (only insert / flood are valid).
        clean = NalUnit(
            start_code_len=4,
            offset=0,
            ebsp=bytes([0x40, 0x01]) + bytes(range(4, 40)),  # no 0x000003 anywhere
        )
        nals = [clean]
        for seed in range(40):
            result = get_mutator("nal-emulation-bytes")(nals, random.Random(seed))
            assert not result.detail.startswith("dropped emulation")


# --- Item: SPS feature-toggle flag mutator --------------------------------

FEATURE_FLAG_MUTATORS = {"sps-feature-flags"}


def _build_feature_flag_sps_rbsp(
    *,
    scaling_list_enabled: int = 0,
    pcm_enabled: int = 0,
) -> bytes:
    """A minimal SPS RBSP that parses through the feature-toggle flag region.

    Uses max_sub_layers_minus1 == 0 (fixed 96-bit profile_tier_level) and stops
    right after pcm_enabled_flag — far enough for the scaling-list and pcm spans.
    When pcm_enabled is 1 a minimal PCM config block is emitted so the parser does
    not run off the end before the flag span is recorded.
    """
    from mangle.bitstream import BitWriter

    w = BitWriter()
    w.write_bits(0, 4)  # sps_video_parameter_set_id
    w.write_bits(0, 3)  # sps_max_sub_layers_minus1 = 0
    w.write_bit(0)      # sps_temporal_id_nesting_flag
    w.write_bits(0, 8)   # profile_tier_level: profile_space/tier/profile_idc
    w.write_bits(0, 32)  # profile_compatibility_flag[32]
    w.write_bits(0, 48)  # constraint flags
    w.write_bits(0, 8)   # general_level_idc
    w.write_ue(0)        # sps_seq_parameter_set_id
    w.write_ue(1)        # chroma_format_idc (4:2:0, no separate-plane flag)
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
    w.write_bit(scaling_list_enabled)  # scaling_list_enabled_flag
    # When scaling lists are enabled the parser bails right after recording the
    # span, so we do not need to emit scaling_list_data() for the span to exist.
    w.write_bit(0)       # amp_enabled_flag
    w.write_bit(0)       # sample_adaptive_offset_enabled_flag
    w.write_bit(pcm_enabled)  # pcm_enabled_flag
    if pcm_enabled:
        w.write_bits(0, 4)  # pcm_sample_bit_depth_luma_minus1
        w.write_bits(0, 4)  # pcm_sample_bit_depth_chroma_minus1
        w.write_ue(0)       # log2_min_pcm_luma_coding_block_size_minus3
        w.write_ue(0)       # log2_diff_max_min_pcm_luma_coding_block_size
        w.write_bit(0)      # pcm_loop_filter_disabled_flag
    w.write_bit(1)       # rbsp_stop_one_bit
    return w.to_bytes()


def _feature_flag_stream(**kwargs) -> list[NalUnit]:
    sps_rbsp = _build_feature_flag_sps_rbsp(**kwargs)
    sps_nal = NalUnit(4, 0, bytes([(33 << 1), 0x01]) + rbsp_to_ebsp(sps_rbsp))
    vps_nal = NalUnit(4, 0, bytes([(32 << 1), 0x01]) + b"\x80")
    pps_nal = NalUnit(4, 0, bytes([(34 << 1), 0x01]) + b"\x80")
    return [vps_nal, sps_nal, pps_nal]


class TestSpsFeatureFlagsRegistered:
    def test_present(self):
        assert FEATURE_FLAG_MUTATORS.issubset(set(list_mutators()))

    def test_reproducible(self):
        r1 = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(7))
        r2 = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(7))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail


class TestSpsFeatureFlags:
    def test_parser_records_both_flag_spans(self):
        sps = parse_sps(_build_feature_flag_sps_rbsp())
        assert sps.has_span("scaling_list_enabled_flag")
        assert sps.has_span("pcm_enabled_flag")
        assert sps.scaling_list_enabled_flag == 0
        assert sps.pcm_enabled_flag == 0

    def test_clean_fixture_reaches_flags(self):
        # The bundled seed must parse through to the feature flags (both off),
        # which is what makes it a valid target for this mutator.
        sps_nal = next(n for n in _seed_nals() if n.nal_unit_type == 33)
        sps = parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))
        assert sps.scaling_list_enabled_flag == 0
        assert sps.pcm_enabled_flag == 0

    def test_changes_only_sps(self):
        original = _seed_nals()
        result = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue
            assert orig.ebsp == mut.ebsp, "non-SPS NAL modified"

    def test_flag_is_flipped_on(self):
        # Every produced mutant must have its targeted flag set to 1.
        for s in range(24):
            result = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(s))
            sps = _reparse_sps(result.nals)
            target = result.detail.split(":")[0]
            assert sps.span(target).value == 1, (target, s)

    def test_both_flags_reachable(self):
        targets = set()
        for s in range(40):
            result = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(s))
            if "scaling_list_enabled_flag" in result.detail:
                targets.add("scaling")
            if "pcm_enabled_flag" in result.detail:
                targets.add("pcm")
        assert targets == {"scaling", "pcm"}, f"only hit {targets}"

    def test_single_bit_change_preserves_length(self):
        # Flipping a u(1) flag must not shift the bitstream length.
        original = assemble_nal_units(_seed_nals())
        result = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(3))
        mutated = assemble_nal_units(result.nals)
        assert len(mutated) == len(original)
        assert result.bytes_changed >= 1

    def test_framing_integrity(self):
        result = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(1))
        mutated = assemble_nal_units(result.nals)
        # The NAL count must be unchanged (in-place flip, no injection).
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_only_offers_flags_that_are_off(self):
        # An SPS whose pcm flag is already on (but scaling-list off) must only
        # offer the scaling-list flag. (scaling_list=0 keeps the parser advancing
        # far enough to reach and record the pcm flag.)
        nals = _feature_flag_stream(scaling_list_enabled=0, pcm_enabled=1)
        sps = parse_sps(ebsp_to_rbsp(nals[1].ebsp[2:]))
        assert sps.scaling_list_enabled_flag == 0
        assert sps.pcm_enabled_flag == 1
        for s in range(20):
            result = get_mutator("sps-feature-flags")(nals, random.Random(s))
            assert "scaling_list_enabled_flag" in result.detail
            assert "pcm_enabled_flag" not in result.detail

    def test_raises_when_no_off_flag_available(self):
        # No reachable off-flag → no inconsistency to create → mutator bails so
        # the engine can pick another mutator. A stream truncated before the flag
        # region records no flag spans at all, the cleanest bail case.
        truncated = _truncated_pre_flag_stream()
        try:
            get_mutator("sps-feature-flags")(truncated, random.Random(0))
        except ValueError as exc:
            assert "feature flag" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError when no off-flag reachable")

    def test_result_name(self):
        result = get_mutator("sps-feature-flags")(_seed_nals(), random.Random(0))
        assert result.mutator == "sps-feature-flags"


def _truncated_pre_flag_stream() -> list[NalUnit]:
    """An SPS truncated before the feature-flag region (no flag spans recorded)."""
    from mangle.bitstream import BitWriter

    w = BitWriter()
    w.write_bits(0, 4)  # sps_video_parameter_set_id
    w.write_bits(0, 3)  # sps_max_sub_layers_minus1 = 0
    w.write_bit(0)      # sps_temporal_id_nesting_flag
    w.write_bits(0, 8)
    w.write_bits(0, 32)
    w.write_bits(0, 48)
    w.write_bits(0, 8)
    w.write_ue(0)        # sps_seq_parameter_set_id
    w.write_ue(1)        # chroma_format_idc
    w.write_ue(64)       # width
    w.write_ue(64)       # height
    # truncate here, before the conformance/bit-depth/flag region
    truncated = w.to_bytes()
    sps_view = parse_sps(truncated)
    assert not sps_view.has_span("scaling_list_enabled_flag")
    assert not sps_view.has_span("pcm_enabled_flag")
    sps_nal = NalUnit(4, 0, bytes([(33 << 1), 0x01]) + rbsp_to_ebsp(truncated))
    return [
        NalUnit(4, 0, bytes([(32 << 1), 0x01]) + b"\x80"),
        sps_nal,
        NalUnit(4, 0, bytes([(34 << 1), 0x01]) + b"\x80"),
    ]


VUI_HRD_MUTATORS = {"sps-vui-hrd"}


def _build_vui_sps_rbsp(
    *,
    vui_present: int = 1,
    timing_present: int = 1,
    hrd_present: int = 0,
) -> bytes:
    """A minimal SPS RBSP that parses through the VUI / HRD gate region.

    Builds the same prefix as :func:`_build_feature_flag_sps_rbsp` (both feature
    flags off, no RPS) and then emits the two post-RPS feature flags followed by a
    configurable VUI block. The early VUI sub-blocks are all written "absent" so
    the parser reaches the timing-info and HRD gates deterministically.
    """
    from mangle.bitstream import BitWriter

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
            # hrd_parameters() body omitted; parser stops at the gate.
    w.write_bit(1)       # rbsp_stop_one_bit
    return w.to_bytes()


def _vui_stream(**kwargs) -> list[NalUnit]:
    sps_rbsp = _build_vui_sps_rbsp(**kwargs)
    sps_nal = NalUnit(4, 0, bytes([(33 << 1), 0x01]) + rbsp_to_ebsp(sps_rbsp))
    vps_nal = NalUnit(4, 0, bytes([(32 << 1), 0x01]) + b"\x80")
    pps_nal = NalUnit(4, 0, bytes([(34 << 1), 0x01]) + b"\x80")
    return [vps_nal, sps_nal, pps_nal]


class TestSpsVuiHrdRegistered:
    def test_present(self):
        assert VUI_HRD_MUTATORS.issubset(set(list_mutators()))

    def test_reproducible(self):
        r1 = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(7))
        r2 = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(7))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_result_name(self):
        result = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(0))
        assert result.mutator == "sps-vui-hrd"


class TestSpsVuiHrdParsing:
    def test_parser_records_all_three_gate_spans(self):
        sps = parse_sps(_build_vui_sps_rbsp(hrd_present=0))
        assert sps.has_span("vui_parameters_present_flag")
        assert sps.has_span("vui_timing_info_present_flag")
        assert sps.has_span("vui_hrd_parameters_present_flag")
        assert sps.vui_parameters_present_flag == 1
        assert sps.vui_timing_info_present_flag == 1
        assert sps.vui_hrd_parameters_present_flag == 0

    def test_clean_fixture_reaches_hrd_gate(self):
        # The bundled seed must parse through to the HRD gate (off), which is what
        # makes it a valid target for this mutator.
        sps_nal = next(n for n in _seed_nals() if n.nal_unit_type == 33)
        sps = parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))
        assert sps.vui_parameters_present_flag == 1
        assert sps.vui_hrd_parameters_present_flag == 0

    def test_no_vui_records_only_outer_gate(self):
        # When VUI is absent the parser records only the outer gate (value 0) and
        # leaves the inner gates unset.
        sps = parse_sps(_build_vui_sps_rbsp(vui_present=0))
        assert sps.has_span("vui_parameters_present_flag")
        assert sps.vui_parameters_present_flag == 0
        assert not sps.has_span("vui_timing_info_present_flag")
        assert not sps.has_span("vui_hrd_parameters_present_flag")
        assert sps.vui_timing_info_present_flag is None

    def test_no_timing_records_only_two_gates(self):
        sps = parse_sps(_build_vui_sps_rbsp(timing_present=0))
        assert sps.vui_parameters_present_flag == 1
        assert sps.vui_timing_info_present_flag == 0
        assert not sps.has_span("vui_hrd_parameters_present_flag")


class TestSpsVuiHrdMutator:
    def test_changes_only_sps(self):
        original = _seed_nals()
        result = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue
            assert orig.ebsp == mut.ebsp, "non-SPS NAL modified"

    def test_gate_is_flipped_on(self):
        for s in range(24):
            result = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(s))
            sps = _reparse_sps(result.nals)
            target = result.detail.split(":")[0]
            assert sps.span(target).value == 1, (target, s)

    def test_single_bit_change_preserves_length(self):
        original = assemble_nal_units(_seed_nals())
        result = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(3))
        mutated = assemble_nal_units(result.nals)
        assert len(mutated) == len(original)
        assert result.bytes_changed >= 1

    def test_framing_integrity(self):
        result = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(1))
        mutated = assemble_nal_units(result.nals)
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_prefers_hrd_gate_when_off(self):
        # The clean fixture has the HRD gate off and both outer gates on, so the
        # HRD gate is the only off candidate and must always be chosen.
        for s in range(24):
            result = get_mutator("sps-vui-hrd")(_seed_nals(), random.Random(s))
            assert "vui_hrd_parameters_present_flag" in result.detail

    def test_all_three_gates_reachable_across_seeds(self):
        # A synthetic SPS with every gate off (no VUI) exposes the outer gate; a
        # stream with VUI+timing on but HRD off exposes the HRD gate; a stream with
        # VUI on but timing off exposes the timing gate. Each yields its lone
        # off-candidate, exercising all three branches.
        no_vui = _vui_stream(vui_present=0)
        for s in range(8):
            r = get_mutator("sps-vui-hrd")(no_vui, random.Random(s))
            assert "vui_parameters_present_flag" in r.detail

        no_timing = _vui_stream(timing_present=0)
        for s in range(8):
            r = get_mutator("sps-vui-hrd")(no_timing, random.Random(s))
            assert "vui_timing_info_present_flag" in r.detail

        hrd_off = _vui_stream(hrd_present=0)
        for s in range(8):
            r = get_mutator("sps-vui-hrd")(hrd_off, random.Random(s))
            assert "vui_hrd_parameters_present_flag" in r.detail

    def test_raises_when_no_off_gate_available(self):
        # All reachable gates on → no inconsistency to create → mutator bails.
        all_on = _vui_stream(vui_present=1, timing_present=1, hrd_present=1)
        try:
            get_mutator("sps-vui-hrd")(all_on, random.Random(0))
        except ValueError as exc:
            assert "vui" in str(exc).lower() or "hrd" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError when no off-gate reachable")


REXT_MUTATORS = {"sps-rext-flags"}


def _build_rext_sps_rbsp(
    *,
    vui_present: int = 0,
    timing_present: int = 1,
    hrd_present: int = 0,
    ext_present: int = 0,
    rext_flag: int = 0,
) -> bytes:
    """A minimal SPS RBSP that parses through to the SPS extension gate region.

    Builds the same RPS-free prefix as :func:`_build_vui_sps_rbsp`, then emits a
    configurable VUI block (tail with ``bitstream_restriction_flag`` absent) and a
    configurable extension region (H.265 §7.3.2.2.1). With ``vui_present=0`` the
    extension gate follows the VUI gate directly — the deterministic path used to
    exercise every off/on gate combination the mutator can encounter.
    """
    from mangle.bitstream import BitWriter

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
                # hrd_parameters() body omitted; parser stops before the
                # extension region for this combination.
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


def _rext_stream(**kwargs) -> list[NalUnit]:
    sps_rbsp = _build_rext_sps_rbsp(**kwargs)
    sps_nal = NalUnit(4, 0, bytes([(33 << 1), 0x01]) + rbsp_to_ebsp(sps_rbsp))
    vps_nal = NalUnit(4, 0, bytes([(32 << 1), 0x01]) + b"\x80")
    pps_nal = NalUnit(4, 0, bytes([(34 << 1), 0x01]) + b"\x80")
    return [vps_nal, sps_nal, pps_nal]


class TestSpsRextFlagsRegistered:
    def test_present(self):
        assert REXT_MUTATORS.issubset(set(list_mutators()))

    def test_reproducible(self):
        r1 = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(7))
        r2 = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(7))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_result_name(self):
        result = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(0))
        assert result.mutator == "sps-rext-flags"


class TestSpsRextFlagsMutator:
    def test_changes_only_sps(self):
        original = _seed_nals()
        result = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 33:
                continue
            assert orig.ebsp == mut.ebsp, "non-SPS NAL modified"

    def test_gate_is_flipped_on(self):
        for s in range(24):
            result = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(s))
            sps = _reparse_sps(result.nals)
            target = result.detail.split(":")[0]
            assert sps.span(target).value == 1, (target, s)

    def test_single_bit_change_preserves_length(self):
        original = assemble_nal_units(_seed_nals())
        result = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(3))
        mutated = assemble_nal_units(result.nals)
        assert len(mutated) == len(original)
        assert result.bytes_changed >= 1

    def test_framing_integrity(self):
        result = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(1))
        mutated = assemble_nal_units(result.nals)
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_clean_fixture_uses_extension_present_gate(self):
        # The bundled seed has no SPS extension, so sps_extension_present_flag is
        # the lone off candidate and must always be the chosen gate.
        for s in range(24):
            result = get_mutator("sps-rext-flags")(_seed_nals(), random.Random(s))
            assert "sps_extension_present_flag" in result.detail

    def test_prefers_range_extension_gate_when_off(self):
        # An SPS that already has the extension region present but the
        # range-extension flag off exposes both gates; the mutator must prefer the
        # range-extension flag (it lands directly in RExt handling).
        stream = _rext_stream(vui_present=0, ext_present=1, rext_flag=0)
        for s in range(16):
            r = get_mutator("sps-rext-flags")(stream, random.Random(s))
            assert "sps_range_extension_flag" in r.detail

    def test_extension_present_gate_when_no_extension(self):
        # No extension region at all → only the outer gate is an off candidate.
        stream = _rext_stream(vui_present=0, ext_present=0)
        for s in range(16):
            r = get_mutator("sps-rext-flags")(stream, random.Random(s))
            assert "sps_extension_present_flag" in r.detail

    def test_raises_when_no_off_gate_available(self):
        # Extension present AND range-extension flag already on → no off gate.
        all_on = _rext_stream(vui_present=0, ext_present=1, rext_flag=1)
        try:
            get_mutator("sps-rext-flags")(all_on, random.Random(0))
        except ValueError as exc:
            assert "rext" in str(exc).lower() or "extension" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError when no off-gate reachable")

    def test_hrd_present_seed_cannot_reach_extension(self):
        # When the seed's HRD gate is on, the parser cannot walk to the extension
        # region, so the mutator has no gate and must raise.
        hrd_on = _rext_stream(vui_present=1, timing_present=1, hrd_present=1)
        try:
            get_mutator("sps-rext-flags")(hrd_on, random.Random(0))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError when extension unreachable")


PPS_EXTENSION_MUTATORS = {"pps-extension-flags"}


def _build_ext_pps_rbsp(
    *,
    scaling_list_present: int = 0,
    lists_modification: int = 0,
    pps_extension_present: int = 0,
) -> bytes:
    """A minimal no-tiles PPS RBSP reaching the extension gate region.

    ``scaling_list_present`` / ``pps_extension_present`` set the two gates so the
    parse/mutate paths around an already-on gate can be exercised. When the
    scaling-list gate is on its body is not modelled, so the parser stops there
    and ``pps_extension_present`` is unreachable (matching the real parser).
    """
    from mangle.bitstream import BitWriter

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
    w.write_se(0)  # init_qp_minus26
    w.write_bit(0)  # constrained_intra_pred_flag
    w.write_bit(0)  # transform_skip_enabled_flag
    w.write_bit(0)  # cu_qp_delta_enabled_flag
    w.write_se(0)  # pps_cb_qp_offset
    w.write_se(0)  # pps_cr_qp_offset
    w.write_bit(0)  # pps_slice_chroma_qp_offsets_present_flag
    w.write_bit(0)  # weighted_pred_flag
    w.write_bit(0)  # weighted_bipred_flag
    w.write_bit(0)  # transquant_bypass_enabled_flag
    w.write_bit(0)  # tiles_enabled_flag
    w.write_bit(0)  # entropy_coding_sync_enabled_flag
    w.write_bit(1)  # pps_loop_filter_across_slices_enabled_flag
    w.write_bit(0)  # deblocking_filter_control_present_flag
    w.write_bit(scaling_list_present)  # pps_scaling_list_data_present_flag
    w.write_bit(lists_modification)  # lists_modification_present_flag
    w.write_ue(0)  # log2_parallel_merge_level_minus2
    w.write_bit(0)  # slice_segment_header_extension_present_flag
    w.write_bit(pps_extension_present)  # pps_extension_present_flag
    w.write_bit(1)  # rbsp_stop_one_bit
    return w.to_bytes()


def _ext_pps_stream(**kwargs) -> list[NalUnit]:
    """A VPS+SPS+PPS stream whose PPS reaches the extension gate region."""
    seed = _seed_nals()
    sps = next(n for n in seed if n.nal_unit_type == 33)
    pps_header = bytes([(34 << 1), 0x01])
    pps_rbsp = _build_ext_pps_rbsp(**kwargs)
    pps_nal = NalUnit(4, 0, pps_header + rbsp_to_ebsp(pps_rbsp))
    vps_header = bytes([(32 << 1), 0x01])
    return [
        NalUnit(4, 0, vps_header + b"\x80"),
        NalUnit(4, 0, sps.ebsp),
        pps_nal,
    ]


class TestPpsExtensionFlagsRegistered:
    def test_present(self):
        assert PPS_EXTENSION_MUTATORS.issubset(set(list_mutators()))

    def test_reproducible(self):
        r1 = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(7))
        r2 = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(7))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_result_name(self):
        result = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(0))
        assert result.mutator == "pps-extension-flags"


class TestPpsExtensionFlagsMutator:
    def test_changes_bytes_on_seed(self):
        original = SEED.read_bytes()
        result = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated != original
        assert result.bytes_changed > 0
        assert result.detail

    def test_changes_only_pps(self):
        original = _seed_nals()
        result = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 34:
                continue
            assert orig.ebsp == mut.ebsp, "non-PPS NAL modified"

    def test_gate_is_flipped_on(self):
        # Whichever gate the mutator names, it must re-parse as 1. (When the
        # scaling-list gate is chosen its on-state hides the extension gate, so we
        # only assert the chosen gate's value.)
        for s in range(24):
            result = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(s))
            pps = _reparse_pps(result.nals)
            target = result.detail.split(":")[0]
            assert pps.span(target).value == 1, (target, s)

    def test_single_bit_change_preserves_length(self):
        original = assemble_nal_units(_seed_nals())
        result = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(3))
        mutated = assemble_nal_units(result.nals)
        assert len(mutated) == len(original)
        assert result.bytes_changed >= 1

    def test_framing_integrity(self):
        result = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(1))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_seed_exposes_both_off_gates(self):
        # The bundled seed has both gates off, so over many seeds the mutator must
        # exercise both branches (extension is preferred but scaling can be picked).
        targets = set()
        for s in range(64):
            result = get_mutator("pps-extension-flags")(_seed_nals(), random.Random(s))
            targets.add(result.detail.split(":")[0])
        assert targets == {
            "pps_scaling_list_data_present_flag",
            "pps_extension_present_flag",
        }

    def test_prefers_extension_gate_when_scaling_already_on(self):
        # Scaling-list gate on hides the extension gate, but here we set scaling
        # off and extension on: only the scaling gate is an off candidate, so it
        # must be chosen.
        stream = _ext_pps_stream(scaling_list_present=0, pps_extension_present=1)
        for s in range(16):
            r = get_mutator("pps-extension-flags")(stream, random.Random(s))
            assert "pps_scaling_list_data_present_flag" in r.detail

    def test_raises_when_no_off_gate_available(self):
        # Scaling-list gate on → its body is unmodelled, the parser stops, and the
        # only reachable gate is already on, so no off gate remains.
        stream = _ext_pps_stream(scaling_list_present=1)
        try:
            get_mutator("pps-extension-flags")(stream, random.Random(0))
        except ValueError as exc:
            assert "extension" in str(exc).lower() or "scaling" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError when no off-gate reachable")

    def test_tiles_enabled_pps_raises(self):
        # A tiled PPS never reaches the extension gates (variable tile geometry),
        # so the mutator must raise so the engine can pick another.
        nals = _deblocking_stream(ctl_present=0)
        # Flip tiles on via the deblocking helper's stream by building a tiled PPS.
        from mangle.bitstream import BitWriter

        w = BitWriter()
        w.write_ue(0)  # pps_pic_parameter_set_id
        w.write_ue(0)  # pps_seq_parameter_set_id
        w.write_bit(0)
        w.write_bit(0)
        w.write_bits(0, 3)
        w.write_bit(0)
        w.write_bit(0)
        w.write_ue(0)
        w.write_ue(0)
        w.write_se(0)  # init_qp_minus26
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_se(0)
        w.write_se(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(1)  # tiles_enabled_flag = 1
        w.write_bit(0)
        w.write_bit(1)  # rbsp_stop_one_bit (truncated; tiles geometry not modelled)
        tiled_rbsp = w.to_bytes()
        sps = next(n for n in _seed_nals() if n.nal_unit_type == 33)
        pps_header = bytes([(34 << 1), 0x01])
        pps_nal = NalUnit(4, 0, pps_header + rbsp_to_ebsp(tiled_rbsp))
        vps_header = bytes([(32 << 1), 0x01])
        nals = [
            NalUnit(4, 0, vps_header + b"\x80"),
            NalUnit(4, 0, sps.ebsp),
            pps_nal,
        ]
        try:
            get_mutator("pps-extension-flags")(nals, random.Random(0))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for a tiled PPS")


def _irap_slice_no_output(nals):
    """Read the no_output_of_prior_pics_flag of the first IRAP slice in a stream."""
    nal = next(n for n in nals if 16 <= n.nal_unit_type <= 23)
    sh = parse_slice_header(ebsp_to_rbsp(nal.ebsp[2:]), nal.nal_unit_type)
    return sh.no_output_of_prior_pics_flag


class TestSliceNoOutputPriorPicsRegistered:
    def test_present(self):
        assert "slice-no-output-prior-pics" in list_mutators()

    def test_result_name(self):
        r = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(0))
        assert r.mutator == "slice-no-output-prior-pics"

    def test_reproducible(self):
        r1 = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(42))
        r2 = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(42))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail


class TestSliceNoOutputPriorPicsMutator:
    def test_changes_bytes_on_seed(self):
        original = SEED.read_bytes()
        result = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(1))
        assert result.bytes_changed > 0
        assert assemble_nal_units(result.nals) != original

    def test_detail_is_nonempty(self):
        result = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(0))
        assert result.detail
        assert "no_output_of_prior_pics_flag" in result.detail

    def test_flag_is_flipped(self):
        original_flag = _irap_slice_no_output(_seed_nals())
        result = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(3))
        mutated_flag = _irap_slice_no_output(result.nals)
        assert mutated_flag == 1 - original_flag

    def test_single_bit_change_preserves_length(self):
        original = SEED.read_bytes()
        result = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(5))
        mutated = assemble_nal_units(result.nals)
        # A 1-bit flip never changes the stream length.
        assert len(mutated) == len(original)

    def test_changes_only_slice_nal(self):
        original = _seed_nals()
        result = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(9))
        for orig, mut in zip(original, result.nals):
            if 16 <= orig.nal_unit_type <= 23:
                continue  # IRAP slice may change
            assert orig.ebsp == mut.ebsp, (
                f"non-IRAP NAL type {orig.nal_unit_type} was modified"
            )

    def test_framing_integrity(self):
        result = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(7))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_idempotent_under_double_application(self):
        # Flipping the flag twice restores the original stream.
        once = get_mutator("slice-no-output-prior-pics")(_seed_nals(), random.Random(0))
        twice = get_mutator("slice-no-output-prior-pics")(once.nals, random.Random(0))
        assert assemble_nal_units(twice.nals) == SEED.read_bytes()

    def test_raises_when_no_irap_slice(self):
        # Build a stream whose only VCL slice is a non-IRAP type (TRAIL_R = 1).
        nals = _seed_nals()
        rebuilt = []
        for n in nals:
            if 16 <= n.nal_unit_type <= 23:
                # Relabel the IRAP slice as TRAIL_R (type 1) via the header byte.
                header0 = (n.ebsp[0] & 0x81) | (1 << 1)
                rebuilt.append(NalUnit(n.start_code_len, n.offset, bytes([header0]) + n.ebsp[1:]))
            else:
                rebuilt.append(n)
        try:
            get_mutator("slice-no-output-prior-pics")(rebuilt, random.Random(0))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError when no IRAP slice is present")


class TestPpsSliceHeaderExtensionRegistered:
    def test_present(self):
        assert "pps-slice-header-extension" in list_mutators()

    def test_reproducible(self):
        r1 = get_mutator("pps-slice-header-extension")(_seed_nals(), random.Random(7))
        r2 = get_mutator("pps-slice-header-extension")(_seed_nals(), random.Random(7))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_result_name(self):
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(0)
        )
        assert result.mutator == "pps-slice-header-extension"


class TestPpsSliceHeaderExtensionMutator:
    def test_changes_bytes_on_seed(self):
        original = SEED.read_bytes()
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(0)
        )
        mutated = assemble_nal_units(result.nals)
        assert mutated != original
        assert result.bytes_changed > 0
        assert result.detail

    def test_gate_is_flipped_on(self):
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(3)
        )
        pps = _reparse_pps(result.nals)
        assert pps.slice_segment_header_extension_present_flag == 1

    def test_detail_names_the_gate(self):
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(0)
        )
        assert "slice_segment_header_extension_present_flag" in result.detail

    def test_changes_only_pps(self):
        original = _seed_nals()
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(0)
        )
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 34:
                continue
            assert orig.ebsp == mut.ebsp, "non-PPS NAL modified"

    def test_single_bit_change_preserves_length(self):
        original = assemble_nal_units(_seed_nals())
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(3)
        )
        mutated = assemble_nal_units(result.nals)
        assert len(mutated) == len(original)
        assert result.bytes_changed >= 1

    def test_neighbouring_extension_gate_untouched(self):
        # Flipping the slice-header gate must not disturb pps_extension_present_flag.
        original_pps = _reparse_pps(_seed_nals())
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(5)
        )
        mutated_pps = _reparse_pps(result.nals)
        assert (
            mutated_pps.pps_extension_present_flag
            == original_pps.pps_extension_present_flag
        )

    def test_framing_integrity(self):
        result = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(1)
        )
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_double_application_raises(self):
        # After the first flip the gate is on; a second application must raise,
        # since the gate-on desync needs an off gate.
        first = get_mutator("pps-slice-header-extension")(
            _seed_nals(), random.Random(1)
        )
        try:
            get_mutator("pps-slice-header-extension")(first.nals, random.Random(1))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError when the gate is already on")

    def test_raises_when_gate_already_on(self):
        # A PPS whose slice-header extension gate is already set offers no off gate.
        stream = _ext_pps_stream()
        # Pre-flip the gate on so the mutator must refuse.
        first = get_mutator("pps-slice-header-extension")(stream, random.Random(0))
        try:
            get_mutator("pps-slice-header-extension")(first.nals, random.Random(0))
        except ValueError as exc:
            assert "already" in str(exc).lower() or "off gate" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError when gate already on")

    def test_tiles_enabled_pps_raises(self):
        # A tiled PPS never reaches the slice-header extension gate, so the mutator
        # must raise so the engine can pick another.
        from mangle.bitstream import BitWriter

        w = BitWriter()
        w.write_ue(0)  # pps_pic_parameter_set_id
        w.write_ue(0)  # pps_seq_parameter_set_id
        w.write_bit(0)
        w.write_bit(0)
        w.write_bits(0, 3)
        w.write_bit(0)
        w.write_bit(0)
        w.write_ue(0)
        w.write_ue(0)
        w.write_se(0)  # init_qp_minus26
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_se(0)
        w.write_se(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(1)  # tiles_enabled_flag = 1
        w.write_bit(0)
        w.write_bit(1)  # rbsp_stop_one_bit (truncated; tile geometry not modelled)
        tiled_rbsp = w.to_bytes()
        sps = next(n for n in _seed_nals() if n.nal_unit_type == 33)
        pps_header = bytes([(34 << 1), 0x01])
        pps_nal = NalUnit(4, 0, pps_header + rbsp_to_ebsp(tiled_rbsp))
        vps_header = bytes([(32 << 1), 0x01])
        nals = [
            NalUnit(4, 0, vps_header + b"\x80"),
            NalUnit(4, 0, sps.ebsp),
            pps_nal,
        ]
        try:
            get_mutator("pps-slice-header-extension")(nals, random.Random(0))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for a tiled PPS")


class TestPpsListsModificationRegistered:
    def test_present(self):
        assert "pps-lists-modification" in list_mutators()

    def test_reproducible(self):
        r1 = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(7))
        r2 = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(7))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_result_name(self):
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(0))
        assert result.mutator == "pps-lists-modification"


class TestPpsListsModificationMutator:
    def test_changes_bytes_on_seed(self):
        original = SEED.read_bytes()
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(0))
        mutated = assemble_nal_units(result.nals)
        assert mutated != original
        assert result.bytes_changed > 0
        assert result.detail

    def test_gate_is_flipped_on(self):
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(3))
        pps = _reparse_pps(result.nals)
        assert pps.lists_modification_present_flag == 1

    def test_detail_names_the_gate(self):
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(0))
        assert "lists_modification_present_flag" in result.detail

    def test_changes_only_pps(self):
        original = _seed_nals()
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(0))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 34:
                continue
            assert orig.ebsp == mut.ebsp, "non-PPS NAL modified"

    def test_single_bit_change_preserves_length(self):
        original = assemble_nal_units(_seed_nals())
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(3))
        mutated = assemble_nal_units(result.nals)
        assert len(mutated) == len(original)
        assert result.bytes_changed >= 1

    def test_neighbouring_slice_header_gate_untouched(self):
        # Flipping the lists-modification gate must not disturb the neighbouring
        # slice_segment_header_extension_present_flag.
        original_pps = _reparse_pps(_seed_nals())
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(5))
        mutated_pps = _reparse_pps(result.nals)
        assert (
            mutated_pps.slice_segment_header_extension_present_flag
            == original_pps.slice_segment_header_extension_present_flag
        )

    def test_framing_integrity(self):
        result = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(1))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_double_application_raises(self):
        # After the first flip the gate is on; a second application must raise,
        # since the gate-on desync needs an off gate.
        first = get_mutator("pps-lists-modification")(_seed_nals(), random.Random(1))
        try:
            get_mutator("pps-lists-modification")(first.nals, random.Random(1))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError when the gate is already on")

    def test_raises_when_gate_already_on(self):
        # A PPS whose lists-modification gate is already set offers no off gate.
        stream = _ext_pps_stream(lists_modification=1)
        try:
            get_mutator("pps-lists-modification")(stream, random.Random(0))
        except ValueError as exc:
            assert "already" in str(exc).lower() or "off gate" in str(exc).lower()
        else:
            raise AssertionError("expected ValueError when gate already on")

    def test_scaling_list_gate_on_raises(self):
        # When the scaling-list gate is on the parser cannot reach the
        # lists-modification gate, so the mutator must raise.
        stream = _ext_pps_stream(scaling_list_present=1)
        try:
            get_mutator("pps-lists-modification")(stream, random.Random(0))
        except ValueError:
            pass
        else:
            raise AssertionError(
                "expected ValueError when scaling-list gate blocks the walk"
            )

    def test_tiles_enabled_pps_raises(self):
        # A tiled PPS never reaches the lists-modification gate, so the mutator
        # must raise so the engine can pick another.
        from mangle.bitstream import BitWriter

        w = BitWriter()
        w.write_ue(0)  # pps_pic_parameter_set_id
        w.write_ue(0)  # pps_seq_parameter_set_id
        w.write_bit(0)
        w.write_bit(0)
        w.write_bits(0, 3)
        w.write_bit(0)
        w.write_bit(0)
        w.write_ue(0)
        w.write_ue(0)
        w.write_se(0)  # init_qp_minus26
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_se(0)
        w.write_se(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(0)
        w.write_bit(1)  # tiles_enabled_flag = 1
        w.write_bit(0)
        w.write_bit(1)  # rbsp_stop_one_bit (truncated; tile geometry not modelled)
        tiled_rbsp = w.to_bytes()
        sps = next(n for n in _seed_nals() if n.nal_unit_type == 33)
        pps_header = bytes([(34 << 1), 0x01])
        pps_nal = NalUnit(4, 0, pps_header + rbsp_to_ebsp(tiled_rbsp))
        vps_header = bytes([(32 << 1), 0x01])
        nals = [
            NalUnit(4, 0, vps_header + b"\x80"),
            NalUnit(4, 0, sps.ebsp),
            pps_nal,
        ]
        try:
            get_mutator("pps-lists-modification")(nals, random.Random(0))
        except ValueError:
            pass
        else:
            raise AssertionError("expected ValueError for a tiled PPS")
