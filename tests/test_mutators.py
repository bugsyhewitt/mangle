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
from mangle.hevc import parse_pps, parse_sei, parse_sps
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
