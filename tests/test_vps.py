"""Tests for parse_vps() and the vps-layer-count mutator."""

from __future__ import annotations

import random
from pathlib import Path

from mangle.bitstream import (
    START_CODE_LONG,
    START_CODE_SHORT,
    assemble_nal_units,
    ebsp_to_rbsp,
    rbsp_to_ebsp,
    split_nal_units,
)
from mangle.hevc import FieldSpan, VideoParameterSet, parse_vps, splice_fixed_bits
from mangle.mutators import get_mutator

SEED = Path(__file__).parent / "fixtures" / "clean.h265"

# A minimal synthetic VPS RBSP for unit tests (no real stream needed).
# Bits:  vps_id(4)=0  base_int(1)=1  base_avail(1)=1
#        max_layers(6)=0  max_sub(3)=0  nesting(1)=1  … padding
# Byte 0: 0000 1100 = 0x0C
# Byte 1: 0000 0001 = 0x01  (bit 8..15: 000 | 000 | 1 = wait, let's recompute)
# Layout of first 16 bits:
#  [0..3]  = vps_id = 0000
#  [4]     = base_int = 1
#  [5]     = base_avail = 1
#  [6..11] = max_layers = 000000
#  [12..14]= max_sub = 000
#  [15]    = nesting = 1
# => 0000 1100 0000 0001 = 0x0C 0x01
_SYNTHETIC_VPS_RBSP = bytes([0x0C, 0x01]) + bytes(17)  # 19 bytes total, matching fixture len


def _seed_nals():
    return split_nal_units(SEED.read_bytes())


def _vps_rbsp_from_seed():
    nals = _seed_nals()
    vps_nal = next(n for n in nals if n.nal_unit_type == 32)
    return ebsp_to_rbsp(vps_nal.ebsp[2:])


# ---------------------------------------------------------------------------
# parse_vps tests
# ---------------------------------------------------------------------------


class TestParseVps:
    def test_parses_seed_vps(self):
        rbsp = _vps_rbsp_from_seed()
        vps = parse_vps(rbsp)
        assert isinstance(vps, VideoParameterSet)
        assert vps.vps_id == 0
        # Seed is a simple single-layer stream
        assert vps.vps_max_layers_minus1 == 0
        assert vps.vps_max_sub_layers_minus1 == 0
        # Nesting flag should be 1 (conformant: required when sub_layers=0)
        assert vps.vps_temporal_id_nesting_flag == 1

    def test_all_three_spans_present(self):
        rbsp = _vps_rbsp_from_seed()
        vps = parse_vps(rbsp)
        assert vps.span("vps_max_layers_minus1").bit_length == 6
        assert vps.span("vps_max_sub_layers_minus1").bit_length == 3
        assert vps.span("vps_temporal_id_nesting_flag").bit_length == 1

    def test_span_offsets_are_ordered(self):
        rbsp = _vps_rbsp_from_seed()
        vps = parse_vps(rbsp)
        layers_off = vps.span("vps_max_layers_minus1").bit_offset
        sub_off = vps.span("vps_max_sub_layers_minus1").bit_offset
        nesting_off = vps.span("vps_temporal_id_nesting_flag").bit_offset
        assert layers_off < sub_off < nesting_off

    def test_synthetic_vps_fields(self):
        vps = parse_vps(_SYNTHETIC_VPS_RBSP)
        assert vps.vps_id == 0
        assert vps.vps_max_layers_minus1 == 0
        assert vps.vps_max_sub_layers_minus1 == 0
        assert vps.vps_temporal_id_nesting_flag == 1

    def test_splice_max_layers(self):
        rbsp = _vps_rbsp_from_seed()
        vps = parse_vps(rbsp)
        span = vps.span("vps_max_layers_minus1")
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 63)
        reparsed = parse_vps(new_rbsp)
        assert reparsed.vps_max_layers_minus1 == 63
        # Other fields must be unchanged
        assert reparsed.vps_max_sub_layers_minus1 == vps.vps_max_sub_layers_minus1
        assert reparsed.vps_temporal_id_nesting_flag == vps.vps_temporal_id_nesting_flag

    def test_splice_max_sub_layers(self):
        rbsp = _vps_rbsp_from_seed()
        vps = parse_vps(rbsp)
        span = vps.span("vps_max_sub_layers_minus1")
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, 7)
        reparsed = parse_vps(new_rbsp)
        assert reparsed.vps_max_sub_layers_minus1 == 7
        assert reparsed.vps_max_layers_minus1 == vps.vps_max_layers_minus1

    def test_splice_nesting_flag(self):
        rbsp = _vps_rbsp_from_seed()
        vps = parse_vps(rbsp)
        span = vps.span("vps_temporal_id_nesting_flag")
        flipped = 1 - vps.vps_temporal_id_nesting_flag
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, flipped)
        reparsed = parse_vps(new_rbsp)
        assert reparsed.vps_temporal_id_nesting_flag == flipped

    def test_missing_vps_key_raises(self):
        rbsp = _vps_rbsp_from_seed()
        vps = parse_vps(rbsp)
        try:
            vps.span("nonexistent_field")
        except KeyError:
            pass
        else:
            raise AssertionError("expected KeyError for missing span name")


# ---------------------------------------------------------------------------
# vps-layer-count mutator tests
# ---------------------------------------------------------------------------


class TestVpsLayerCountRegistered:
    def test_mutator_is_registered(self):
        from mangle.mutators import list_mutators
        assert "vps-layer-count" in list_mutators()


class TestVpsLayerCountNoVps:
    def test_raises_when_no_vps_present(self):
        # Build a stream with only SPS + PPS (no VPS).
        nals = _seed_nals()
        nals_no_vps = [n for n in nals if n.nal_unit_type != 32]
        rng = random.Random(1)
        try:
            get_mutator("vps-layer-count")(nals_no_vps, rng)
        except (ValueError, KeyError):
            pass  # expected — no VPS in stream
        else:
            raise AssertionError("expected an error when no VPS NAL is present")


class TestVpsLayerCountMutation:
    def test_produces_change(self):
        original = SEED.read_bytes()
        rng = random.Random(42)
        result = get_mutator("vps-layer-count")(_seed_nals(), rng)
        assert result.bytes_changed > 0
        assert assemble_nal_units(result.nals) != original

    def test_detail_is_nonempty(self):
        result = get_mutator("vps-layer-count")(_seed_nals(), random.Random(0))
        assert result.detail

    def test_mutator_name_in_result(self):
        result = get_mutator("vps-layer-count")(_seed_nals(), random.Random(0))
        assert result.mutator == "vps-layer-count"

    def test_only_vps_nal_changes(self):
        original = _seed_nals()
        result = get_mutator("vps-layer-count")(_seed_nals(), random.Random(42))
        for orig, mut in zip(original, result.nals):
            if orig.nal_unit_type == 32:
                continue  # VPS may change
            assert orig.ebsp == mut.ebsp, f"non-VPS NAL type {orig.nal_unit_type} was modified"

    def test_framing_intact(self):
        result = get_mutator("vps-layer-count")(_seed_nals(), random.Random(42))
        mutated = assemble_nal_units(result.nals)
        assert mutated[:4] == START_CODE_LONG or mutated[:3] == START_CODE_SHORT
        assert len(split_nal_units(mutated)) == len(_seed_nals())

    def test_reproducible(self):
        r1 = get_mutator("vps-layer-count")(_seed_nals(), random.Random(42))
        r2 = get_mutator("vps-layer-count")(_seed_nals(), random.Random(42))
        assert assemble_nal_units(r1.nals) == assemble_nal_units(r2.nals)
        assert r1.detail == r2.detail

    def test_different_seeds_can_differ(self):
        outputs = set()
        for seed in range(20):
            r = get_mutator("vps-layer-count")(_seed_nals(), random.Random(seed))
            outputs.add(assemble_nal_units(r.nals))
        assert len(outputs) > 1, "expected some variation across seeds"


class TestVpsLayerCountMaxLayers:
    def test_max_layers_mutation_sets_field_to_63(self):
        # Force mutation 0 (max_layers overflow) by scanning seeds
        for seed in range(50):
            result = get_mutator("vps-layer-count")(_seed_nals(), random.Random(seed))
            if "vps_max_layers_minus1" in result.detail:
                mutated = assemble_nal_units(result.nals)
                vps_nal = next(n for n in split_nal_units(mutated) if n.nal_unit_type == 32)
                vps = parse_vps(ebsp_to_rbsp(vps_nal.ebsp[2:]))
                assert vps.vps_max_layers_minus1 >= 63, (
                    f"vps_max_layers_minus1={vps.vps_max_layers_minus1} should be >= 63"
                )
                return
        raise AssertionError("no seed exercised the vps_max_layers_minus1 mutation path")


class TestVpsLayerCountMaxSubLayers:
    def test_max_sub_layers_mutation_sets_field_to_7(self):
        for seed in range(50):
            result = get_mutator("vps-layer-count")(_seed_nals(), random.Random(seed))
            if "vps_max_sub_layers_minus1" in result.detail:
                mutated = assemble_nal_units(result.nals)
                vps_nal = next(n for n in split_nal_units(mutated) if n.nal_unit_type == 32)
                vps = parse_vps(ebsp_to_rbsp(vps_nal.ebsp[2:]))
                assert vps.vps_max_sub_layers_minus1 == 7, (
                    f"vps_max_sub_layers_minus1={vps.vps_max_sub_layers_minus1} should be 7"
                )
                return
        raise AssertionError("no seed exercised the vps_max_sub_layers_minus1 mutation path")


class TestVpsLayerCountNestingFlag:
    def test_nesting_flag_flip_works(self):
        for seed in range(50):
            result = get_mutator("vps-layer-count")(_seed_nals(), random.Random(seed))
            if "vps_temporal_id_nesting_flag" in result.detail:
                # Parse the original VPS nesting flag
                original_vps = parse_vps(_vps_rbsp_from_seed())
                expected_flip = 1 - original_vps.vps_temporal_id_nesting_flag
                # Parse the mutated VPS
                mutated = assemble_nal_units(result.nals)
                vps_nal = next(n for n in split_nal_units(mutated) if n.nal_unit_type == 32)
                mutated_vps = parse_vps(ebsp_to_rbsp(vps_nal.ebsp[2:]))
                assert mutated_vps.vps_temporal_id_nesting_flag == expected_flip, (
                    f"nesting flag should be {expected_flip}, got {mutated_vps.vps_temporal_id_nesting_flag}"
                )
                assert mutated_vps.vps_max_sub_layers_minus1 == 0, (
                    "sub_layers should be clamped to 0 in the nesting-flag mutation"
                )
                return
        raise AssertionError("no seed exercised the vps_temporal_id_nesting_flag mutation path")
