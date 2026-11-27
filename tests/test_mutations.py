"""Tests for mutation strategy properties, boundary values, and encoding invariants.

Complements test_mutators.py (which tests each mutator's functional output) by
verifying cross-cutting properties: stream integrity, determinism, encoding
round-trips, and boundary behaviour.
"""

from __future__ import annotations

import random
from pathlib import Path

import pytest

from mangle.bitstream import (
    NalUnit,
    assemble_nal_units,
    ebsp_to_rbsp,
    rbsp_to_ebsp,
    split_nal_units,
)
from mangle.engine import mutate_bytes
from mangle.mutators import get_mutator, list_mutators
from mangle.mutators.registry import count_changed_bytes

SEED = Path(__file__).parent / "fixtures" / "clean.h265"
SEED_BYTES = SEED.read_bytes()


# ---------------------------------------------------------------------------
# Cross-mutator invariants
# ---------------------------------------------------------------------------

class TestMutationInvariants:
    """Every mutator in the registry must satisfy these properties."""

    def test_all_mutators_produce_non_empty_output(self):
        for name in list_mutators():
            mutant, _ = mutate_bytes(SEED_BYTES, name, random.Random(0))
            assert len(mutant) > 0, f"{name}: produced empty output"

    def test_all_mutators_produce_valid_annex_b_framing(self):
        """The mutant must re-split into at least one NAL unit that round-trips."""
        for name in list_mutators():
            mutant, _ = mutate_bytes(SEED_BYTES, name, random.Random(1))
            nals = split_nal_units(mutant)
            assert nals, f"{name}: no NAL units in output"
            reassembled = assemble_nal_units(nals)
            assert reassembled == mutant, f"{name}: round-trip failed"

    def test_all_mutators_start_with_start_code(self):
        """Annex-B streams must begin with 0x000001 or 0x00000001."""
        for name in list_mutators():
            mutant, _ = mutate_bytes(SEED_BYTES, name, random.Random(2))
            assert mutant[:3] == b"\x00\x00\x01" or mutant[:4] == b"\x00\x00\x00\x01", (
                f"{name}: output does not start with a start code"
            )

    def test_all_mutators_change_at_least_one_byte(self):
        """Every mutator must produce output that differs from the seed."""
        for name in list_mutators():
            mutant, result = mutate_bytes(SEED_BYTES, name, random.Random(3))
            assert result.bytes_changed > 0, f"{name}: bytes_changed == 0"
            assert mutant != SEED_BYTES, f"{name}: mutant == seed (unchanged)"

    def test_all_mutators_populate_detail_field(self):
        for name in list_mutators():
            _, result = mutate_bytes(SEED_BYTES, name, random.Random(4))
            assert result.detail, f"{name}: detail field is empty"
            assert isinstance(result.detail, str)

    def test_all_mutators_set_correct_mutator_name(self):
        for name in list_mutators():
            _, result = mutate_bytes(SEED_BYTES, name, random.Random(5))
            assert result.mutator == name, (
                f"result.mutator={result.mutator!r} != {name!r}"
            )

    def test_all_mutators_reproducible_with_same_rng_seed(self):
        for name in list_mutators():
            a, _ = mutate_bytes(SEED_BYTES, name, random.Random(99))
            b, _ = mutate_bytes(SEED_BYTES, name, random.Random(99))
            assert a == b, f"{name}: not reproducible with same RNG seed"

    def test_all_mutators_do_not_produce_bare_null_bytes_as_framing(self):
        """NAL framing must be intact — no NAL should have empty EBSP."""
        for name in list_mutators():
            mutant, _ = mutate_bytes(SEED_BYTES, name, random.Random(6))
            nals = split_nal_units(mutant)
            for nal in nals:
                assert len(nal.ebsp) >= 2, (
                    f"{name}: NAL has fewer than 2 bytes of EBSP "
                    f"(nal_unit_type={nal.nal_unit_type})"
                )

    def test_count_changed_bytes_matches_actual_diff(self):
        """count_changed_bytes must accurately reflect positional differences."""
        for name in list_mutators():
            mutant, result = mutate_bytes(SEED_BYTES, name, random.Random(7))
            computed = count_changed_bytes(SEED_BYTES, mutant)
            assert result.bytes_changed == computed, (
                f"{name}: reported {result.bytes_changed} but computed {computed}"
            )


# ---------------------------------------------------------------------------
# Boundary value tests for specific mutators
# ---------------------------------------------------------------------------

class TestSPSDimensionsBoundaries:
    def test_produces_different_dimensions_from_seed(self):
        from mangle.hevc import parse_sps

        mutant, _ = mutate_bytes(SEED_BYTES, "sps-dimensions", random.Random(0))
        nals = split_nal_units(mutant)
        sps_nal = next(n for n in nals if n.nal_unit_type == 33)
        mutant_sps = parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))

        orig_nals = split_nal_units(SEED_BYTES)
        orig_sps_nal = next(n for n in orig_nals if n.nal_unit_type == 33)
        orig_sps = parse_sps(ebsp_to_rbsp(orig_sps_nal.ebsp[2:]))

        changed = (
            mutant_sps.pic_width_in_luma_samples != orig_sps.pic_width_in_luma_samples
            or mutant_sps.pic_height_in_luma_samples != orig_sps.pic_height_in_luma_samples
        )
        assert changed, "sps-dimensions mutator did not change any dimension field"

    def test_mutant_still_has_sps_nal(self):
        mutant, _ = mutate_bytes(SEED_BYTES, "sps-dimensions", random.Random(0))
        nals = split_nal_units(mutant)
        sps_nals = [n for n in nals if n.nal_unit_type == 33]
        assert sps_nals, "sps-dimensions: mutant has no SPS NAL"

    def test_different_rng_seeds_produce_different_dimensions(self):
        """Different RNG seeds should occasionally yield different outputs."""
        variants = set()
        for seed in range(10):
            mutant, _ = mutate_bytes(SEED_BYTES, "sps-dimensions", random.Random(seed))
            variants.add(mutant)
        # With 10 seeds, at least 2 should differ.
        assert len(variants) >= 2, "sps-dimensions: all 10 RNG seeds gave same output"


class TestNalEmulationBytes:
    def test_output_length_differs_from_seed(self):
        """nal-emulation-bytes operations add or remove bytes."""
        changed = False
        for seed in range(20):
            mutant, _ = mutate_bytes(
                SEED_BYTES, "nal-emulation-bytes", random.Random(seed)
            )
            if len(mutant) != len(SEED_BYTES):
                changed = True
                break
        assert changed, "nal-emulation-bytes: never changed stream length over 20 seeds"

    def test_output_is_valid_annex_b(self):
        for seed in range(5):
            mutant, _ = mutate_bytes(
                SEED_BYTES, "nal-emulation-bytes", random.Random(seed)
            )
            nals = split_nal_units(mutant)
            assert nals, f"nal-emulation-bytes seed={seed}: no NAL units"
            assert assemble_nal_units(nals) == mutant


class TestRpsOverflow:
    def test_sps_still_present_after_rps_mutation(self):
        mutant, _ = mutate_bytes(SEED_BYTES, "rps-overflow", random.Random(0))
        nals = split_nal_units(mutant)
        assert any(n.nal_unit_type == 33 for n in nals)

    def test_bytes_changed_positive(self):
        _, result = mutate_bytes(SEED_BYTES, "rps-overflow", random.Random(0))
        assert result.bytes_changed > 0


# ---------------------------------------------------------------------------
# Encoding round-trip tests (Exp-Golomb and RBSP↔EBSP)
# ---------------------------------------------------------------------------

class TestEBSPRoundTrip:
    def test_rbsp_to_ebsp_and_back_identity(self):
        """Converting to EBSP and back must yield the original RBSP."""
        raw = bytes(range(256))
        assert ebsp_to_rbsp(rbsp_to_ebsp(raw)) == raw

    def test_ebsp_insertes_emulation_prevention_on_000000(self):
        rbsp = b"\x00\x00\x00\x01"
        ebsp = rbsp_to_ebsp(rbsp)
        assert b"\x00\x00\x03" in ebsp

    def test_ebsp_insertes_emulation_prevention_on_000001(self):
        rbsp = b"\x00\x00\x01\xff"
        ebsp = rbsp_to_ebsp(rbsp)
        assert b"\x00\x00\x03\x01" in ebsp

    def test_ebsp_to_rbsp_removes_emulation_prevention(self):
        ebsp_with_ep = b"\x00\x00\x03\x01"
        rbsp = ebsp_to_rbsp(ebsp_with_ep)
        assert rbsp == b"\x00\x00\x01"

    def test_round_trip_preserves_seed_sps_rbsp(self):
        nals = split_nal_units(SEED_BYTES)
        sps_nal = next(n for n in nals if n.nal_unit_type == 33)
        rbsp = ebsp_to_rbsp(sps_nal.ebsp[2:])
        ebsp_back = rbsp_to_ebsp(rbsp)
        assert ebsp_to_rbsp(ebsp_back) == rbsp

    def test_all_mutant_nals_round_trip_through_ebsp(self):
        mutant, _ = mutate_bytes(SEED_BYTES, "sps-dimensions", random.Random(0))
        for nal in split_nal_units(mutant):
            rbsp = ebsp_to_rbsp(nal.ebsp[2:])
            assert ebsp_to_rbsp(rbsp_to_ebsp(rbsp)) == rbsp


# ---------------------------------------------------------------------------
# Registry integrity
# ---------------------------------------------------------------------------

class TestMutatorRegistry:
    def test_list_mutators_non_empty(self):
        names = list_mutators()
        assert len(names) >= 20, f"expected ≥20 mutators, got {len(names)}"

    def test_list_mutators_sorted(self):
        names = list_mutators()
        assert names == sorted(names)

    def test_get_mutator_returns_callable(self):
        for name in list_mutators():
            fn = get_mutator(name)
            assert callable(fn)

    def test_get_mutator_unknown_raises_key_error(self):
        with pytest.raises(KeyError, match="unknown mutator"):
            get_mutator("does-not-exist-xyz")

    def test_known_mutators_present(self):
        names = set(list_mutators())
        expected = {
            "sps-dimensions",
            "pps-tile-config",
            "slice-header-ref-pic-list",
            "nal-unit-type-swap",
            "rps-overflow",
            "nal-emulation-bytes",
        }
        assert expected <= names, f"missing mutators: {expected - names}"
