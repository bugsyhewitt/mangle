"""Unit tests for the four v0.1 mutators and the registry."""

from __future__ import annotations

import random
from pathlib import Path

from mangle.bitstream import (
    assemble_nal_units,
    ebsp_to_rbsp,
    split_nal_units,
    START_CODE_LONG,
    START_CODE_SHORT,
)
from mangle.hevc import parse_sps
from mangle.mutators import get_mutator, list_mutators

SEED = Path(__file__).parent / "fixtures" / "clean.h265"

REQUIRED_MUTATORS = {
    "sps-dimensions",
    "pps-tile-config",
    "slice-header-ref-pic-list",
    "nal-unit-type-swap",
}

RPS_MUTATORS = {"rps-overflow", "rps-lt-poc-ambiguity"}


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
