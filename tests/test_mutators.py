"""Unit tests for the four v0.1 mutators and the registry."""

from __future__ import annotations

import random
from pathlib import Path

from mangle.bitstream import assemble_nal_units, split_nal_units
from mangle.mutators import get_mutator, list_mutators

SEED = Path(__file__).parent / "fixtures" / "clean.h265"

REQUIRED_MUTATORS = {
    "sps-dimensions",
    "pps-tile-config",
    "slice-header-ref-pic-list",
    "nal-unit-type-swap",
}


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
