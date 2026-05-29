"""Tests for the mutator-selection schedulers (uniform + adaptive)."""

from __future__ import annotations

import random

import pytest

from mangle.scheduler import (
    AdaptiveScheduler,
    UniformScheduler,
    make_scheduler,
)

POOL = ["alpha", "beta", "gamma", "delta"]


class TestMakeScheduler:
    def test_uniform(self):
        s = make_scheduler("uniform", POOL)
        assert isinstance(s, UniformScheduler)
        assert s.name == "uniform"

    def test_adaptive(self):
        s = make_scheduler("adaptive", POOL)
        assert isinstance(s, AdaptiveScheduler)
        assert s.name == "adaptive"

    def test_unknown_strategy_rejected(self):
        with pytest.raises(ValueError, match="unknown scheduler strategy"):
            make_scheduler("bandit9000", POOL)

    def test_empty_pool_rejected(self):
        with pytest.raises(ValueError, match="non-empty"):
            make_scheduler("uniform", [])
        with pytest.raises(ValueError, match="non-empty"):
            make_scheduler("adaptive", [])


class TestUniformScheduler:
    def test_matches_random_choice_stream(self):
        # The uniform scheduler must consume the RNG exactly like random.choice,
        # so existing campaigns keep their byte-identical mutator sequence.
        sched = UniformScheduler(POOL)
        a_rng = random.Random(123)
        b_rng = random.Random(123)
        sched_picks = [sched.select(a_rng) for _ in range(50)]
        choice_picks = [b_rng.choice(POOL) for _ in range(50)]
        assert sched_picks == choice_picks

    def test_update_is_noop(self):
        sched = UniformScheduler(POOL)
        for _ in range(10):
            sched.update("alpha", rewarded=True)
        # No learning: stats stay zeroed.
        assert all(v == {"trials": 0, "rewards": 0} for v in sched.stats().values())


class TestAdaptiveScheduler:
    def test_starts_uniform_with_no_rewards(self):
        sched = AdaptiveScheduler(POOL)
        weights = sched.weights()
        assert pytest.approx(sum(weights.values()), abs=1e-9) == 1.0
        # With zero observations every arm has the same prior, so equal weights.
        vals = list(weights.values())
        assert all(pytest.approx(v, abs=1e-9) == vals[0] for v in vals)

    def test_rewarded_arm_gets_more_weight(self):
        sched = AdaptiveScheduler(POOL)
        # alpha crashes every time it is tried; beta never does.
        for _ in range(20):
            sched.update("alpha", rewarded=True)
        for _ in range(20):
            sched.update("beta", rewarded=False)
        weights = sched.weights()
        assert weights["alpha"] > weights["gamma"] > weights["beta"]
        assert pytest.approx(sum(weights.values()), abs=1e-9) == 1.0

    def test_exploration_floor_is_respected(self):
        sched = AdaptiveScheduler(POOL, exploration_floor=0.05)
        # Crash one arm relentlessly; the cold arms must still keep >= the floor.
        for _ in range(500):
            sched.update("alpha", rewarded=True)
        weights = sched.weights()
        for m in ("beta", "gamma", "delta"):
            assert weights[m] >= 0.05 - 1e-9

    def test_selection_is_deterministic_for_seed(self):
        a = AdaptiveScheduler(POOL)
        b = AdaptiveScheduler(POOL)
        ra = random.Random(99)
        rb = random.Random(99)
        # Apply identical reward histories, then compare selection streams.
        for sched in (a, b):
            for _ in range(5):
                sched.update("gamma", rewarded=True)
        assert [a.select(ra) for _ in range(30)] == [b.select(rb) for _ in range(30)]

    def test_select_always_returns_pool_member(self):
        sched = AdaptiveScheduler(POOL)
        rng = random.Random(7)
        for _ in range(200):
            assert sched.select(rng) in POOL

    def test_select_biases_toward_rewarded_arm(self):
        sched = AdaptiveScheduler(POOL, exploration_floor=0.0)
        for _ in range(50):
            sched.update("delta", rewarded=True)
        rng = random.Random(2024)
        picks = [sched.select(rng) for _ in range(2000)]
        # The rewarded arm should be selected far more than its 1/4 uniform share.
        assert picks.count("delta") > 2000 * 0.4

    def test_stats_track_trials_and_rewards(self):
        sched = AdaptiveScheduler(POOL)
        sched.update("alpha", rewarded=True)
        sched.update("alpha", rewarded=False)
        sched.update("beta", rewarded=False)
        stats = sched.stats()
        assert stats["alpha"] == {"trials": 2, "rewards": 1}
        assert stats["beta"] == {"trials": 1, "rewards": 0}
        assert stats["gamma"] == {"trials": 0, "rewards": 0}

    def test_invalid_priors_rejected(self):
        with pytest.raises(ValueError, match="positive"):
            AdaptiveScheduler(POOL, alpha=0)
        with pytest.raises(ValueError, match="positive"):
            AdaptiveScheduler(POOL, beta=-1)

    def test_floor_too_large_rejected(self):
        # Floors must sum to <= 1 across the pool.
        with pytest.raises(ValueError, match="exploration_floor"):
            AdaptiveScheduler(POOL, exploration_floor=0.5)
