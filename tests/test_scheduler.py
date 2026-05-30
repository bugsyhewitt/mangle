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


class TestAdaptiveSchedulerLoadState:
    """Warm-start the adaptive scheduler from a prior campaign's scoreboard."""

    def test_loads_prior_arm_counts(self):
        sched = AdaptiveScheduler(POOL)
        report = sched.load_state(
            {
                "alpha": {"trials": 10, "rewards": 7},
                "beta": {"trials": 5, "rewards": 0},
                "gamma": {"trials": 0, "rewards": 0},
                "delta": {"trials": 3, "rewards": 1},
            }
        )
        stats = sched.stats()
        assert stats["alpha"] == {"trials": 10, "rewards": 7}
        assert stats["beta"] == {"trials": 5, "rewards": 0}
        assert stats["gamma"] == {"trials": 0, "rewards": 0}
        assert stats["delta"] == {"trials": 3, "rewards": 1}
        assert report.loaded == ["alpha", "beta", "delta", "gamma"]
        assert report.unknown == []
        assert report.cold == []
        assert report.total_trials == 18
        assert report.total_rewards == 8

    def test_loaded_counts_shift_weights_like_live_updates(self):
        # Loading {alpha: 20/20, beta: 20/0} must yield the same weight vector as
        # making the same 40 update() calls — proving the load *is* the bandit's
        # posterior, not a parallel tracker.
        live = AdaptiveScheduler(POOL)
        for _ in range(20):
            live.update("alpha", rewarded=True)
        for _ in range(20):
            live.update("beta", rewarded=False)

        resumed = AdaptiveScheduler(POOL)
        resumed.load_state(
            {
                "alpha": {"trials": 20, "rewards": 20},
                "beta": {"trials": 20, "rewards": 0},
            }
        )
        assert live.weights() == resumed.weights()

    def test_load_then_resume_select_matches_continuous_run(self):
        # A "split campaign" — half the trials, save stats, load into a fresh
        # scheduler, run the second half — must select the exact mutator stream
        # that one continuous scheduler would have, given the same RNG. This is
        # the determinism contract the resume flow rests on.
        continuous = AdaptiveScheduler(POOL)
        rng_cont = random.Random(11)
        cont_picks = []
        for i in range(40):
            pick = continuous.select(rng_cont)
            cont_picks.append(pick)
            continuous.update(pick, rewarded=(i % 3 == 0))

        # Now simulate a split: first half on one scheduler, save, resume.
        first = AdaptiveScheduler(POOL)
        rng_split = random.Random(11)
        split_picks = []
        for i in range(20):
            pick = first.select(rng_split)
            split_picks.append(pick)
            first.update(pick, rewarded=(i % 3 == 0))
        second = AdaptiveScheduler(POOL)
        second.load_state(first.stats())
        for i in range(20, 40):
            pick = second.select(rng_split)
            split_picks.append(pick)
            second.update(pick, rewarded=(i % 3 == 0))

        assert split_picks == cont_picks
        # And the final state matches too.
        assert second.stats() == continuous.stats()

    def test_unknown_mutators_dropped(self):
        sched = AdaptiveScheduler(POOL)
        report = sched.load_state(
            {
                "alpha": {"trials": 2, "rewards": 1},
                "vanished-mutator": {"trials": 99, "rewards": 88},
            }
        )
        assert report.unknown == ["vanished-mutator"]
        assert report.loaded == ["alpha"]
        # The vanished arm contributes nothing.
        assert "vanished-mutator" not in sched.stats()
        assert sched.stats()["alpha"] == {"trials": 2, "rewards": 1}

    def test_cold_arms_listed(self):
        sched = AdaptiveScheduler(POOL)
        report = sched.load_state({"alpha": {"trials": 1, "rewards": 0}})
        assert report.loaded == ["alpha"]
        # Three pool members got no prior data.
        assert report.cold == ["beta", "delta", "gamma"]

    def test_loads_are_additive(self):
        sched = AdaptiveScheduler(POOL)
        sched.update("alpha", rewarded=True)
        sched.update("alpha", rewarded=False)
        sched.load_state({"alpha": {"trials": 5, "rewards": 3}})
        # Live counts (2/1) + loaded (5/3) = (7/4)
        assert sched.stats()["alpha"] == {"trials": 7, "rewards": 4}

    def test_rewards_exceeding_trials_rejected(self):
        sched = AdaptiveScheduler(POOL)
        with pytest.raises(ValueError, match="rewards .* > trials"):
            sched.load_state({"alpha": {"trials": 1, "rewards": 2}})
        # All-or-nothing: nothing was loaded.
        assert all(
            v == {"trials": 0, "rewards": 0} for v in sched.stats().values()
        )

    def test_negative_counts_rejected(self):
        sched = AdaptiveScheduler(POOL)
        with pytest.raises(ValueError, match="negative count"):
            sched.load_state({"alpha": {"trials": -1, "rewards": 0}})
        with pytest.raises(ValueError, match="negative count"):
            sched.load_state({"alpha": {"trials": 0, "rewards": -1}})

    def test_non_integer_counts_rejected(self):
        sched = AdaptiveScheduler(POOL)
        with pytest.raises(ValueError, match="integer trials/rewards"):
            sched.load_state({"alpha": {"trials": 1.5, "rewards": 0}})

    def test_non_mapping_state_rejected(self):
        sched = AdaptiveScheduler(POOL)
        with pytest.raises(ValueError, match="'arms' must be a mapping"):
            sched.load_state([("alpha", {"trials": 1, "rewards": 0})])  # type: ignore[arg-type]

    def test_non_mapping_arm_value_rejected(self):
        sched = AdaptiveScheduler(POOL)
        with pytest.raises(ValueError, match="arm 'alpha' must be a mapping"):
            sched.load_state({"alpha": [1, 0]})  # type: ignore[dict-item]

    def test_missing_count_keys_default_to_zero(self):
        sched = AdaptiveScheduler(POOL)
        sched.load_state({"alpha": {}})
        assert sched.stats()["alpha"] == {"trials": 0, "rewards": 0}

    def test_failed_load_leaves_state_untouched(self):
        sched = AdaptiveScheduler(POOL)
        sched.update("alpha", rewarded=True)
        with pytest.raises(ValueError):
            sched.load_state(
                {
                    "alpha": {"trials": 5, "rewards": 2},
                    # gamma has rewards > trials — the whole load must abort
                    # before any arm is mutated.
                    "gamma": {"trials": 1, "rewards": 2},
                }
            )
        # alpha keeps its pre-load counts; nothing got loaded.
        assert sched.stats()["alpha"] == {"trials": 1, "rewards": 1}
        assert sched.stats()["gamma"] == {"trials": 0, "rewards": 0}
