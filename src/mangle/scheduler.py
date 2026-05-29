"""Mutator selection schedulers for fuzzing campaigns.

A *scheduler* decides which mutator to apply on each fuzzing iteration. The v0.1
campaign used a single fixed policy — uniform-random choice over the mutator pool
— which spends the same budget on a mutator that never produces a crash as on one
that crashes the decoder on every other input. For a black-box decoder harness
(mangle shells out to ffmpeg / libde265; there is no edge-coverage feedback), the
strongest signal available is the *outcome* of each decode: a crash or abort is a
reward. This module turns that signal into a feedback loop.

Two schedulers are provided:

  * :class:`UniformScheduler` — the v0.1 behaviour: every mutator is equally
    likely on every iteration. Ignores outcomes. Kept as the default so existing
    campaigns and their reproducible RNG streams are unchanged.

  * :class:`AdaptiveScheduler` — a deterministic multi-armed-bandit selector. Each
    mutator is an "arm" tracking ``trials`` (times selected) and ``rewards`` (times
    the resulting decode crashed/aborted). Selection is weighted by a smoothed
    reward rate with a Beta(alpha, beta) prior, plus an exploration floor so every
    mutator keeps being probed even after others prove productive. This is the
    realistic, in-architecture form of "coverage-guided mutation prioritisation"
    for a harness that only sees pass/fail, not coverage.

Both schedulers are fully deterministic for a given seed RNG (criterion 7): the
adaptive scheduler draws every selection from a caller-supplied
:class:`random.Random`, and its weights are a pure function of the observed
reward counts.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field


class UniformScheduler:
    """Uniform-random mutator selection (the v0.1 policy).

    Outcomes are accepted via :meth:`update` but ignored, so the two schedulers
    share one interface and the engine never has to special-case the policy.
    """

    name = "uniform"

    def __init__(self, mutators: list[str]):
        if not mutators:
            raise ValueError("scheduler requires a non-empty mutator pool")
        self._mutators = list(mutators)

    def select(self, rng: random.Random) -> str:
        return rng.choice(self._mutators)

    def update(self, mutator: str, rewarded: bool) -> None:  # noqa: D401
        """No-op: the uniform policy does not learn from outcomes."""

    def stats(self) -> dict[str, dict[str, int]]:
        return {m: {"trials": 0, "rewards": 0} for m in self._mutators}


@dataclass
class _Arm:
    trials: int = 0
    rewards: int = 0


@dataclass
class AdaptiveScheduler:
    """Outcome-feedback (multi-armed-bandit) mutator selection.

    The selection weight for a mutator is::

        floor + (1 - floor * n) * smoothed_reward_rate / sum(smoothed_reward_rate)

    where ``smoothed_reward_rate = (rewards + alpha) / (trials + alpha + beta)``.
    The Beta(``alpha``, ``beta``) prior keeps a never-rewarded mutator from
    collapsing to zero weight too fast, and the per-arm ``exploration_floor``
    guarantees every mutator retains a minimum selection probability so the
    scheduler keeps probing the long tail. With all reward counts at zero the
    weights are equal, so the adaptive scheduler *starts* uniform and only
    diverges from uniform as crashes accumulate.

    Deterministic: :meth:`select` consumes one ``rng`` draw and the weight vector
    is a pure function of the accumulated arm counts.
    """

    mutators: list[str]
    alpha: float = 1.0
    beta: float = 1.0
    exploration_floor: float = 0.02
    _arms: dict[str, _Arm] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.mutators:
            raise ValueError("scheduler requires a non-empty mutator pool")
        if self.alpha <= 0 or self.beta <= 0:
            raise ValueError("alpha and beta must be positive")
        n = len(self.mutators)
        if not 0.0 <= self.exploration_floor <= 1.0 / n:
            raise ValueError(
                "exploration_floor must be in [0, 1/len(mutators)] so the floors "
                f"sum to <= 1 (got {self.exploration_floor} for {n} mutators)"
            )
        self.mutators = list(self.mutators)
        self._arms = {m: _Arm() for m in self.mutators}

    name = "adaptive"

    def weights(self) -> dict[str, float]:
        """Return the current normalised selection weight per mutator."""
        rates = {
            m: (arm.rewards + self.alpha) / (arm.trials + self.alpha + self.beta)
            for m, arm in self._arms.items()
        }
        total = sum(rates.values())
        n = len(self.mutators)
        floor = self.exploration_floor
        residual = 1.0 - floor * n
        if total <= 0:  # pragma: no cover - alpha>0 makes this unreachable
            return {m: 1.0 / n for m in self.mutators}
        return {m: floor + residual * (rate / total) for m, rate in rates.items()}

    def select(self, rng: random.Random) -> str:
        weights = self.weights()
        # Deterministic weighted pick from a single uniform draw — independent of
        # Python version (random.choices' internal algorithm is not contractually
        # stable, so we roll our own cumulative-weight walk).
        roll = rng.random()
        cumulative = 0.0
        for mutator in self.mutators:
            cumulative += weights[mutator]
            if roll < cumulative:
                return mutator
        return self.mutators[-1]  # float-rounding guard

    def update(self, mutator: str, rewarded: bool) -> None:
        arm = self._arms[mutator]
        arm.trials += 1
        if rewarded:
            arm.rewards += 1

    def stats(self) -> dict[str, dict[str, int]]:
        return {
            m: {"trials": arm.trials, "rewards": arm.rewards}
            for m, arm in self._arms.items()
        }


def make_scheduler(strategy: str, mutators: list[str]):
    """Construct a scheduler by strategy name (``uniform`` or ``adaptive``)."""
    if strategy == "uniform":
        return UniformScheduler(mutators)
    if strategy == "adaptive":
        return AdaptiveScheduler(mutators)
    raise ValueError(
        f"unknown scheduler strategy '{strategy}' (expected uniform or adaptive)"
    )
