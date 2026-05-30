"""Mutation-score reporter (POST_V01 mutation-testing leg).

Classic mutation testing scores a test suite by the fraction of mutants it
*kills* — a "killed" mutant is one whose behaviour the suite detects, a
"survived" mutant is one the suite shrugs off. mangle inverts the roles: the
mutants are the bitstream variants this fuzzer generates, and the "test suite"
is the decoder under test. A mangle mutant therefore **kills** the decoder when
the decoder's behaviour visibly diverges from a clean decode (crash, abort,
timeout, or hang), and **survives** when the decoder accepts it as if it were a
normal stream (a ``clean`` outcome). The mutation score is the kill ratio.

That ratio is a complementary metric to :mod:`mangle.coverage` and
:mod:`mangle.heatmap`:

  * ``coverage`` reports **which** mutators a campaign exercised against the
    registry (breadth).
  * ``heatmap`` reports **where** in the bitstream the pressure landed
    (region distribution).
  * ``mutation-score`` reports **how potent** the campaign's mutants were
    overall, per mutator, and per base seed — i.e. how often the decoder
    actually noticed.

A near-zero mutation score on a mutator means it is producing mutants the
decoder silently accepts (the mutator is weak, or the decoder is permissive in
that region — both worth knowing). A near-1.0 score on a mutator that crashes
on only one bug means the mutator is potent but narrow — pair with
``coverage`` 's ``distinct_signatures`` to disentangle. A high per-base-seed
score on one seed and a low one on another tells you which corpus inputs are
yielding fuzz-productive mutants.

This module is a pure post-processing pass over the ``results.jsonl`` a
:func:`mangle.engine.fuzz_async` campaign already wrote — the same read-only,
deterministic, no-pipeline-change shape as :mod:`mangle.triage`,
:mod:`mangle.coverage`, and :mod:`mangle.heatmap`. Writes
``<output_dir>/mutation-score.json``. Runs no decoder.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

# Outcomes that count as a "kill" — the decoder visibly diverged from a clean
# decode. ``hang`` is a stall (the harness reserves it for an externally-
# detected stuck process, see mangle.decoder.Outcome) and is counted as a kill
# because the decoder's behaviour changed even if no signal fired.
_KILL_OUTCOMES = frozenset({"crash", "abort", "timeout", "hang"})
# A mutant the decoder accepted as if normal.
_SURVIVE_OUTCOMES = frozenset({"clean"})
# Stable display order for the per-mutator and campaign outcome breakdown.
_OUTCOME_ORDER = ("clean", "crash", "abort", "timeout", "hang")


@dataclass
class MutatorScore:
    """Per-mutator kill ratio over one campaign's ``results.jsonl``."""

    mutator: str
    iterations: int = 0
    killed: int = 0
    survived: int = 0
    score: float = 0.0
    outcomes: dict[str, int] = field(default_factory=dict)


@dataclass
class SeedScore:
    """Per-base-seed kill ratio.

    ``base_seed`` is ``None`` for v0.1-shape ``--seed`` campaigns (the seed is
    implicit in the CLI invocation). For multi-seed campaigns
    (``--seed-corpus-dir`` / ``--seed-from-crashes``) it is the basename of the
    base seed file each iteration mutated, exactly as
    :class:`mangle.engine.IterationResult.base_seed` records.
    """

    base_seed: str | None
    iterations: int = 0
    killed: int = 0
    survived: int = 0
    score: float = 0.0


@dataclass
class MutationScoreReport:
    """Campaign-level mutation-score summary."""

    total_iterations: int = 0
    killed_count: int = 0
    survived_count: int = 0
    score: float = 0.0
    outcomes: dict[str, int] = field(default_factory=dict)
    mutators: list[MutatorScore] = field(default_factory=list)
    seeds: list[SeedScore] = field(default_factory=list)


def _load_iterations(results_path: Path) -> list[dict]:
    """Parse every non-blank iteration record from a ``results.jsonl``."""
    records: list[dict] = []
    with results_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def _ordered_outcomes(counts: Counter[str]) -> dict[str, int]:
    """Return ``counts`` as a dict in stable display order.

    Known outcomes first in :data:`_OUTCOME_ORDER`; any out-of-spec outcome
    string (a future engine state we do not know about) is appended in sorted
    order rather than dropped so the breakdown stays honest.
    """
    ordered: dict[str, int] = {}
    for o in _OUTCOME_ORDER:
        if counts.get(o):
            ordered[o] = counts[o]
    for o in sorted(counts):
        if o not in ordered and counts[o]:
            ordered[o] = counts[o]
    return ordered


def mutation_score(output_dir: str | Path) -> MutationScoreReport:
    """Compute the mutation-score report for a fuzz ``output_dir``.

    Reads ``<output_dir>/results.jsonl``. An empty results file is valid: it
    yields an all-zero report rather than an error (so callers can score a
    just-started campaign without special-casing). A missing file raises
    :class:`FileNotFoundError`, matching the surrounding modules' contract.
    """
    out_dir = Path(output_dir)
    results_path = out_dir / "results.jsonl"
    if not results_path.exists():
        raise FileNotFoundError(f"no results.jsonl in {out_dir}")

    records = _load_iterations(results_path)

    overall_outcomes: Counter[str] = Counter()
    per_mutator_outcomes: dict[str, Counter[str]] = {}
    per_mutator_iters: Counter[str] = Counter()
    per_mutator_killed: Counter[str] = Counter()
    per_mutator_survived: Counter[str] = Counter()
    per_seed_iters: Counter[str | None] = Counter()
    per_seed_killed: Counter[str | None] = Counter()
    per_seed_survived: Counter[str | None] = Counter()
    seed_seen: set[str | None] = set()

    killed = 0
    survived = 0
    for rec in records:
        outcome = rec.get("outcome", "")
        name = rec.get("mutator", "unknown")
        seed = rec.get("base_seed")  # None for single-seed campaigns

        overall_outcomes[outcome] += 1
        per_mutator_iters[name] += 1
        per_mutator_outcomes.setdefault(name, Counter())[outcome] += 1
        per_seed_iters[seed] += 1
        seed_seen.add(seed)

        if outcome in _KILL_OUTCOMES:
            killed += 1
            per_mutator_killed[name] += 1
            per_seed_killed[seed] += 1
        elif outcome in _SURVIVE_OUTCOMES:
            survived += 1
            per_mutator_survived[name] += 1
            per_seed_survived[seed] += 1
        # Outcomes that are neither (an unknown future state) contribute to
        # total_iterations and the breakdown only — not to killed or survived,
        # so the score stays a well-defined kill / total fraction.

    total = sum(per_mutator_iters.values())

    mutator_scores: list[MutatorScore] = []
    for name in per_mutator_iters:
        n = per_mutator_iters[name]
        k = per_mutator_killed[name]
        mutator_scores.append(
            MutatorScore(
                mutator=name,
                iterations=n,
                killed=k,
                survived=per_mutator_survived[name],
                score=(k / n) if n else 0.0,
                outcomes=_ordered_outcomes(per_mutator_outcomes[name]),
            )
        )
    # Highest-scoring mutator first (the most potent), then by name for
    # deterministic tiebreaks.
    mutator_scores.sort(key=lambda m: (-m.score, m.mutator))

    seed_scores: list[SeedScore] = []
    for seed in seed_seen:
        n = per_seed_iters[seed]
        k = per_seed_killed[seed]
        seed_scores.append(
            SeedScore(
                base_seed=seed,
                iterations=n,
                killed=k,
                survived=per_seed_survived[seed],
                score=(k / n) if n else 0.0,
            )
        )
    # None bucket sorts last so multi-seed runs read top-down by basename and
    # a single-seed (None) run still has a stable last row.
    seed_scores.sort(key=lambda s: (s.base_seed is None, s.base_seed or ""))

    return MutationScoreReport(
        total_iterations=total,
        killed_count=killed,
        survived_count=survived,
        score=(killed / total) if total else 0.0,
        outcomes=_ordered_outcomes(overall_outcomes),
        mutators=mutator_scores,
        seeds=seed_scores,
    )


def write_mutation_score(output_dir: str | Path) -> MutationScoreReport:
    """Compute the mutation-score report and write ``mutation-score.json``.

    Returns the report. The JSON is the dataclass tree serialised verbatim, so
    its schema is exactly :class:`MutationScoreReport`.
    """
    out_dir = Path(output_dir)
    report = mutation_score(out_dir)
    (out_dir / "mutation-score.json").write_text(
        json.dumps(asdict(report), indent=2) + "\n"
    )
    return report
