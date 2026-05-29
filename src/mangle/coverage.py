"""Mutation-coverage reporter (POST_V01 coverage-metrics leg).

mangle is a *black-box* harness: it shells out to ffmpeg / libde265 and the only
feedback it sees is each decode's pass/fail outcome — there is no edge-coverage
instrumentation to drive a libFuzzer/AFL-style coverage map (see the harness note
in :mod:`mangle.scheduler`). The honest, in-architecture coverage question for
such a harness is therefore *structural*, not edge-based:

    Did this campaign actually exercise the full mutator surface, how did each
    mutator's outcomes distribute, and which registered mutators did it never
    reach?

This module answers that with a pure post-processing pass over the
``results.jsonl`` a :func:`mangle.engine.fuzz_async` campaign already wrote — the
same read-only, deterministic, no-pipeline-change shape as :mod:`mangle.triage`
and :mod:`mangle.replay`. It reports, per mutator:

  * **iterations** the campaign spent on it;
  * the **outcome breakdown** (clean / crash / abort / timeout / hang);
  * **crash_aborts** — the count of crash+abort iterations (the harness's reward
    signal);
  * **distinct_signatures** — how many *unique bugs* it found, computed with the
    exact triage crash fingerprint (ASAN top frames, else normalised-stderr hash)
    so a mutator that crashes 500 times on one bug is not mistaken for broad
    coverage;
  * **bytes_changed** summed across its iterations.

And, at the campaign level:

  * **exercised** vs **uncovered** mutators against the live registry — the
    blind-spot list (mutators registered but never selected this campaign);
  * **coverage_fraction** (exercised / registry) and **productive_fraction**
    (mutators that produced >=1 crash/abort, over the registry);
  * **unknown_mutators** — mutators named in the results but absent from the
    current registry (a results file from a different mangle build), surfaced
    rather than silently dropped.

Writes ``<output_dir>/coverage.json``. Runs no decoder; changes nothing in the
fuzzing pipeline; fully deterministic.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .mutators import list_mutators
from .triage import signature_for

# The outcome states the engine records (see mangle.decoder.Outcome). Listed in a
# fixed order so the per-mutator outcome breakdown is stable across runs.
_OUTCOME_ORDER = ("clean", "crash", "abort", "timeout", "hang")
# Outcomes that count as the harness's "reward" — a decoder failure. Mirrors
# mangle.engine._REWARD_OUTCOMES.
_REWARD_OUTCOMES = frozenset({"crash", "abort"})


@dataclass
class MutatorCoverage:
    """Per-mutator coverage stats over one campaign's ``results.jsonl``."""

    mutator: str
    known: bool
    iterations: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    crash_aborts: int = 0
    distinct_signatures: int = 0
    bytes_changed: int = 0


@dataclass
class CoverageReport:
    """Campaign-level mutation-coverage summary."""

    registry_size: int
    total_iterations: int = 0
    exercised_count: int = 0
    productive_count: int = 0
    coverage_fraction: float = 0.0
    productive_fraction: float = 0.0
    exercised: list[str] = field(default_factory=list)
    uncovered: list[str] = field(default_factory=list)
    unknown_mutators: list[str] = field(default_factory=list)
    mutators: list[MutatorCoverage] = field(default_factory=list)


def _load_iterations(results_path: Path) -> list[dict]:
    """Parse every (non-blank) iteration record from a results.jsonl."""
    records: list[dict] = []
    with results_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def coverage_report(
    output_dir: str | Path,
    frame_depth: int = 3,
) -> CoverageReport:
    """Compute the mutation-coverage report for a fuzz ``output_dir``.

    Reads ``<output_dir>/results.jsonl`` for the per-iteration mutator/outcome
    metadata and, for crash/abort iterations, ``<output_dir>/crashes/<hash>.txt``
    to fingerprint the crash (so ``distinct_signatures`` counts unique bugs, not
    raw crashes). Missing crash artifacts degrade gracefully — the iteration
    still counts toward ``crash_aborts``, it just contributes an empty-stderr
    signature.

    ``frame_depth`` is forwarded to the triage signature function, matching the
    ``triage`` / ``reduce`` / ``corpus-trim`` knob.
    """
    out_dir = Path(output_dir)
    results_path = out_dir / "results.jsonl"
    crashes_dir = out_dir / "crashes"
    if not results_path.exists():
        raise FileNotFoundError(f"no results.jsonl in {out_dir}")

    registry = list_mutators()
    registry_set = set(registry)

    records = _load_iterations(results_path)

    # Accumulate per-mutator state. Keys are mutator names as they appear in the
    # results (which may include names not in the current registry).
    iters: Counter[str] = Counter()
    outcomes: dict[str, Counter[str]] = {}
    crash_aborts: Counter[str] = Counter()
    bytes_changed: Counter[str] = Counter()
    # Distinct crash signatures per mutator (set of signature strings).
    signatures: dict[str, set[str]] = {}

    for rec in records:
        name = rec.get("mutator", "unknown")
        outcome = rec.get("outcome", "")
        iters[name] += 1
        outcomes.setdefault(name, Counter())[outcome] += 1
        bytes_changed[name] += int(rec.get("bytes_changed", 0) or 0)

        if outcome in _REWARD_OUTCOMES:
            crash_aborts[name] += 1
            crash_hash = rec.get("crash_hash")
            stderr = ""
            if crash_hash:
                txt_path = crashes_dir / f"{crash_hash}.txt"
                if txt_path.exists():
                    stderr = txt_path.read_text()
            sig = signature_for(stderr, frame_depth)
            signatures.setdefault(name, set()).add(f"{sig.kind}:{sig.signature}")

    seen_names = sorted(iters)
    mutator_covs: list[MutatorCoverage] = []
    for name in seen_names:
        ordered = {
            o: outcomes[name][o]
            for o in _OUTCOME_ORDER
            if outcomes[name].get(o)
        }
        # Preserve any out-of-spec outcome strings rather than dropping them.
        for o in sorted(outcomes[name]):
            if o not in ordered and outcomes[name][o]:
                ordered[o] = outcomes[name][o]
        mutator_covs.append(
            MutatorCoverage(
                mutator=name,
                known=name in registry_set,
                iterations=iters[name],
                outcomes=ordered,
                crash_aborts=crash_aborts[name],
                distinct_signatures=len(signatures.get(name, ())),
                bytes_changed=bytes_changed[name],
            )
        )

    # ``exercised`` is every mutator the campaign actually ran (registry-known or
    # not). Coverage is measured only against the live registry, so the count and
    # fractions below use the registry-known subset; unknown mutators are still
    # listed (in ``exercised`` and ``unknown_mutators``) rather than dropped.
    exercised = sorted(seen_names)
    exercised_known = [n for n in exercised if n in registry_set]
    uncovered = sorted(registry_set - set(seen_names))
    unknown = sorted(n for n in seen_names if n not in registry_set)
    productive = sorted(n for n in exercised_known if crash_aborts[n] > 0)

    n_reg = len(registry)
    return CoverageReport(
        registry_size=n_reg,
        total_iterations=sum(iters.values()),
        exercised_count=len(exercised_known),
        productive_count=len(productive),
        coverage_fraction=(len(exercised_known) / n_reg) if n_reg else 0.0,
        productive_fraction=(len(productive) / n_reg) if n_reg else 0.0,
        exercised=exercised,
        uncovered=uncovered,
        unknown_mutators=unknown,
        mutators=mutator_covs,
    )


def write_coverage(
    output_dir: str | Path,
    frame_depth: int = 3,
) -> CoverageReport:
    """Compute the coverage report and write ``<output_dir>/coverage.json``.

    Returns the report. The JSON is the dataclass tree serialised verbatim, so
    its schema is exactly :class:`CoverageReport` (with a ``mutators`` list of
    :class:`MutatorCoverage`).
    """
    out_dir = Path(output_dir)
    report = coverage_report(out_dir, frame_depth=frame_depth)
    (out_dir / "coverage.json").write_text(json.dumps(asdict(report), indent=2) + "\n")
    return report
