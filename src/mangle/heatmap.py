"""Mutation heat-map reporter (POST_V01 heat-map leg).

``mangle coverage`` answers the *per-mutator* structural-coverage question: did
the campaign reach every registered mutator, and which ones were productive? That
view is **flat** — 22 independent rows — and it does not tell you *which part of
the HEVC bitstream* the campaign actually leaned on. mangle is a grammar-aware
fuzzer; every mutator targets a specific structural region of the stream (the VPS,
the SPS, the PPS, the slice header, the reference-picture-set block, the SEI
payload, or the raw NAL framing). The natural next analytic is therefore a
**heat-map**: aggregate the campaign's pressure (iterations, bytes changed) and
its reward (crashes/aborts, distinct bugs) *by bitstream region*, so you can see
at a glance where the campaign pounded and — more importantly — where that effort
actually paid off.

This is the "where is the soft spot in the H.265 parser?" view. A region that
absorbed 40% of the campaign's iterations but produced zero crashes is wasted
pressure; a region that took 5% of iterations but yielded three distinct bugs is
the place to aim the next campaign. Neither :mod:`mangle.coverage` (per-mutator,
flat) nor :mod:`mangle.triage` (per-bug) surfaces that region-level picture.

Like ``coverage`` / ``triage`` / ``replay``, this is a **pure post-processing**
pass over the ``results.jsonl`` a :func:`mangle.engine.fuzz_async` campaign wrote:
no decoder is run, nothing in the fuzzing pipeline changes, and the output is
fully deterministic.

Region assignment
-----------------

Every mutator's CLI name carries its target region as a prefix
(``sps-dimensions``, ``pps-deblocking``, ``rps-overflow``, ...). The region is
derived from that prefix via :data:`REGION_BY_PREFIX`, a deterministic, explicit
table — no guessing. A mutator whose prefix is not in the table is bucketed under
``"other"`` and surfaced, never silently dropped (the same graceful-degradation
posture ``coverage`` takes with unknown mutators).

For each region the report records:

  * **iterations** spent on the region (the pressure axis);
  * the **outcome breakdown** (clean / crash / abort / timeout / hang);
  * **crash_aborts** — the region's reward signal;
  * **distinct_signatures** — unique bugs found in the region, computed with the
    exact triage crash fingerprint (ASAN top frames, else normalised-stderr hash)
    so 500 crashes on one bug do not inflate a region's apparent fruitfulness;
  * **bytes_changed** summed across the region;
  * **mutators** — the registry mutators that map to this region, so the heat-map
    is drillable back down to ``coverage``'s granularity;
  * **iteration_share** — the region's fraction of all iterations (pressure
    intensity, 0..1);
  * **crash_share** — the region's fraction of all crash/abort iterations (reward
    intensity, 0..1).

The ``iteration_share`` vs ``crash_share`` pair *is* the heat-map: a region whose
crash_share far exceeds its iteration_share is hotter than its pressure — the
profitable target — while the reverse marks wasted pressure.

Writes ``<output_dir>/heatmap.json``. Runs no decoder; deterministic.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .mutators import list_mutators
from .triage import signature_for

# Outcome states the engine records (mangle.decoder.Outcome), fixed order so the
# per-region outcome breakdown is stable across runs.
_OUTCOME_ORDER = ("clean", "crash", "abort", "timeout", "hang")
# Outcomes that count as the harness's reward (a decoder failure). Mirrors
# mangle.engine._REWARD_OUTCOMES and mangle.coverage._REWARD_OUTCOMES.
_REWARD_OUTCOMES = frozenset({"crash", "abort"})

# Explicit mutator-name-prefix -> bitstream-region table. The prefix is the text
# before the first '-' in a mutator's CLI name. This is deterministic and
# auditable: adding a mutator under a known prefix needs no change here; adding a
# brand-new prefix surfaces as the "other" region until it is mapped.
REGION_BY_PREFIX: dict[str, str] = {
    "vps": "vps",  # Video Parameter Set
    "sps": "sps",  # Sequence Parameter Set
    "pps": "pps",  # Picture Parameter Set (incl. PPS->slice-header gates)
    "rps": "rps",  # Reference Picture Set (short- & long-term)
    "slice": "slice-header",  # slice-segment header
    "sei": "sei",  # Supplemental Enhancement Information
    "nal": "nal-framing",  # raw NAL framing / emulation-prevention bytes
}
# The bucket for any mutator whose prefix is not in REGION_BY_PREFIX.
OTHER_REGION = "other"


def region_for_mutator(name: str) -> str:
    """Map a mutator CLI name to its bitstream region.

    Deterministic: the region is the prefix (text before the first ``-``) looked
    up in :data:`REGION_BY_PREFIX`, or :data:`OTHER_REGION` when the prefix is
    unmapped (an unknown / future mutator). Never raises.
    """
    prefix = name.split("-", 1)[0]
    return REGION_BY_PREFIX.get(prefix, OTHER_REGION)


@dataclass
class RegionHeat:
    """Per-region aggregate over one campaign's ``results.jsonl``."""

    region: str
    iterations: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)
    crash_aborts: int = 0
    distinct_signatures: int = 0
    bytes_changed: int = 0
    mutators: list[str] = field(default_factory=list)
    iteration_share: float = 0.0
    crash_share: float = 0.0


@dataclass
class HeatmapReport:
    """Campaign-level mutation heat-map: pressure and reward by region."""

    total_iterations: int = 0
    total_crash_aborts: int = 0
    region_count: int = 0
    hottest_region: str | None = None
    regions: list[RegionHeat] = field(default_factory=list)


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


def heatmap_report(
    output_dir: str | Path,
    frame_depth: int = 3,
) -> HeatmapReport:
    """Compute the mutation heat-map for a fuzz ``output_dir``.

    Reads ``<output_dir>/results.jsonl`` for per-iteration mutator/outcome
    metadata and, for crash/abort iterations, ``<output_dir>/crashes/<hash>.txt``
    to fingerprint each crash (so ``distinct_signatures`` counts unique bugs per
    region). Missing crash artifacts degrade gracefully — the iteration still
    counts toward ``crash_aborts`` with an empty-stderr signature.

    ``frame_depth`` is forwarded to the triage signature function, matching the
    ``triage`` / ``reduce`` / ``coverage`` knob.

    Regions are sorted by reward (crash_aborts desc), then by iterations desc,
    then by name, so the most interesting region is first and ties are stable.
    """
    out_dir = Path(output_dir)
    results_path = out_dir / "results.jsonl"
    crashes_dir = out_dir / "crashes"
    if not results_path.exists():
        raise FileNotFoundError(f"no results.jsonl in {out_dir}")

    records = _load_iterations(results_path)

    iters: Counter[str] = Counter()
    outcomes: dict[str, Counter[str]] = {}
    crash_aborts: Counter[str] = Counter()
    bytes_changed: Counter[str] = Counter()
    signatures: dict[str, set[str]] = {}

    for rec in records:
        mutator = rec.get("mutator", "unknown")
        region = region_for_mutator(mutator)
        outcome = rec.get("outcome", "")
        iters[region] += 1
        outcomes.setdefault(region, Counter())[outcome] += 1
        bytes_changed[region] += int(rec.get("bytes_changed", 0) or 0)

        if outcome in _REWARD_OUTCOMES:
            crash_aborts[region] += 1
            crash_hash = rec.get("crash_hash")
            stderr = ""
            if crash_hash:
                txt_path = crashes_dir / f"{crash_hash}.txt"
                if txt_path.exists():
                    stderr = txt_path.read_text()
            sig = signature_for(stderr, frame_depth)
            signatures.setdefault(region, set()).add(f"{sig.kind}:{sig.signature}")

    # Registry mutators per region, so each row is drillable back to coverage's
    # per-mutator view (independent of whether the campaign exercised them).
    mutators_by_region: dict[str, list[str]] = {}
    for name in list_mutators():
        mutators_by_region.setdefault(region_for_mutator(name), []).append(name)

    total_iters = sum(iters.values())
    total_crashes = sum(crash_aborts.values())

    seen_regions = sorted(iters)
    region_heats: list[RegionHeat] = []
    for region in seen_regions:
        ordered = {
            o: outcomes[region][o]
            for o in _OUTCOME_ORDER
            if outcomes[region].get(o)
        }
        # Preserve any out-of-spec outcome strings rather than dropping them.
        for o in sorted(outcomes[region]):
            if o not in ordered and outcomes[region][o]:
                ordered[o] = outcomes[region][o]
        region_heats.append(
            RegionHeat(
                region=region,
                iterations=iters[region],
                outcomes=ordered,
                crash_aborts=crash_aborts[region],
                distinct_signatures=len(signatures.get(region, ())),
                bytes_changed=bytes_changed[region],
                mutators=sorted(mutators_by_region.get(region, [])),
                iteration_share=(iters[region] / total_iters) if total_iters else 0.0,
                crash_share=(
                    crash_aborts[region] / total_crashes if total_crashes else 0.0
                ),
            )
        )

    # Sort by reward first (crash_aborts desc), then pressure (iterations desc),
    # then name — the hottest region leads, ties are deterministic.
    region_heats.sort(key=lambda r: (-r.crash_aborts, -r.iterations, r.region))

    hottest = region_heats[0].region if region_heats else None

    return HeatmapReport(
        total_iterations=total_iters,
        total_crash_aborts=total_crashes,
        region_count=len(region_heats),
        hottest_region=hottest,
        regions=region_heats,
    )


def write_heatmap(
    output_dir: str | Path,
    frame_depth: int = 3,
) -> HeatmapReport:
    """Compute the heat-map report and write ``<output_dir>/heatmap.json``.

    Returns the report. The JSON is the dataclass tree serialised verbatim, so
    its schema is exactly :class:`HeatmapReport` (with a ``regions`` list of
    :class:`RegionHeat`).
    """
    out_dir = Path(output_dir)
    report = heatmap_report(out_dir, frame_depth=frame_depth)
    (out_dir / "heatmap.json").write_text(json.dumps(asdict(report), indent=2) + "\n")
    return report
