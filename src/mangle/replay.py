"""Deterministic mutant replay (POST_V01 item #8, mutation-replay leg).

A ``mangle fuzz`` campaign records, for every iteration, the *exact* RNG draws
that produced that iteration's mutant: ``results.jsonl`` stores each iteration's
``mutator`` name and its per-iteration RNG seed (``seed_rng`` — the
``iter_rng_seed`` the engine drew from the campaign's base RNG). Because every
mutator is a pure function of ``(input bytes, random.Random(seed))`` and the
NAL split/assemble round-trips losslessly, that pair is sufficient to *replay*
the iteration: re-apply the same mutator with a fresh ``random.Random(seed_rng)``
to the original seed file and you get back the byte-identical mutant.

The roadmap (POST_V01 item #8) called for "mutation replay: re-run the exact RNG
seed to confirm reproducibility". Triage and reduce both operate on the *saved
crash artifact bytes*; neither can reconstruct a mutant that was **not** a crash
(clean / timeout / hang iterations write no artifact). Replay closes that gap:
given the seed file and the campaign's ``results.jsonl``, it reconstructs the
mutant for *any* iteration — crashing or not — so an analyst can:

  * recover a timeout/hang mutant the campaign never saved to ``crashes/``;
  * confirm a saved crash artifact is bit-identical to what the recorded seed
    re-derives (tamper / reproducibility check);
  * hand a colleague a one-line, decoder-free recipe (``--seed`` + iteration)
    instead of a binary blob.

Replay is a pure, deterministic re-derivation. It runs no decoder and makes no
changes to the fuzzing pipeline; it only reads what ``fuzz`` already wrote.
"""

from __future__ import annotations

import hashlib
import json
import random
from dataclasses import dataclass
from pathlib import Path

from .engine import mutate_bytes


@dataclass
class ReplayRecord:
    """One iteration's reproduction metadata, read from ``results.jsonl``."""

    iteration: int
    mutator: str
    seed_rng: int
    outcome: str
    crash_hash: str | None
    # The base seed the iteration mutated. ``None`` for a single-``--seed``
    # campaign (mutate the file passed to replay's --seed). A basename for a
    # ``--seed-from-crashes`` campaign — replay must resolve that file from a
    # base-seed directory rather than from --seed.
    base_seed: str | None = None


@dataclass
class ReplayResult:
    """The outcome of replaying one iteration."""

    iteration: int
    mutator: str
    seed_rng: int
    outcome: str
    bytes_written: int
    mutant_sha256: str
    output_path: str
    # When the iteration was a crash, the campaign saved the mutant under
    # ``crashes/<crash_hash>.h265``. ``verified`` is True when that saved
    # artifact exists and is byte-identical to the freshly re-derived mutant
    # (the reproducibility / tamper check). None when there was no saved
    # artifact to compare against (a clean/timeout/hang iteration).
    crash_hash: str | None
    verified: bool | None


def load_results(output_dir: str | Path) -> list[ReplayRecord]:
    """Read every iteration record from ``<output_dir>/results.jsonl``."""
    results_path = Path(output_dir) / "results.jsonl"
    if not results_path.exists():
        raise FileNotFoundError(
            f"no results.jsonl in {output_dir} — is this a fuzz output directory?"
        )
    records: list[ReplayRecord] = []
    with results_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            records.append(
                ReplayRecord(
                    iteration=row["iteration"],
                    mutator=row["mutator"],
                    seed_rng=row["seed_rng"],
                    outcome=row["outcome"],
                    crash_hash=row.get("crash_hash"),
                    base_seed=row.get("base_seed"),
                )
            )
    return records


def find_record(
    records: list[ReplayRecord], iteration: int
) -> ReplayRecord:
    """Return the record for ``iteration`` or raise a clear error."""
    for rec in records:
        if rec.iteration == iteration:
            return rec
    available = [r.iteration for r in records]
    lo = min(available) if available else None
    hi = max(available) if available else None
    raise KeyError(
        f"iteration {iteration} not found in results.jsonl "
        f"(campaign has iterations {lo}..{hi})"
    )


def replay_record(seed_data: bytes, record: ReplayRecord) -> bytes:
    """Re-derive the mutant bytes for one recorded iteration.

    Pure function of ``(seed_data, record.mutator, record.seed_rng)`` — the same
    inputs the engine used, so the result is byte-identical to the original
    iteration's mutant.
    """
    rng = random.Random(record.seed_rng)
    mutated, _ = mutate_bytes(seed_data, record.mutator, rng)
    return mutated


def resolve_seed_bytes(
    record: ReplayRecord,
    seed_path: str | Path | None,
    seed_dir: str | Path | None,
) -> bytes:
    """Read the base-seed bytes the recorded iteration mutated.

    For a single-``--seed`` campaign (``record.base_seed is None``) the base is
    the file at ``seed_path``. For a ``--seed-from-crashes`` campaign the base is
    ``<seed_dir>/<record.base_seed>`` — the specific crash artifact that
    iteration mutated, resolved from the prior campaign's seed directory.
    """
    if record.base_seed is not None:
        if seed_dir is None:
            raise ValueError(
                f"iteration {record.iteration} was fuzzed from a crash seed "
                f"('{record.base_seed}'); replay needs --seed-dir pointing at the "
                "directory of base seeds (e.g. the prior campaign's crashes/)"
            )
        seed_file = Path(seed_dir) / record.base_seed
        if not seed_file.exists():
            raise FileNotFoundError(
                f"base seed '{record.base_seed}' for iteration {record.iteration} "
                f"not found in --seed-dir {seed_dir}"
            )
        return seed_file.read_bytes()
    if seed_path is None:
        raise ValueError(
            f"iteration {record.iteration} is a single-seed iteration; replay "
            "needs --seed pointing at the original seed file"
        )
    return Path(seed_path).read_bytes()


def replay_iteration(
    seed_path: str | Path | None,
    output_dir: str | Path,
    iteration: int,
    out_path: str | Path,
    seed_dir: str | Path | None = None,
) -> ReplayResult:
    """Reconstruct one iteration's mutant from the campaign metadata.

    Reads ``<output_dir>/results.jsonl`` to find ``iteration``, re-derives the
    mutant from its recorded base seed and ``(mutator, seed_rng)``, and writes it
    to ``out_path``. The base seed is the file at ``seed_path`` for a single-seed
    campaign, or ``<seed_dir>/<base_seed>`` for a ``--seed-from-crashes``
    campaign. When the iteration was a crash, cross-checks the re-derived bytes
    against the saved ``crashes/`` artifact.
    """
    records = load_results(output_dir)
    record = find_record(records, iteration)

    seed_data = resolve_seed_bytes(record, seed_path, seed_dir)
    mutated = replay_record(seed_data, record)
    mutant_sha256 = hashlib.sha256(mutated).hexdigest()

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(mutated)

    verified: bool | None = None
    if record.crash_hash is not None:
        artifact = Path(output_dir) / "crashes" / f"{record.crash_hash}.h265"
        if artifact.exists():
            verified = artifact.read_bytes() == mutated

    return ReplayResult(
        iteration=record.iteration,
        mutator=record.mutator,
        seed_rng=record.seed_rng,
        outcome=record.outcome,
        bytes_written=len(mutated),
        mutant_sha256=mutant_sha256,
        output_path=str(out),
        crash_hash=record.crash_hash,
        verified=verified,
    )
