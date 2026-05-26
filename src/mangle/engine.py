"""High-level mutate and fuzz orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

from .bitstream import assemble_nal_units, split_nal_units
from .decoder import Outcome, run_decoder
from .mutators import MutationResult, get_mutator


@dataclass
class MutateOutcome:
    mutator: str
    bytes_changed: int
    detail: str
    output_path: str


def mutate_file(
    seed_path: str | Path,
    output_path: str | Path,
    mutator_name: str,
    seed_rng: int,
) -> MutateOutcome:
    """Apply one named mutator to a seed file and write the mutant.

    Deterministic for a given (seed file, mutator, seed_rng) — criterion 7.
    """
    data = Path(seed_path).read_bytes()
    nals = split_nal_units(data)
    rng = random.Random(seed_rng)
    mutator = get_mutator(mutator_name)
    result: MutationResult = mutator(nals, rng)
    mutated = assemble_nal_units(result.nals)
    Path(output_path).write_bytes(mutated)
    return MutateOutcome(
        mutator=result.mutator,
        bytes_changed=result.bytes_changed,
        detail=result.detail,
        output_path=str(output_path),
    )


def mutate_bytes(
    data: bytes, mutator_name: str, rng: random.Random
) -> tuple[bytes, MutationResult]:
    """Apply a mutator to raw bytes, returning the mutated stream and result."""
    nals = split_nal_units(data)
    mutator = get_mutator(mutator_name)
    result = mutator(nals, rng)
    return assemble_nal_units(result.nals), result


@dataclass
class IterationResult:
    iteration: int
    mutator: str
    seed_rng: int
    outcome: str
    returncode: int | None
    bytes_changed: int
    detail: str
    crash_hash: str | None = None


async def _run_iteration(
    i: int,
    seed_data: bytes,
    mutator_name: str,
    iter_rng_seed: int,
    decoder: str,
    timeout: float,
    crashes_dir: Path,
    semaphore: asyncio.Semaphore,
) -> IterationResult:
    rng = random.Random(iter_rng_seed)
    mutated, result = mutate_bytes(seed_data, mutator_name, rng)

    async with semaphore:
        loop = asyncio.get_running_loop()
        with tempfile.NamedTemporaryFile(suffix=".h265", delete=False) as tmp:
            tmp.write(mutated)
            tmp_path = tmp.name
        try:
            decode = await loop.run_in_executor(
                None, run_decoder, decoder, tmp_path, timeout
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    crash_hash: str | None = None
    if decode.outcome in (Outcome.CRASH, Outcome.ABORT):
        crash_hash = hashlib.sha256(mutated).hexdigest()[:16]
        crashes_dir.mkdir(parents=True, exist_ok=True)
        (crashes_dir / f"{crash_hash}.h265").write_bytes(mutated)
        (crashes_dir / f"{crash_hash}.txt").write_text(decode.stderr)

    return IterationResult(
        iteration=i,
        mutator=mutator_name,
        seed_rng=iter_rng_seed,
        outcome=decode.outcome.value,
        returncode=decode.returncode,
        bytes_changed=result.bytes_changed,
        detail=result.detail,
        crash_hash=crash_hash,
    )


async def fuzz_async(
    seed_path: str | Path,
    output_dir: str | Path,
    iterations: int,
    decoder: str,
    timeout: float,
    seed_rng: int,
    mutators: list[str] | None,
    concurrency: int,
) -> list[IterationResult]:
    """Run ``iterations`` mutate+decode cycles in parallel via asyncio.

    Writes per-iteration outcomes to ``<output_dir>/results.jsonl`` and crash
    artifacts under ``<output_dir>/crashes/``.
    """
    seed_data = Path(seed_path).read_bytes()
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    crashes_dir = out_dir / "crashes"

    from .mutators import list_mutators

    mutator_pool = mutators or list_mutators()
    base_rng = random.Random(seed_rng)

    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    for i in range(iterations):
        mutator_name = base_rng.choice(mutator_pool)
        iter_rng_seed = base_rng.randrange(2**32)
        tasks.append(
            _run_iteration(
                i,
                seed_data,
                mutator_name,
                iter_rng_seed,
                decoder,
                timeout,
                crashes_dir,
                semaphore,
            )
        )

    results = await asyncio.gather(*tasks)
    results.sort(key=lambda r: r.iteration)

    results_path = out_dir / "results.jsonl"
    with results_path.open("w") as fh:
        for r in results:
            fh.write(json.dumps(asdict(r)) + "\n")
    return results


def fuzz_file(
    seed_path: str | Path,
    output_dir: str | Path,
    iterations: int,
    decoder: str,
    timeout: float,
    seed_rng: int = 0,
    mutators: list[str] | None = None,
    concurrency: int = 4,
) -> list[IterationResult]:
    """Synchronous wrapper around :func:`fuzz_async`."""
    return asyncio.run(
        fuzz_async(
            seed_path,
            output_dir,
            iterations,
            decoder,
            timeout,
            seed_rng,
            mutators,
            concurrency,
        )
    )
