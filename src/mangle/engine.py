"""High-level mutate and fuzz orchestration."""

from __future__ import annotations

import asyncio
import hashlib
import json
import random
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path

from .bitstream import assemble_nal_units, split_nal_units
from .decoder import Outcome, run_decoder, run_decoder_pair
from .mutators import MutationResult, get_mutator
from .scheduler import make_scheduler
from .triage import signature_for


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
    # The base seed this iteration mutated. ``None`` for a single-``--seed``
    # campaign (the v0.1 shape — the seed is implicit in --seed). For a
    # crash-fed campaign (--seed-from-crashes) it is the basename of the crash
    # artifact used as the base seed, so the iteration stays fully replayable.
    base_seed: str | None = None
    # Crash-dedup signature (the same ASAN-top-frame / normalised-stderr
    # fingerprint :mod:`mangle.triage` uses), recorded for every crashing
    # iteration when the campaign was launched with ``crash_dedup=True``.
    # ``None`` when dedup is off (the default) or the iteration did not crash —
    # so the v0.1 results.jsonl shape is preserved field-for-field.
    dedup_signature: str | None = None
    # When ``crash_dedup`` is on and this iteration crashed: ``True`` if this
    # iteration's signature was *new* (so the ``crashes/<hash>.{h265,txt}``
    # artifacts were written), ``False`` if the signature had already been seen
    # by an earlier iteration in this campaign (the iteration is still
    # recorded — the count statistics stay honest — but the redundant artifact
    # write is suppressed). ``None`` when dedup is off or no crash.
    dedup_first: bool | None = None


def _collect_seeds(
    directory: str | Path,
    label: str,
    artifacts_name: str = "seed files",
) -> list[tuple[str, bytes]]:
    """Return ``(basename, bytes)`` for every ``*.h265`` file in *directory*.

    Used for both ``--seed-from-crashes`` (``label="crash"``,
    ``artifacts_name="crash artifacts"``) and ``--seed-corpus-dir``
    (``label="corpus"``). Files are returned sorted by basename so the seed
    pool — and every per-iteration seed assignment derived from it — is
    deterministic regardless of filesystem listing order. Non-``*.h265`` files
    (e.g. a sibling ``manifest.json``) are ignored.
    """
    d = Path(directory)
    if not d.is_dir():
        raise FileNotFoundError(
            f"no such {label} directory: {directory} "
            f"(expected a directory of *.h265 seed files)"
        )
    files = sorted(d.glob("*.h265"), key=lambda p: p.name)
    seeds = [(p.name, p.read_bytes()) for p in files]
    if not seeds:
        raise ValueError(
            f"no *.h265 {artifacts_name} found in {directory} — nothing to seed from"
        )
    return seeds


class _DedupRegistry:
    """Live crash-signature registry for in-campaign deduplication.

    A campaign launched with ``crash_dedup=True`` writes each crashing mutant's
    ``crashes/<hash>.{h265,txt}`` artifact only on the *first* occurrence of
    its signature. Subsequent crashing iterations whose signature matches an
    already-seen one are still recorded in ``results.jsonl`` (so the outcome
    counts stay honest), but the redundant artifact write is suppressed and
    the iteration's ``dedup_first`` flag is set to ``False``.

    The set of seen signatures is also persisted to
    ``<output_dir>/dedup-signatures.json`` at the end of the campaign so a
    follow-on campaign into the same output directory can resume from the same
    state (the post-processing :func:`mangle.triage.triage` cluster view stays
    consistent because the artifacts that *were* written are still the
    canonical representative for each cluster). On startup we load whatever the
    file already contains, so the registry is monotonic across resumes.

    The registry is shared between coroutines via a single ``asyncio.Lock`` —
    the check-and-insert must be atomic so two iterations that crash with the
    same signature in the same dispatch round can never both believe they were
    "first".
    """

    DEDUP_FILE = "dedup-signatures.json"

    def __init__(self, output_dir: Path, frame_depth: int = 3) -> None:
        self._output_dir = output_dir
        self._frame_depth = frame_depth
        self._seen: set[str] = set()
        self._lock = asyncio.Lock()
        # Resume: pick up signatures from a prior campaign in the same dir.
        path = output_dir / self.DEDUP_FILE
        if path.exists():
            try:
                payload = json.loads(path.read_text())
                self._seen = set(payload.get("signatures", []))
            except (OSError, ValueError):
                # A corrupt or unreadable file is non-fatal — start fresh; the
                # campaign will overwrite it with the post-run state.
                self._seen = set()

    async def check_and_record(self, stderr: str) -> tuple[str, bool]:
        """Return ``(signature, is_first)`` for one crash's stderr.

        Atomically computes the signature, checks whether it has been seen
        before, and (if not) records it. Concurrent callers in the same
        asyncio loop are serialised — the lock is the only safe primitive for
        a check-then-insert against a shared set in an async context.
        """
        sig = signature_for(stderr, frame_depth=self._frame_depth).signature
        async with self._lock:
            is_first = sig not in self._seen
            if is_first:
                self._seen.add(sig)
        return sig, is_first

    @property
    def unique_count(self) -> int:
        """Number of distinct crash signatures seen so far."""
        return len(self._seen)

    def persist(self) -> None:
        """Write the seen-signatures set to disk for resume."""
        path = self._output_dir / self.DEDUP_FILE
        self._output_dir.mkdir(parents=True, exist_ok=True)
        # ``sorted`` makes the file byte-stable for the same set of signatures —
        # easier to diff between campaigns / between resumes.
        path.write_text(
            json.dumps(
                {
                    "frame_depth": self._frame_depth,
                    "signatures": sorted(self._seen),
                },
                indent=2,
            )
            + "\n"
        )


async def _run_iteration(
    i: int,
    seed_data: bytes,
    mutator_name: str,
    iter_rng_seed: int,
    decoder: str,
    timeout: float,
    crashes_dir: Path,
    semaphore: asyncio.Semaphore,
    base_seed: str | None = None,
    dedup: _DedupRegistry | None = None,
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
    dedup_signature: str | None = None
    dedup_first: bool | None = None
    if decode.outcome in (Outcome.CRASH, Outcome.ABORT):
        crash_hash = hashlib.sha256(mutated).hexdigest()[:16]
        if dedup is not None:
            dedup_signature, dedup_first = await dedup.check_and_record(decode.stderr)
        # Write artifacts only on first occurrence — every iteration writes
        # when dedup is off; only the first-of-signature writes when dedup is
        # on. The check-and-record above is atomic, so concurrent crashes with
        # the same signature have exactly one winner.
        if dedup is None or dedup_first:
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
        base_seed=base_seed,
        dedup_signature=dedup_signature,
        dedup_first=dedup_first,
    )


# An outcome is a "reward" for the adaptive scheduler when the decoder failed —
# this is the only feedback signal a black-box harness gets.
_REWARD_OUTCOMES = {Outcome.CRASH.value, Outcome.ABORT.value}


async def fuzz_async(
    seed_path: str | Path | None,
    output_dir: str | Path,
    iterations: int,
    decoder: str,
    timeout: float,
    seed_rng: int,
    mutators: list[str] | None,
    concurrency: int,
    strategy: str = "uniform",
    seed_from_crashes: str | Path | None = None,
    seed_corpus_dir: str | Path | None = None,
    time_limit: float | None = None,
    clock: Callable[[], float] | None = None,
    scheduler_state: dict | None = None,
    crash_dedup: bool = False,
    dedup_frame_depth: int = 3,
    max_crashes: int | None = None,
    max_time_without_crash: float | None = None,
) -> list[IterationResult]:
    """Run ``iterations`` mutate+decode cycles and record outcomes.

    Writes per-iteration outcomes to ``<output_dir>/results.jsonl`` and crash
    artifacts under ``<output_dir>/crashes/``.

    The base input each iteration mutates comes from one of three mutually
    exclusive sources:

    - ``seed_path`` (the v0.1 shape): a single seed file. Every iteration mutates
      it; ``base_seed`` is recorded as ``None``.
    - ``seed_from_crashes``: a previous campaign's ``crashes/`` directory. The
      crash artifacts (``<hash>.h265``) become the base-seed pool, closing the
      fuzzing feedback loop — a crash is re-mutated to explore the state around
      it. Iterations are assigned across the pool round-robin (deterministic), and
      each iteration records the basename of the crash artifact it mutated so the
      run stays fully replayable.
    - ``seed_corpus_dir``: any directory of ``*.h265`` seed files — typically the
      output of ``mangle corpus`` or ``mangle corpus-trim``, but any directory of
      valid H.265 streams works. The seeds become the base-seed pool, sorted by
      filename for determinism, and iterations are assigned across the pool
      round-robin by iteration index (the same dispatch as
      ``seed_from_crashes``). Each iteration records the basename of the seed it
      mutated so the run stays fully replayable via ``mangle replay`` with the
      same ``--seed-dir`` form.

    ``strategy`` selects the mutator-scheduling policy:

    - ``"uniform"`` (default): every mutator is equally likely on every
      iteration. With no ``time_limit`` all iterations are dispatched at once and
      run in parallel up to ``concurrency``; with a single seed the RNG draw
      stream is byte-identical to v0.1, so a campaign's mutator/seed sequence is
      unchanged.
    - ``"adaptive"``: an outcome-feedback bandit biases selection toward mutators
      that have produced crashes/aborts. Iterations run in rounds of
      ``concurrency`` so each round's verdicts update the scheduler before the
      next round is selected. Still fully deterministic for a given ``seed_rng``.

    ``time_limit`` (seconds) is an optional wall-clock budget for the whole
    campaign. When set, ``--iterations`` becomes an upper bound: the campaign
    stops dispatching new iterations as soon as the deadline passes, whichever
    limit is reached first. Iterations already dispatched run to completion, so
    the deadline is a soft stop (no in-flight decode is killed). When
    ``time_limit`` is ``None`` (the default) the budget is unlimited and the
    fast single-shot dispatch path — and the exact v0.1 RNG stream — is
    preserved. A time-budgeted run is non-deterministic in its iteration *count*
    (it depends on the wall clock), but every iteration that runs is still
    individually replayable: its mutator and per-iteration ``seed_rng`` are
    recorded in ``results.jsonl`` exactly as before. ``clock`` is the monotonic
    time source (injectable for testing).

    ``max_time_without_crash`` (seconds) is an optional stagnation-stop:
    if no *new* unique crash signature is discovered for this many consecutive
    wall-clock seconds the campaign stops dispatching new iterations, even if
    the ``iterations`` budget and ``time_limit`` have not been reached. The
    window is measured from campaign start (or the last new crash, whichever is
    more recent). Like ``max_crashes``, this guard requires ``crash_dedup=True``
    — unique crash counting is only possible when in-campaign deduplication is
    active. Checked at round boundaries (not mid-round); in-flight decodes are
    never killed. ``None`` (the default) disables the stagnation check.
    """
    sources_supplied = sum(
        x is not None for x in (seed_path, seed_from_crashes, seed_corpus_dir)
    )
    if sources_supplied > 1:
        raise ValueError(
            "fuzz takes exactly one base-input source: --seed OR "
            "--seed-from-crashes OR --seed-corpus-dir, not more than one"
        )
    if sources_supplied == 0:
        raise ValueError(
            "fuzz requires --seed or --seed-from-crashes or --seed-corpus-dir"
        )
    if time_limit is not None and time_limit <= 0:
        raise ValueError(
            f"--time-limit must be a positive number of seconds (got {time_limit})"
        )
    if max_crashes is not None and max_crashes <= 0:
        raise ValueError(
            f"--max-crashes must be a positive integer (got {max_crashes})"
        )
    if max_crashes is not None and not crash_dedup:
        raise ValueError(
            "--max-crashes requires --crash-dedup: unique crash counting is only "
            "possible when in-campaign deduplication is active"
        )
    if max_time_without_crash is not None and max_time_without_crash <= 0:
        raise ValueError(
            f"--max-time-without-crash must be a positive number of seconds "
            f"(got {max_time_without_crash})"
        )
    if max_time_without_crash is not None and not crash_dedup:
        raise ValueError(
            "--max-time-without-crash requires --crash-dedup: the stagnation "
            "check counts *new unique* crashes, which is only possible when "
            "in-campaign deduplication is active"
        )
    # Resolve the time source at call time (not at def time) so a test can patch
    # ``engine.time.monotonic`` and have it take effect here.
    if clock is None:
        clock = time.monotonic

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    crashes_dir = out_dir / "crashes"

    # In-campaign crash deduplication: when on, every crashing iteration's
    # stderr is fingerprinted with the same signature mangle triage uses, and
    # only the first occurrence of each signature writes the
    # ``crashes/<hash>.{h265,txt}`` artifact pair — duplicates of an already-
    # seen bug add a results.jsonl row (so the count stats stay honest) but
    # not a redundant artifact. ``None`` means dedup is off — the v0.1 path.
    dedup = (
        _DedupRegistry(out_dir, frame_depth=dedup_frame_depth)
        if crash_dedup
        else None
    )

    # Build the base-seed pool: one (--seed) or many (--seed-from-crashes /
    # --seed-corpus-dir). ``seed_pool`` is a list of (basename | None, bytes);
    # a None basename marks the single-seed v0.1 case so its results record
    # base_seed=None.
    if seed_from_crashes is not None:
        seed_pool: list[tuple[str | None, bytes]] = list(
            _collect_seeds(seed_from_crashes, "crash", artifacts_name="crash artifacts")
        )
    elif seed_corpus_dir is not None:
        seed_pool = list(_collect_seeds(seed_corpus_dir, "corpus"))
    else:
        seed_pool = [(None, Path(seed_path).read_bytes())]

    from .mutators import list_mutators

    mutator_pool = mutators or list_mutators()
    base_rng = random.Random(seed_rng)
    scheduler = make_scheduler(strategy, mutator_pool)
    if scheduler_state is not None:
        if strategy == "uniform":
            raise ValueError(
                "scheduler_state is only meaningful with --strategy adaptive "
                "(the uniform scheduler does not learn)"
            )
        arms = scheduler_state.get("arms")
        if arms is None:
            raise ValueError(
                "scheduler_state must contain an 'arms' mapping "
                "(the shape written by a prior campaign's scheduler.json)"
            )
        scheduler.load_state(arms)
    semaphore = asyncio.Semaphore(concurrency)

    def _seed_for(i: int) -> tuple[str | None, bytes]:
        # Round-robin over the pool by iteration index — a pure function of i, so
        # the assignment is deterministic and independent of decode completion
        # order. For a single seed this is always element 0, so the v0.1 RNG draw
        # stream (mutator pick + iter seed) is unchanged.
        return seed_pool[i % len(seed_pool)]

    # A wall-clock budget converts ``iterations`` into an upper bound: dispatch
    # stops once this deadline passes. ``None`` means no budget — the v0.1 path.
    deadline = clock() + time_limit if time_limit is not None else None

    def _budget_exhausted() -> bool:
        return deadline is not None and clock() >= deadline

    # Stagnation tracking: ``last_new_crash_time`` is the monotonic timestamp at
    # which the most recent *new* unique crash was discovered (or the campaign
    # start time if no crash has been found yet).  When max_time_without_crash is
    # set we check at every round boundary whether the gap has been exceeded.
    # Using a mutable container so the inner closure can rebind it.
    # Only read the clock here when stagnation tracking is active — tests that
    # patch the clock for time_limit tests must not see an extra read.
    _last_new_crash = [clock() if max_time_without_crash is not None else 0.0]

    def _stagnated() -> bool:
        if max_time_without_crash is None:
            return False
        return clock() - _last_new_crash[0] >= max_time_without_crash

    if strategy == "uniform" and time_limit is None and max_crashes is None and max_time_without_crash is None:
        # Single-shot dispatch preserves the exact v0.1 RNG stream and the full
        # parallelism of one big asyncio.gather. Only taken when there is no
        # time budget and no --max-crashes cap, so a plain ``--iterations``
        # campaign is byte-for-byte the same as earlier releases.
        tasks = []
        for i in range(iterations):
            mutator_name = scheduler.select(base_rng)
            iter_rng_seed = base_rng.randrange(2**32)
            base_name, seed_data = _seed_for(i)
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
                    base_seed=base_name,
                    dedup=dedup,
                )
            )
        results = await asyncio.gather(*tasks)
    else:
        # Round-based dispatch. Adaptive mode needs it so each round's outcomes
        # feed the scheduler before the next round is chosen; the uniform +
        # time_limit case needs it so the deadline can actually halt dispatch
        # between rounds (a single giant gather could not be interrupted). Round
        # size is ``concurrency`` to keep the same parallelism budget either way.
        results = []
        round_size = max(1, concurrency)
        for start in range(0, iterations, round_size):
            # Stop launching new work once the wall-clock budget is spent. Already
            # dispatched rounds have completed; in-flight decodes are never killed.
            if _budget_exhausted():
                break
            # Stop once the unique-crash cap is reached. Checked at round
            # boundaries (not mid-round) because dedup state is updated
            # asynchronously within a round and a mid-round check would
            # require a lock. dedup is guaranteed non-None here because
            # fuzz_async() raises ValueError if max_crashes is set without
            # crash_dedup.
            if max_crashes is not None and dedup is not None and dedup.unique_count >= max_crashes:
                break
            # Stop when the stagnation window has elapsed with no new unique
            # crash. Checked at round boundaries (not mid-round) for the same
            # reason as the max_crashes check above.
            if _stagnated():
                break
            count = min(round_size, iterations - start)
            round_tasks = []
            picks = []
            for j in range(count):
                mutator_name = scheduler.select(base_rng)
                iter_rng_seed = base_rng.randrange(2**32)
                base_name, seed_data = _seed_for(start + j)
                picks.append(mutator_name)
                round_tasks.append(
                    _run_iteration(
                        start + j,
                        seed_data,
                        mutator_name,
                        iter_rng_seed,
                        decoder,
                        timeout,
                        crashes_dir,
                        semaphore,
                        base_seed=base_name,
                        dedup=dedup,
                    )
                )
            round_results = await asyncio.gather(*round_tasks)
            for pick, res in zip(picks, round_results):
                scheduler.update(pick, res.outcome in _REWARD_OUTCOMES)
            # Update the stagnation clock whenever a *new* unique crash appeared
            # in this round (dedup_first=True means the signature had not been
            # seen before). Checked after every round so the window resets as
            # soon as a novel crash lands.
            if max_time_without_crash is not None and any(
                r.dedup_first is True for r in round_results
            ):
                _last_new_crash[0] = clock()
            results.extend(round_results)

    results.sort(key=lambda r: r.iteration)

    results_path = out_dir / "results.jsonl"
    with results_path.open("w") as fh:
        for r in results:
            fh.write(json.dumps(asdict(r)) + "\n")

    if dedup is not None:
        dedup.persist()

    if strategy != "uniform":
        # Emit the learned per-mutator scoreboard so a campaign's prioritisation
        # decisions are auditable alongside the raw results.
        scoreboard_path = out_dir / "scheduler.json"
        scoreboard = {
            "strategy": strategy,
            # The actual iterations dispatched, which a --time-limit budget may
            # cut below the requested upper bound.
            "iterations": len(results),
            "arms": scheduler.stats(),
        }
        if scheduler_state is not None:
            # Carry a breadcrumb so a chained resume (run -> run -> run) is
            # self-documenting in the artifact itself.
            scoreboard["resumed_from_prior_iterations"] = int(
                scheduler_state.get("iterations", 0)
            )
        scoreboard_path.write_text(json.dumps(scoreboard, indent=2) + "\n")

    return results


def fuzz_file(
    seed_path: str | Path | None,
    output_dir: str | Path,
    iterations: int,
    decoder: str,
    timeout: float,
    seed_rng: int = 0,
    mutators: list[str] | None = None,
    concurrency: int = 4,
    strategy: str = "uniform",
    seed_from_crashes: str | Path | None = None,
    seed_corpus_dir: str | Path | None = None,
    time_limit: float | None = None,
    clock: Callable[[], float] | None = None,
    scheduler_state: dict | None = None,
    crash_dedup: bool = False,
    dedup_frame_depth: int = 3,
    max_crashes: int | None = None,
    max_time_without_crash: float | None = None,
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
            strategy,
            seed_from_crashes,
            seed_corpus_dir,
            time_limit,
            clock,
            scheduler_state,
            crash_dedup=crash_dedup,
            dedup_frame_depth=dedup_frame_depth,
            max_crashes=max_crashes,
            max_time_without_crash=max_time_without_crash,
        )
    )


# ---------------------------------------------------------------------------
# Differential decoder oracle (POST_V01 item #6)
# ---------------------------------------------------------------------------


@dataclass
class DiffResult:
    iteration: int
    mutator: str
    seed_rng: int
    diverged: bool
    kind: str
    left_decoder: str
    left_outcome: str
    left_returncode: int | None
    right_decoder: str
    right_outcome: str
    right_returncode: int | None
    bytes_changed: int
    detail: str
    divergence_hash: str | None = None
    # SHA256 of each decoder's captured raw-frame stdout when the campaign
    # was run with ``compare_output=True``; ``None`` otherwise (or on a
    # decoder timeout). When both are populated and the kind is
    # ``"output-divergence"`` the two hashes differ — the silent-acceptor
    # signal.
    left_output_hash: str | None = None
    right_output_hash: str | None = None


async def _run_diff_iteration(
    i: int,
    seed_data: bytes,
    mutator_name: str,
    iter_rng_seed: int,
    left_decoder: str,
    right_decoder: str,
    timeout: float,
    divergences_dir: Path,
    semaphore: asyncio.Semaphore,
    compare_output: bool = False,
) -> DiffResult:
    rng = random.Random(iter_rng_seed)
    mutated, result = mutate_bytes(seed_data, mutator_name, rng)

    async with semaphore:
        loop = asyncio.get_running_loop()
        with tempfile.NamedTemporaryFile(suffix=".h265", delete=False) as tmp:
            tmp.write(mutated)
            tmp_path = tmp.name
        try:
            # run_in_executor does not accept kwargs, so always wrap in a
            # lambda — this also handles the compare_output=False case cleanly.
            divergence = await loop.run_in_executor(
                None,
                lambda: run_decoder_pair(
                    left_decoder,
                    right_decoder,
                    tmp_path,
                    timeout,
                    compare_output=compare_output,
                ),
            )
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    divergence_hash: str | None = None
    if divergence.diverged:
        divergence_hash = hashlib.sha256(mutated).hexdigest()[:16]
        divergences_dir.mkdir(parents=True, exist_ok=True)
        (divergences_dir / f"{divergence_hash}.h265").write_bytes(mutated)
        # Write both decoders' stderr side by side so the divergence is
        # self-documenting (the artifact alone explains why it was kept).
        # For output-divergence kinds the stderrs are typically empty (both
        # decoders ran cleanly); the output hashes carry the signal, so we
        # surface them in the report as well.
        left_hash_line = (
            f" output_hash={divergence.left.output_hash}"
            if divergence.left.output_hash is not None
            else ""
        )
        right_hash_line = (
            f" output_hash={divergence.right.output_hash}"
            if divergence.right.output_hash is not None
            else ""
        )
        report = (
            f"=== {divergence.kind} ===\n"
            f"--- {left_decoder} ({divergence.left.outcome.value}, "
            f"rc={divergence.left.returncode}){left_hash_line} ---\n"
            f"{divergence.left.stderr}\n"
            f"--- {right_decoder} ({divergence.right.outcome.value}, "
            f"rc={divergence.right.returncode}){right_hash_line} ---\n"
            f"{divergence.right.stderr}\n"
        )
        (divergences_dir / f"{divergence_hash}.txt").write_text(report)

    return DiffResult(
        iteration=i,
        mutator=mutator_name,
        seed_rng=iter_rng_seed,
        diverged=divergence.diverged,
        kind=divergence.kind,
        left_decoder=left_decoder,
        left_outcome=divergence.left.outcome.value,
        left_returncode=divergence.left.returncode,
        right_decoder=right_decoder,
        right_outcome=divergence.right.outcome.value,
        right_returncode=divergence.right.returncode,
        bytes_changed=result.bytes_changed,
        detail=result.detail,
        divergence_hash=divergence_hash,
        left_output_hash=divergence.left.output_hash,
        right_output_hash=divergence.right.output_hash,
    )


async def diff_async(
    seed_path: str | Path,
    output_dir: str | Path,
    iterations: int,
    left_decoder: str,
    right_decoder: str,
    timeout: float,
    seed_rng: int,
    mutators: list[str] | None,
    concurrency: int,
    compare_output: bool = False,
) -> list[DiffResult]:
    """Run ``iterations`` mutate+decode-pair cycles and record divergences.

    Each mutant is fed through *two* decoders; when they disagree on the crash
    class the mutant and a side-by-side stderr report are written under
    ``<output_dir>/divergences/``. All per-iteration outcomes are written to
    ``<output_dir>/diff.jsonl``.
    """
    if left_decoder == right_decoder:
        raise ValueError(
            "diff requires two different decoders "
            f"(got '{left_decoder}' twice)"
        )

    seed_data = Path(seed_path).read_bytes()
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    divergences_dir = out_dir / "divergences"

    from .mutators import list_mutators

    mutator_pool = mutators or list_mutators()
    base_rng = random.Random(seed_rng)

    semaphore = asyncio.Semaphore(concurrency)
    tasks = []
    for i in range(iterations):
        mutator_name = base_rng.choice(mutator_pool)
        iter_rng_seed = base_rng.randrange(2**32)
        tasks.append(
            _run_diff_iteration(
                i,
                seed_data,
                mutator_name,
                iter_rng_seed,
                left_decoder,
                right_decoder,
                timeout,
                divergences_dir,
                semaphore,
                compare_output=compare_output,
            )
        )

    results = await asyncio.gather(*tasks)
    results.sort(key=lambda r: r.iteration)

    results_path = out_dir / "diff.jsonl"
    with results_path.open("w") as fh:
        for r in results:
            fh.write(json.dumps(asdict(r)) + "\n")
    return results


def diff_file(
    seed_path: str | Path,
    output_dir: str | Path,
    iterations: int,
    left_decoder: str,
    right_decoder: str,
    timeout: float,
    seed_rng: int = 0,
    mutators: list[str] | None = None,
    concurrency: int = 4,
    compare_output: bool = False,
) -> list[DiffResult]:
    """Synchronous wrapper around :func:`diff_async`."""
    return asyncio.run(
        diff_async(
            seed_path,
            output_dir,
            iterations,
            left_decoder,
            right_decoder,
            timeout,
            seed_rng,
            mutators,
            concurrency,
            compare_output=compare_output,
        )
    )
