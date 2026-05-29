"""Corpus minimiser (afl-cmin / corpus-trim).

``mangle corpus`` *builds* a diverse seed set and ``mangle reduce`` minimises a
single *crash*; neither shrinks a whole *corpus*. A corpus accumulated over many
campaigns (hand-collected seeds, generated seeds, crash-derived seeds, samples
pulled from the wild) is almost always redundant: dozens of files exercise the
exact same decoder behaviour, only differing in incidental bytes. Carrying that
redundancy slows every coverage-guided or manual campaign — each extra seed is an
extra decode per pass that buys no new behaviour.

This module is the ``afl-cmin`` step of the workflow: given a directory of seed
files, it keeps a **minimal subset** that preserves the corpus's full set of
observed decoder *behaviours*, dropping every redundant seed.

The behaviour of a seed is its decode *signature*, computed exactly as
:mod:`mangle.triage` and :mod:`mangle.reduce` compute a crash signature, then
keyed on the decode outcome so that distinct non-crash behaviours stay distinct:

  * **crash / abort** → the triage signature (ASAN top frames when a sanitizer
    build is present, else a normalised-stderr hash). Two seeds that crash with
    the same fingerprint are the same behaviour.
  * **clean** → all cleanly-decoding seeds collapse to one ``clean`` behaviour
    (a corpus needs only one representative well-framed seed).
  * **timeout / hang** → kept as their own behaviour buckets (a seed that wedges
    the decoder is worth keeping a representative of).

Within each behaviour bucket the **representative** is the most useful seed to
keep: the smallest file (cheapest to re-decode, most minimal), tie-broken by
file name for full determinism. Every other seed in the bucket is dropped as
redundant.

The decode probe is injected (``probe_fn``) exactly as the decoder ``runner`` is
elsewhere, so the trimmer is fully unit-testable without ffmpeg/libde265
installed. The default probe shells out to :func:`mangle.decoder.run_decoder`.

Outputs (for the directory entry point):

  * the kept seeds are copied into ``output_dir`` verbatim;
  * ``trim-manifest.json`` records every input seed, its behaviour key, whether
    it was kept or dropped, and (for dropped seeds) which representative
    subsumed it.

The trim is deterministic: seeds are processed in sorted file-name order and the
probe is a pure function of the seed bytes.

References: corpus minimisation is the ``afl-cmin`` / ``llvm-merge`` step of every
coverage-guided fuzzing workflow; behaviour-bucket dedup mirrors the
ClusterFuzz / OSS-Fuzz minimisation practice that mangle's :mod:`triage` already
applies to *crashes*, here generalised to a whole seed corpus.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from .decoder import Outcome, run_decoder
from .triage import signature_for

# A probe maps seed bytes -> the seed's decode behaviour. ``outcome`` is the
# decoder outcome string ("clean" / "crash" / "abort" / "timeout" / "hang") and
# ``signature`` is the crash signature for crash/abort outcomes, else "".
ProbeFn = Callable[[bytes], "BehaviourProbe"]


@dataclass
class BehaviourProbe:
    """The decode behaviour of one corpus seed.

    Attributes:
        outcome: the decoder outcome string for the seed.
        signature: the crash signature (ASAN top frames or normalised-stderr
            hash) when ``outcome`` is a crash class; empty string otherwise.
    """

    outcome: str
    signature: str = ""

    def behaviour_key(self) -> str:
        """Return the stable bucket key for this behaviour.

        Crash-class outcomes are keyed by ``<outcome>:<signature>`` so distinct
        crash fingerprints stay in distinct buckets; every other outcome is
        keyed by the outcome alone (all clean seeds share one bucket, etc.).
        """
        if self.signature:
            return f"{self.outcome}:{self.signature}"
        return self.outcome


def make_decoder_probe(
    decoder: str,
    timeout: float,
    frame_depth: int = 3,
    runner=None,
) -> ProbeFn:
    """Build a decode probe that shells out to a real decoder.

    The returned function writes the seed to a temp file, runs the decoder, and
    returns a :class:`BehaviourProbe`. ``runner`` is forwarded to
    :func:`mangle.decoder.run_decoder` so tests can inject a fake subprocess;
    when ``None`` the real ``subprocess.run`` is used.
    """
    import subprocess
    import tempfile

    real_runner = runner if runner is not None else subprocess.run

    def probe(seed: bytes) -> BehaviourProbe:
        with tempfile.NamedTemporaryFile(suffix=".h265", delete=False) as tmp:
            tmp.write(seed)
            tmp_path = tmp.name
        try:
            result = run_decoder(decoder, tmp_path, timeout, runner=real_runner)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        if result.outcome in (Outcome.CRASH, Outcome.ABORT):
            sig = signature_for(result.stderr, frame_depth=frame_depth)
            return BehaviourProbe(outcome=result.outcome.value, signature=sig.signature)
        return BehaviourProbe(outcome=result.outcome.value, signature="")

    return probe


@dataclass
class SeedVerdict:
    """The trim verdict for one input seed.

    Attributes:
        name: the seed's file name (or caller-supplied identifier).
        bytes: the seed's byte size.
        outcome: the decoder outcome for the seed.
        behaviour: the behaviour bucket key the seed fell into.
        kept: True when this seed is the representative of its bucket.
        subsumed_by: for a dropped seed, the name of the representative that
            covers its behaviour; ``None`` for a kept seed.
    """

    name: str
    bytes: int
    outcome: str
    behaviour: str
    kept: bool
    subsumed_by: str | None = None


@dataclass
class TrimResult:
    """Summary of one corpus-trim run.

    Attributes:
        input_count: number of seeds examined.
        kept_count: number of representative seeds kept.
        dropped_count: number of redundant seeds dropped.
        behaviour_count: number of distinct decoder behaviours preserved.
        probes: number of decode probes performed (one per input seed).
        verdicts: per-seed verdicts in deterministic (sorted-name) order.
        output_dir: where kept seeds were copied (``None`` for in-memory runs).
    """

    input_count: int
    kept_count: int
    dropped_count: int
    behaviour_count: int
    probes: int
    verdicts: list[SeedVerdict]
    output_dir: str | None = None


def trim_corpus(
    seeds: list[tuple[str, bytes]],
    probe_fn: ProbeFn,
) -> TrimResult:
    """Minimise an in-memory corpus, preserving every distinct decode behaviour.

    ``seeds`` is a list of ``(name, bytes)`` pairs. Each seed is probed once; the
    seeds are then bucketed by behaviour key and the smallest seed in each bucket
    (tie-broken by name) is kept as the representative. Returns a
    :class:`TrimResult` whose ``verdicts`` are in sorted-name order.

    Empty seeds (zero bytes) and an empty corpus are handled gracefully: an empty
    corpus yields an all-zero result with no verdicts.
    """
    # Deterministic processing order: sort by name.
    ordered = sorted(seeds, key=lambda s: s[0])

    probes = 0
    # behaviour key -> list of (name, size) members, in sorted-name order.
    buckets: dict[str, list[tuple[str, int]]] = {}
    behaviour_of: dict[str, str] = {}
    size_of: dict[str, int] = {}
    outcome_of: dict[str, str] = {}

    for name, data in ordered:
        result = probe_fn(data)
        probes += 1
        key = result.behaviour_key()
        size = len(data)
        behaviour_of[name] = key
        size_of[name] = size
        outcome_of[name] = result.outcome
        buckets.setdefault(key, []).append((name, size))

    # Representative per bucket: smallest size, tie-broken by name.
    representative: dict[str, str] = {}
    for key, members in buckets.items():
        rep_name = min(members, key=lambda m: (m[1], m[0]))[0]
        representative[key] = rep_name

    verdicts: list[SeedVerdict] = []
    for name, _data in ordered:
        key = behaviour_of[name]
        rep = representative[key]
        kept = name == rep
        verdicts.append(
            SeedVerdict(
                name=name,
                bytes=size_of[name],
                outcome=outcome_of[name],
                behaviour=key,
                kept=kept,
                subsumed_by=None if kept else rep,
            )
        )

    kept_count = sum(1 for v in verdicts if v.kept)
    return TrimResult(
        input_count=len(ordered),
        kept_count=kept_count,
        dropped_count=len(ordered) - kept_count,
        behaviour_count=len(buckets),
        probes=probes,
        verdicts=verdicts,
    )


def trim_corpus_dir(
    input_dir: str | Path,
    output_dir: str | Path,
    decoder: str = "ffmpeg",
    timeout: float = 5.0,
    frame_depth: int = 3,
    pattern: str = "*.h265",
    probe_fn: ProbeFn | None = None,
    runner=None,
) -> TrimResult:
    """Minimise a corpus directory and copy the kept seeds into ``output_dir``.

    Reads every file in ``input_dir`` matching ``pattern`` (default ``*.h265``),
    probes each through the decoder, keeps one representative per distinct decode
    behaviour, copies the kept seeds verbatim into ``output_dir``, and writes a
    ``trim-manifest.json`` listing every input seed's verdict. Returns a
    :class:`TrimResult` with ``output_dir`` populated.

    ``probe_fn`` is injectable for testing; when ``None`` a real-decoder probe is
    built from ``decoder`` / ``timeout`` (``runner`` is forwarded to it).

    Raises :class:`FileNotFoundError` when ``input_dir`` does not exist and
    :class:`ValueError` when it contains no files matching ``pattern``.
    """
    in_dir = Path(input_dir)
    if not in_dir.is_dir():
        raise FileNotFoundError(f"corpus directory not found: {in_dir}")

    seed_paths = sorted(p for p in in_dir.glob(pattern) if p.is_file())
    if not seed_paths:
        raise ValueError(f"no seeds matching {pattern!r} in {in_dir}")

    seeds = [(p.name, p.read_bytes()) for p in seed_paths]
    probe = probe_fn or make_decoder_probe(
        decoder, timeout, frame_depth=frame_depth, runner=runner
    )
    result = trim_corpus(seeds, probe)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    for verdict in result.verdicts:
        if verdict.kept:
            shutil.copy2(in_dir / verdict.name, out_dir / verdict.name)

    manifest = {
        "input_dir": str(in_dir),
        "input_count": result.input_count,
        "kept_count": result.kept_count,
        "dropped_count": result.dropped_count,
        "behaviour_count": result.behaviour_count,
        "verdicts": [asdict(v) for v in result.verdicts],
    }
    (out_dir / "trim-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    result.output_dir = str(out_dir)
    return result
