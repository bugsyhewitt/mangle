"""Crash test-case minimiser (NAL-aware delta debugging).

``mangle triage`` deduplicates a fuzz campaign down to one *representative*
crashing input per bug, picking the smallest mutant that already exists. But the
smallest mutant a campaign happened to produce is rarely the *minimal* one: a
mutant carries the seed's full NAL framing (VPS, SPS, PPS, SEI, several slices)
even when only one of those NAL units is load-bearing for the crash. Responsible
disclosure and root-cause analysis both want the *minimal reproducer* — the
fewest NAL units that still trigger the same bug. This is the ``afl-tmin`` /
``creduce`` step of a fuzzing workflow, the natural complement to ``triage``.

mangle's grammar awareness lets the reducer work at the *NAL-unit* granularity
rather than the byte granularity a generic minimiser uses. It applies the classic
**ddmin** delta-debugging algorithm (Zeller & Hildebrandt, "Simplifying and
Isolating Failure-Inducing Input", IEEE TSE 2002) over the list of NAL units:

  1. Split the NAL-unit list into ``n`` chunks (starting with ``n = 2``).
  2. Try each chunk alone, then each *complement* (the input with one chunk
     removed). Any candidate that still reproduces the crash becomes the new
     working input — restart, narrowing or coarsening ``n`` per ddmin's rules.
  3. When no single removal helps, increase the granularity (``n``) up to the
     current NAL count; stop when no further removal preserves the crash.

The "does it still crash?" oracle is **signature-stable**, not merely
"does it exit non-zero": the reducer keeps a candidate only when the decoder's
crash *signature* (the same ASAN-top-frame / normalised-stderr fingerprint used
by :mod:`mangle.triage`) matches the original crash's signature. That prevents
the reducer from "succeeding" by swapping the original bug for a *different*
crash — a notorious failure mode of naive minimisers.

The decode oracle is injected (``decode_fn``) exactly as the decoder ``runner``
is elsewhere, so the reducer is fully unit-testable without ffmpeg/libde265
installed. The default oracle shells out to :func:`mangle.decoder.run_decoder`.

Outputs:

  * the minimal mutant is written to ``--output``;
  * a :class:`ReduceResult` summarises the reduction (original/minimal NAL count
    and byte size, number of decode probes, and whether the signature held).

The reduction is deterministic: ddmin's chunk order is fixed and the oracle is a
pure function of the candidate bytes.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .bitstream import NalUnit, assemble_nal_units, split_nal_units
from .decoder import Outcome, run_decoder
from .triage import signature_for

# A decode oracle maps candidate bytes -> (is_crash, crash_signature_string).
# The signature string is compared for equality to decide whether a candidate
# reproduces the *same* crash. ``is_crash`` is False for clean / timeout / hang.
DecodeFn = Callable[[bytes], "ProbeResult"]


@dataclass
class ProbeResult:
    """The outcome of decoding one reduction candidate.

    Attributes:
        is_crash: True when the decoder hit a crash-class outcome
            (``crash`` or ``abort``), the only outcomes the reducer treats as
            "still reproduces".
        signature: the stable crash signature (ASAN top frames or normalised
            stderr hash); empty string when ``is_crash`` is False.
    """

    is_crash: bool
    signature: str


def make_decoder_oracle(
    decoder: str,
    timeout: float,
    frame_depth: int = 3,
    runner=None,
) -> DecodeFn:
    """Build a decode oracle that shells out to a real decoder.

    The returned function writes the candidate to a temp file, runs the decoder,
    and returns a :class:`ProbeResult` carrying the crash signature. ``runner``
    is forwarded to :func:`mangle.decoder.run_decoder` so tests can inject a fake
    subprocess; when ``None`` the real ``subprocess.run`` is used.
    """
    import subprocess
    import tempfile

    real_runner = runner if runner is not None else subprocess.run

    def oracle(candidate: bytes) -> ProbeResult:
        with tempfile.NamedTemporaryFile(suffix=".h265", delete=False) as tmp:
            tmp.write(candidate)
            tmp_path = tmp.name
        try:
            result = run_decoder(decoder, tmp_path, timeout, runner=real_runner)
        finally:
            Path(tmp_path).unlink(missing_ok=True)
        is_crash = result.outcome in (Outcome.CRASH, Outcome.ABORT)
        if not is_crash:
            return ProbeResult(is_crash=False, signature="")
        sig = signature_for(result.stderr, frame_depth=frame_depth)
        return ProbeResult(is_crash=True, signature=sig.signature)

    return oracle


@dataclass
class ReduceResult:
    """Summary of one minimisation run.

    Attributes:
        original_nals: NAL-unit count of the input crash.
        minimal_nals: NAL-unit count of the minimal reproducer.
        original_bytes: byte size of the input crash.
        minimal_bytes: byte size of the minimal reproducer.
        probes: number of decode probes the reducer performed.
        signature: the crash signature that was preserved throughout.
        output_path: where the minimal reproducer was written (or ``None`` when
            the reducer was run in-memory).
    """

    original_nals: int
    minimal_nals: int
    original_bytes: int
    minimal_bytes: int
    probes: int
    signature: str
    output_path: str | None = None


def _reproduces(
    nals: list[NalUnit],
    target_signature: str,
    decode_fn: DecodeFn,
) -> bool:
    """True when this NAL subset still produces the target crash signature."""
    if not nals:
        return False
    candidate = assemble_nal_units(nals)
    probe = decode_fn(candidate)
    return probe.is_crash and probe.signature == target_signature


def ddmin_nals(
    nals: list[NalUnit],
    target_signature: str,
    decode_fn: DecodeFn,
) -> tuple[list[NalUnit], int]:
    """Run ddmin over a NAL-unit list, preserving ``target_signature``.

    Returns ``(minimal_nals, probe_count)``. ``minimal_nals`` is a 1-minimal
    subset: no single chunk can be removed without losing the crash signature.

    This is the classic ddmin (Zeller & Hildebrandt 2002): test complements
    first (coarse reductions), fall back to subsets, and increase granularity
    only when neither helps.
    """
    probes = 0

    def reproduces(subset: list[NalUnit]) -> bool:
        nonlocal probes
        probes += 1
        return _reproduces(subset, target_signature, decode_fn)

    working = list(nals)
    n = 2
    while len(working) >= 2:
        chunk_size = max(1, len(working) // n)
        chunks = [
            working[i : i + chunk_size] for i in range(0, len(working), chunk_size)
        ]

        # Try complements first (remove one chunk) — the biggest reductions.
        reduced = False
        for i in range(len(chunks)):
            complement = [
                nal for j, chunk in enumerate(chunks) if j != i for nal in chunk
            ]
            if complement and reproduces(complement):
                working = complement
                n = max(n - 1, 2)
                reduced = True
                break
        if reduced:
            continue

        # Then try each chunk alone — aggressive reductions to a single chunk.
        for chunk in chunks:
            if chunk and reproduces(chunk):
                working = chunk
                n = 2
                reduced = True
                break
        if reduced:
            continue

        # Neither helped: increase granularity, or stop when maxed out.
        if n >= len(working):
            break
        n = min(len(working), n * 2)

    return working, probes


def reduce_crash(
    crash_bytes: bytes,
    decode_fn: DecodeFn,
) -> tuple[bytes, ReduceResult]:
    """Minimise a crashing input in memory, preserving its crash signature.

    Decodes the input once to establish the target signature, then runs ddmin
    over its NAL units. Returns the minimal reproducer bytes and a
    :class:`ReduceResult`. Raises :class:`ValueError` when the input does not
    crash (nothing to reduce) or contains no NAL units.
    """
    nals = split_nal_units(crash_bytes)
    if not nals:
        raise ValueError("input contains no NAL units")

    baseline = decode_fn(crash_bytes)
    if not baseline.is_crash:
        raise ValueError(
            "input does not crash the decoder — nothing to minimise "
            "(reduce operates on confirmed crash reproducers)"
        )
    target_signature = baseline.signature

    minimal_nals, probes = ddmin_nals(nals, target_signature, decode_fn)
    minimal_bytes = assemble_nal_units(minimal_nals)

    return minimal_bytes, ReduceResult(
        original_nals=len(nals),
        minimal_nals=len(minimal_nals),
        original_bytes=len(crash_bytes),
        minimal_bytes=len(minimal_bytes),
        probes=probes + 1,  # +1 for the baseline decode
        signature=target_signature,
    )


def reduce_file(
    crash_path: str | Path,
    output_path: str | Path,
    decoder: str = "ffmpeg",
    timeout: float = 5.0,
    frame_depth: int = 3,
    decode_fn: DecodeFn | None = None,
    runner=None,
) -> ReduceResult:
    """Minimise a crash file on disk and write the minimal reproducer.

    Reads ``crash_path``, builds (or uses the injected) decode oracle, runs the
    NAL-aware ddmin, and writes the minimal reproducer to ``output_path``.
    Returns a :class:`ReduceResult` with ``output_path`` populated.

    ``decode_fn`` is injectable for testing; when ``None`` a real-decoder oracle
    is built from ``decoder`` / ``timeout`` (``runner`` is forwarded to it).
    """
    crash_bytes = Path(crash_path).read_bytes()
    oracle = decode_fn or make_decoder_oracle(
        decoder, timeout, frame_depth=frame_depth, runner=runner
    )
    minimal_bytes, result = reduce_crash(crash_bytes, oracle)
    Path(output_path).write_bytes(minimal_bytes)
    result.output_path = str(output_path)
    return result
