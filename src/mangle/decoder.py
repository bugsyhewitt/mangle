"""Decoder crash harness: feed mutants through ffmpeg / libde265.

The harness shells out to a decoder, applies a timeout, and classifies the
outcome. ffmpeg is invoked as ``ffmpeg -v error -i <mutant> -f null -`` so it
fully decodes without writing output.

[Worker decision: outcome taxonomy]
We classify outcomes as one of: ``clean``, ``crash``, ``timeout``, ``abort``,
``hang``. A negative return code indicates a signal (POSIX): SIGSEGV/SIGBUS map
to ``crash``; SIGABRT maps to ``abort`` (covers ASAN/assert aborts). A non-zero
*positive* exit is also treated as ``crash`` for fuzzing purposes per criterion
6 (segfault OR non-zero exit -> crash artifact). ``timeout`` is the wall-clock
timeout firing; ``hang`` is reserved for an externally-detected stuck process.
"""

from __future__ import annotations

import hashlib
import signal
import subprocess
from dataclasses import dataclass
from enum import Enum


class Outcome(str, Enum):
    CLEAN = "clean"
    CRASH = "crash"
    TIMEOUT = "timeout"
    ABORT = "abort"
    HANG = "hang"


@dataclass
class DecodeResult:
    outcome: Outcome
    returncode: int | None
    stderr: str
    decoder: str | None = None
    # SHA256 (hex) of the decoded raw-frame output. Populated only when
    # ``run_decoder(..., capture_output=True)`` was used and the decoder ran
    # to a non-timeout completion (CLEAN, CRASH, or ABORT — a partially
    # decoded crash still has bytes worth comparing against another decoder's
    # bytes). ``None`` otherwise. Used by the differential oracle's
    # output-divergence mode to spot silent decoder disagreements when both
    # decoders return CLEAN but produced different pixel data.
    output_hash: str | None = None


# Signals that indicate a hard crash vs. an intentional abort.
_CRASH_SIGNALS = {signal.SIGSEGV, signal.SIGBUS, signal.SIGILL, signal.SIGFPE}
_ABORT_SIGNALS = {signal.SIGABRT}


def decoder_command(decoder: str, path: str) -> list[str]:
    """Build the decoder command line for a given decoder name."""
    if decoder == "ffmpeg":
        return ["ffmpeg", "-v", "error", "-i", path, "-f", "null", "-"]
    if decoder in ("libde265", "dec265"):
        # The libde265 reference decoder ships a `dec265` CLI.
        return ["dec265", path]
    raise ValueError(f"unsupported decoder '{decoder}' (expected ffmpeg or libde265)")


def decoder_output_command(decoder: str, path: str) -> list[str]:
    """Build the decoder command line that writes decoded raw frames to stdout.

    Used by the differential oracle's ``--compare-output`` mode: the captured
    stdout bytes are hashed so two decoders' pixel output can be compared
    directly when both return CLEAN. The output format is normalised to raw
    YUV 4:2:0 across decoders so the hashes are directly comparable.

    - ffmpeg: ``ffmpeg -v error -i <path> -f rawvideo -pix_fmt yuv420p -``
      writes a single concatenated raw YUV 4:2:0 stream to stdout.
    - libde265/dec265: ``dec265 -q -o /dev/stdout <path>`` writes the decoded
      YUV frames to stdout in YUV 4:2:0 by default (``-q`` silences the
      decoder's own progress logging to stderr only).
    """
    if decoder == "ffmpeg":
        return [
            "ffmpeg",
            "-v",
            "error",
            "-i",
            path,
            "-f",
            "rawvideo",
            "-pix_fmt",
            "yuv420p",
            "-",
        ]
    if decoder in ("libde265", "dec265"):
        return ["dec265", "-q", "-o", "/dev/stdout", path]
    raise ValueError(f"unsupported decoder '{decoder}' (expected ffmpeg or libde265)")


def classify(returncode: int) -> Outcome:
    """Classify a process return code into an Outcome.

    POSIX subprocess convention: a negative return code is ``-signal``.
    """
    if returncode == 0:
        return Outcome.CLEAN
    if returncode < 0:
        sig = -returncode
        if sig in _ABORT_SIGNALS:
            return Outcome.ABORT
        if sig in _CRASH_SIGNALS:
            return Outcome.CRASH
        return Outcome.CRASH  # any other fatal signal counts as a crash
    return Outcome.CRASH  # non-zero positive exit -> crash artifact (criterion 6)


def run_decoder(
    decoder: str,
    path: str,
    timeout: float,
    runner=subprocess.run,
    capture_output: bool = False,
) -> DecodeResult:
    """Run a decoder against ``path`` with a timeout and classify the result.

    ``runner`` is injectable so unit tests can mock the subprocess call without
    requiring ffmpeg/libde265 to be installed (criterion 8).

    When ``capture_output`` is True the decoder is invoked via
    :func:`decoder_output_command` (writing raw YUV 4:2:0 to stdout); stdout is
    read into memory and a SHA256 hex digest is stored on
    :attr:`DecodeResult.output_hash`. The hash is populated for any
    non-timeout completion (CLEAN, CRASH, ABORT) — even a crashed decoder may
    have flushed partial pixel data worth comparing against another decoder's
    bytes. Timeouts leave ``output_hash`` as ``None``.
    """
    cmd = (
        decoder_output_command(decoder, path)
        if capture_output
        else decoder_command(decoder, path)
    )
    try:
        proc = runner(
            cmd,
            stdout=subprocess.PIPE if capture_output else subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr or b""
        if isinstance(stderr, str):
            stderr = stderr.encode()
        return DecodeResult(
            Outcome.TIMEOUT, None, stderr.decode("utf-8", "replace"), decoder=decoder
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"decoder '{decoder}' not found on PATH ({cmd[0]}). "
            "Install ffmpeg (or libde265's dec265) to run live fuzzing."
        ) from exc

    stderr_bytes = proc.stderr if proc.stderr is not None else b""
    if isinstance(stderr_bytes, str):
        stderr_text = stderr_bytes
    else:
        stderr_text = stderr_bytes.decode("utf-8", "replace")

    output_hash: str | None = None
    if capture_output:
        stdout_bytes = proc.stdout if proc.stdout is not None else b""
        if isinstance(stdout_bytes, str):
            stdout_bytes = stdout_bytes.encode("utf-8", "replace")
        output_hash = hashlib.sha256(stdout_bytes).hexdigest()

    return DecodeResult(
        classify(proc.returncode),
        proc.returncode,
        stderr_text,
        decoder=decoder,
        output_hash=output_hash,
    )


# Outcomes that count as a "crash-class" failure when comparing two decoders.
# A divergence is reported when one decoder lands in this set and the other does
# not (a crash/clean split), or when both crash with different signals.
_FAILURE_OUTCOMES = {Outcome.CRASH, Outcome.ABORT}


@dataclass
class DivergenceResult:
    """The result of running one mutant through two decoders.

    ``diverged`` is True when the two decoders disagree on the *crash class* of
    the input — the TWINFUZZ (NDSS 2025) signal: one decoder crashes/aborts while
    the other decodes cleanly (or times out), exposing a silent spec violation
    that a single-decoder crash-only campaign would miss.
    """

    diverged: bool
    kind: str
    left: DecodeResult
    right: DecodeResult


def _classify_divergence(left: DecodeResult, right: DecodeResult) -> tuple[bool, str]:
    """Decide whether two DecodeResults represent a divergence.

    Returns ``(diverged, kind)``. ``kind`` is a short, stable label:

    - ``"agree"`` — both decoders agree on the crash class (no divergence).
    - ``"crash-split"`` — exactly one decoder hit a failure outcome
      (crash/abort) while the other did not. The highest-value signal: one
      decoder is vulnerable to an input the other tolerates.
    - ``"signal-split"`` — both decoders failed but with different outcomes
      (e.g. one SIGSEGV crash, one SIGABRT). Weaker but still a divergence.
    - ``"output-divergence"`` — both decoders accepted the input cleanly
      (CLEAN), but the captured raw-frame stdout hashes differ. The TWINFUZZ
      (NDSS 2025) silent-acceptor signal: neither decoder complained, but
      they produced different pixel data — a real spec violation that a
      crash-only campaign and a crash-class-only diff campaign both miss.
      Only produced when both DecodeResults carry ``output_hash`` values
      (i.e. the campaign was run with ``capture_output=True``); when either
      hash is ``None`` the crash-class verdict alone determines the result
      and a clean/clean pair is ``"agree"`` as before.
    """
    left_failed = left.outcome in _FAILURE_OUTCOMES
    right_failed = right.outcome in _FAILURE_OUTCOMES

    if left_failed != right_failed:
        return True, "crash-split"
    if left_failed and right_failed and left.outcome != right.outcome:
        return True, "signal-split"
    if (
        left.outcome == Outcome.CLEAN
        and right.outcome == Outcome.CLEAN
        and left.output_hash is not None
        and right.output_hash is not None
        and left.output_hash != right.output_hash
    ):
        return True, "output-divergence"
    return False, "agree"


def run_decoder_pair(
    left_decoder: str,
    right_decoder: str,
    path: str,
    timeout: float,
    runner=subprocess.run,
    compare_output: bool = False,
) -> DivergenceResult:
    """Run one mutant through two decoders and report whether they disagree.

    Each decoder is invoked independently via :func:`run_decoder`; the two
    results are compared with :func:`_classify_divergence`. ``runner`` is
    injectable so tests can drive the pair without ffmpeg/libde265 installed.

    When ``compare_output`` is True each decoder is invoked with
    ``capture_output=True`` and the resulting :attr:`DecodeResult.output_hash`
    values are fed into the divergence classifier, enabling
    ``"output-divergence"`` detection for clean/clean pairs whose pixel data
    disagrees.
    """
    left = run_decoder(
        left_decoder, path, timeout, runner=runner, capture_output=compare_output
    )
    right = run_decoder(
        right_decoder, path, timeout, runner=runner, capture_output=compare_output
    )
    diverged, kind = _classify_divergence(left, right)
    return DivergenceResult(diverged=diverged, kind=kind, left=left, right=right)
