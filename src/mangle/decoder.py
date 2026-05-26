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
) -> DecodeResult:
    """Run a decoder against ``path`` with a timeout and classify the result.

    ``runner`` is injectable so unit tests can mock the subprocess call without
    requiring ffmpeg/libde265 to be installed (criterion 8).
    """
    cmd = decoder_command(decoder, path)
    try:
        proc = runner(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        stderr = exc.stderr or b""
        if isinstance(stderr, str):
            stderr = stderr.encode()
        return DecodeResult(Outcome.TIMEOUT, None, stderr.decode("utf-8", "replace"))
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
    return DecodeResult(classify(proc.returncode), proc.returncode, stderr_text)
