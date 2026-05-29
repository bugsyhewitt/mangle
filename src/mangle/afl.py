"""AFL++ coverage-feedback integration (POST_V01 item #7).

mangle is a black-box harness: at the Python layer it only sees a decoder's
pass/fail outcome (see the design notes in :mod:`mangle.scheduler` and
:mod:`mangle.coverage`). The closest thing the in-process engine can offer to
"coverage-guided mutation prioritisation" is the outcome-feedback bandit in
``mangle.scheduler.AdaptiveScheduler`` — it learns from crashes but never sees
the decoder's execution traces. The *honest* path to real coverage-guided
fuzzing is to bridge mangle's grammar-aware mutators into an out-of-process
coverage-instrumented fuzzer like AFL++:

  * AFL++ provides the edge-coverage feedback loop (the part of the problem
    mangle's architecture cannot solve from inside Python).
  * mangle provides the grammar-aware mutators (the part AFL++'s bit-flip
    mutator cannot solve, because it does not know about HEVC syntax).

This module is the seam between the two. ``mutate_stream`` is a pure
``(seed_bytes, mutator_name, seed_rng) -> mutant_bytes`` function that wraps
:func:`mangle.engine.mutate_bytes` for the byte-in / byte-out usage AFL++'s
custom-mutator interface expects. ``mutate_stdin_to_stdout`` is the
command-line entry point used by the ``mangle afl-mutate`` subcommand and by
the ``contrib/afl-harness/`` driver: read the seed from a file path (the form
AFL passes its input via ``@@``), write the mutant to stdout (the form a
``harness.c`` driver and ``afl-fuzz``'s standard-input mode both consume
directly), and exit. It is deliberately *thin* — the whole point is that the
real work happens inside ``mangle.engine`` and the real fuzzing loop happens
inside AFL++.

The intended workflows are documented end-to-end in
``contrib/afl-harness/README.md``:

  1. Persistent-mode harness pumping ``mangle afl-mutate`` through ffmpeg's
     ``hevc_demuxer`` API (see ``contrib/afl-harness/harness.c``).
  2. Standalone ``afl-fuzz`` invocation using ``mangle afl-mutate`` as a
     pre-processing step on the seed corpus (the "no harness, just feed the
     mangler through" mode).
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

from .engine import mutate_bytes
from .mutators import list_mutators


def mutate_stream(
    seed_data: bytes,
    mutator_name: str,
    seed_rng: int,
) -> bytes:
    """Apply ``mutator_name`` to ``seed_data`` and return the mutant bytes.

    Pure function — no I/O, no global state — so the same arguments always
    produce the same mutant. This is the function AFL++'s custom-mutator
    interface (Python bindings) or any in-process driver would call directly.

    Validates ``mutator_name`` against the live registry before invoking the
    mutator, so an unknown name fails cleanly with the registered names list
    rather than the bare ``KeyError`` :func:`mangle.engine.mutate_bytes`
    raises. AFL++ drivers benefit from the upfront check: an out-of-process
    fuzzer that receives an empty stream from a silently-failed mutator may
    spend hours fuzzing the empty input before noticing.
    """
    available = list_mutators()
    if mutator_name not in available:
        raise ValueError(
            f"unknown mutator '{mutator_name}'; "
            f"available: {', '.join(sorted(available))}"
        )
    rng = random.Random(seed_rng)
    mutated, _ = mutate_bytes(seed_data, mutator_name, rng)
    return mutated


def mutate_stdin_to_stdout(
    seed_path: str | Path,
    mutator_name: str,
    seed_rng: int,
    out_stream=None,
) -> int:
    """Read seed bytes from ``seed_path``, write the mutant to ``out_stream``.

    The default ``out_stream`` is ``sys.stdout.buffer``, which is the form
    every common AFL++ driver — ``harness.c`` calling
    ``mangle afl-mutate --seed @@ ...``, a shell pipeline feeding ``afl-fuzz``
    its corpus through mangle, or a one-shot byte-level reproduction — expects.
    Output is written to ``out_stream`` and flushed; the return is the count
    of bytes written so the CLI wrapper can report it on stderr.

    ``seed_path`` is the AFL convention: ``@@`` is replaced with the path of
    the candidate file. Reading from a path (not stdin) is what AFL's
    deferred-fork / persistent-mode harnesses require, because the candidate
    is materialised on disk before each invocation.
    """
    if out_stream is None:  # pragma: no cover - exercised at the CLI boundary
        out_stream = sys.stdout.buffer
    data = Path(seed_path).read_bytes()
    mutant = mutate_stream(data, mutator_name, seed_rng)
    out_stream.write(mutant)
    out_stream.flush()
    return len(mutant)
