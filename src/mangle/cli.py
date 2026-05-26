"""mangle command-line interface.

Subcommands:
  mutate  - apply one structured mutation to a seed and write the mutant
  fuzz    - run many mutations against a decoder and record outcomes
  mutators - list available mutator types
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from . import __version__
from .engine import fuzz_file, mutate_file
from .mutators import list_mutators


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mangle",
        description=(
            "A structured H.265 (HEVC) bitstream fuzzer for security research. "
            "Generates syntactically-correct but spec-non-compliant HEVC files "
            "and feeds them through ffmpeg/libde265 to find decoder crashes."
        ),
    )
    parser.add_argument("--version", action="version", version=f"mangle {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    # mutate
    p_mutate = sub.add_parser(
        "mutate",
        help="apply one structured mutation to a seed H.265 file",
        description="Apply one structured mutation to a seed H.265 file.",
    )
    p_mutate.add_argument("--seed", required=True, help="path to the seed H.265 file")
    p_mutate.add_argument("--output", required=True, help="path to write the mutant")
    p_mutate.add_argument(
        "--mutator",
        required=True,
        choices=list_mutators(),
        help="which structured mutator to apply",
    )
    p_mutate.add_argument(
        "--seed-rng",
        type=int,
        default=0,
        help="RNG seed for deterministic, reproducible mutation",
    )
    p_mutate.set_defaults(func=_cmd_mutate)

    # fuzz
    p_fuzz = sub.add_parser(
        "fuzz",
        help="run many mutations against a decoder and record outcomes",
        description="Run many mutations against a decoder and record outcomes.",
    )
    p_fuzz.add_argument("--seed", required=True, help="path to the seed H.265 file")
    p_fuzz.add_argument(
        "--output-dir", required=True, help="directory for results.jsonl and crashes/"
    )
    p_fuzz.add_argument(
        "--iterations", type=int, default=100, help="number of mutate+decode cycles"
    )
    p_fuzz.add_argument(
        "--decoder",
        default="ffmpeg",
        choices=["ffmpeg", "libde265"],
        help="decoder to feed mutants through",
    )
    p_fuzz.add_argument(
        "--timeout", type=float, default=5.0, help="per-decode wall-clock timeout (s)"
    )
    p_fuzz.add_argument(
        "--seed-rng", type=int, default=0, help="RNG seed for the whole campaign"
    )
    p_fuzz.add_argument(
        "--mutator",
        action="append",
        dest="mutators",
        choices=list_mutators(),
        help="restrict to specific mutators (repeatable); default = all",
    )
    p_fuzz.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="parallel decode workers (asyncio)",
    )
    p_fuzz.set_defaults(func=_cmd_fuzz)

    # mutators
    p_list = sub.add_parser("mutators", help="list available mutator types")
    p_list.set_defaults(func=_cmd_list_mutators)

    return parser


def _cmd_mutate(args: argparse.Namespace) -> int:
    result = mutate_file(args.seed, args.output, args.mutator, args.seed_rng)
    print(
        f"mutation applied: {result.mutator}; bytes changed: {result.bytes_changed}"
    )
    print(f"detail: {result.detail}")
    return 0


def _cmd_fuzz(args: argparse.Namespace) -> int:
    results = fuzz_file(
        seed_path=args.seed,
        output_dir=args.output_dir,
        iterations=args.iterations,
        decoder=args.decoder,
        timeout=args.timeout,
        seed_rng=args.seed_rng,
        mutators=args.mutators,
        concurrency=args.concurrency,
    )
    counts = Counter(r.outcome for r in results)
    crashes = [r for r in results if r.crash_hash]
    print(f"ran {len(results)} iterations against {args.decoder}")
    for outcome in ("clean", "crash", "abort", "timeout", "hang"):
        if counts.get(outcome):
            print(f"  {outcome}: {counts[outcome]}")
    print(f"results written to {args.output_dir}/results.jsonl")
    if crashes:
        print(f"{len(crashes)} crash artifact(s) in {args.output_dir}/crashes/")
    return 0


def _cmd_list_mutators(args: argparse.Namespace) -> int:
    for name in list_mutators():
        print(name)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, KeyError, RuntimeError, FileNotFoundError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
