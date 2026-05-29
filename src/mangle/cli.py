"""mangle command-line interface.

Subcommands:
  mutate  - apply one structured mutation to a seed and write the mutant
  fuzz    - run many mutations against a decoder and record outcomes
  diff    - run mutants through two decoders and record where they disagree
  corpus  - generate a diverse minimal seed corpus from one seed file
  triage  - cluster and deduplicate the crashes from a fuzz run
  reduce  - minimise one crashing input to its minimal NAL-unit reproducer
  mutators - list available mutator types
"""

from __future__ import annotations

import argparse
import sys
from collections import Counter

from . import __version__
from .corpus import build_corpus
from .engine import diff_file, fuzz_file, mutate_file
from .mutators import list_mutators
from .reduce import reduce_file
from .triage import triage


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

    # diff
    p_diff = sub.add_parser(
        "diff",
        help="run mutants through two decoders and record where they disagree",
        description=(
            "Differential decoder oracle. Feeds each mutant through TWO decoders "
            "and records the iterations where they disagree on the crash class — "
            "one decoder crashes/aborts while the other decodes cleanly (a "
            "'crash-split'), or both crash with different signals (a "
            "'signal-split'). Divergences expose silent spec violations a "
            "single-decoder crash-only campaign misses (TWINFUZZ, NDSS 2025). "
            "Writes diff.jsonl plus a divergences/ directory holding each "
            "diverging mutant and a side-by-side stderr report."
        ),
    )
    p_diff.add_argument("--seed", required=True, help="path to the seed H.265 file")
    p_diff.add_argument(
        "--output-dir",
        required=True,
        help="directory for diff.jsonl and divergences/",
    )
    p_diff.add_argument(
        "--iterations", type=int, default=100, help="number of mutate+decode-pair cycles"
    )
    p_diff.add_argument(
        "--left-decoder",
        default="ffmpeg",
        choices=["ffmpeg", "libde265"],
        help="first decoder of the differential pair",
    )
    p_diff.add_argument(
        "--right-decoder",
        default="libde265",
        choices=["ffmpeg", "libde265"],
        help="second decoder of the differential pair (must differ from --left-decoder)",
    )
    p_diff.add_argument(
        "--timeout", type=float, default=5.0, help="per-decode wall-clock timeout (s)"
    )
    p_diff.add_argument(
        "--seed-rng", type=int, default=0, help="RNG seed for the whole campaign"
    )
    p_diff.add_argument(
        "--mutator",
        action="append",
        dest="mutators",
        choices=list_mutators(),
        help="restrict to specific mutators (repeatable); default = all",
    )
    p_diff.add_argument(
        "--concurrency",
        type=int,
        default=4,
        help="parallel decode workers (asyncio)",
    )
    p_diff.set_defaults(func=_cmd_diff)

    # corpus
    p_corpus = sub.add_parser(
        "corpus",
        help="generate a diverse minimal seed corpus from one seed file",
        description=(
            "Derive a diverse, compact seed corpus from one seed H.265 file. "
            "Emits seeds covering distinct SPS dimension classes, chroma formats, "
            "incomplete parameter sets (VPS/SPS/PPS-only), and a non-IRAP-first "
            "NAL ordering, plus a manifest.json describing every emitted and "
            "skipped seed. Fully deterministic — no RNG."
        ),
    )
    p_corpus.add_argument("--seed", required=True, help="path to the seed H.265 file")
    p_corpus.add_argument(
        "--output-dir",
        required=True,
        help="directory for the generated seed files and manifest.json",
    )
    p_corpus.set_defaults(func=_cmd_corpus)

    # triage
    p_triage = sub.add_parser(
        "triage",
        help="cluster and deduplicate the crashes from a fuzz run",
        description=(
            "Post-process a fuzz output directory: read results.jsonl and the "
            "crashes/ artifacts, cluster crashes by a stable signature "
            "(ASAN/UBSAN top stack frames when present, else a normalised "
            "stderr hash) keyed on (signature, decoder, mutator), and write "
            "triage.jsonl plus a unique-crashes/ directory holding the most "
            "minimal representative of each cluster. Fully deterministic; makes "
            "no changes to the fuzzing pipeline."
        ),
    )
    p_triage.add_argument(
        "--output-dir",
        required=True,
        help="a fuzz output directory containing results.jsonl and crashes/",
    )
    p_triage.add_argument(
        "--decoder",
        default="ffmpeg",
        choices=["ffmpeg", "libde265"],
        help="label for the campaign's decoder (part of the cluster key)",
    )
    p_triage.add_argument(
        "--frame-depth",
        type=int,
        default=3,
        help="number of top sanitizer stack frames used as the signature",
    )
    p_triage.set_defaults(func=_cmd_triage)

    # reduce
    p_reduce = sub.add_parser(
        "reduce",
        help="minimise one crashing input to its minimal NAL-unit reproducer",
        description=(
            "Test-case minimiser (the afl-tmin / creduce step of a fuzzing "
            "workflow). Given one confirmed crashing H.265 input, apply the "
            "ddmin delta-debugging algorithm (Zeller & Hildebrandt, TSE 2002) "
            "over its NAL units to find the smallest subset that still "
            "reproduces the SAME crash. 'Same crash' is enforced by signature: "
            "the candidate must hit the same ASAN-top-frame / normalised-stderr "
            "fingerprint mangle triage uses, so the reducer never trades the "
            "original bug for a different one. Writes the minimal reproducer to "
            "--output. Deterministic."
        ),
    )
    p_reduce.add_argument(
        "--crash", required=True, help="path to the crashing H.265 input to minimise"
    )
    p_reduce.add_argument(
        "--output", required=True, help="path to write the minimal reproducer"
    )
    p_reduce.add_argument(
        "--decoder",
        default="ffmpeg",
        choices=["ffmpeg", "libde265"],
        help="decoder the crash reproduces against",
    )
    p_reduce.add_argument(
        "--timeout", type=float, default=5.0, help="per-decode wall-clock timeout (s)"
    )
    p_reduce.add_argument(
        "--frame-depth",
        type=int,
        default=3,
        help="number of top sanitizer stack frames used for the crash signature",
    )
    p_reduce.set_defaults(func=_cmd_reduce)

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


def _cmd_diff(args: argparse.Namespace) -> int:
    results = diff_file(
        seed_path=args.seed,
        output_dir=args.output_dir,
        iterations=args.iterations,
        left_decoder=args.left_decoder,
        right_decoder=args.right_decoder,
        timeout=args.timeout,
        seed_rng=args.seed_rng,
        mutators=args.mutators,
        concurrency=args.concurrency,
    )
    divergences = [r for r in results if r.diverged]
    by_kind = Counter(r.kind for r in divergences)
    print(
        f"ran {len(results)} iterations: "
        f"{args.left_decoder} vs {args.right_decoder}"
    )
    print(f"  divergences: {len(divergences)}")
    for kind in ("crash-split", "signal-split"):
        if by_kind.get(kind):
            print(f"    {kind}: {by_kind[kind]}")
    print(f"results written to {args.output_dir}/diff.jsonl")
    if divergences:
        print(
            f"{len(divergences)} divergence artifact(s) in "
            f"{args.output_dir}/divergences/"
        )
    return 0


def _cmd_corpus(args: argparse.Namespace) -> int:
    entries = build_corpus(args.seed, args.output_dir)
    emitted = [e for e in entries if e.skipped is None]
    skipped = [e for e in entries if e.skipped is not None]
    by_strategy: Counter[str] = Counter(e.strategy for e in emitted)
    print(f"generated {len(emitted)} seed(s) in {args.output_dir}")
    for strategy in sorted(by_strategy):
        print(f"  {strategy}: {by_strategy[strategy]}")
    if skipped:
        print(f"skipped {len(skipped)} seed class(es):")
        for e in skipped:
            print(f"  {e.descriptor} ({e.strategy}): {e.skipped} — {e.detail}")
    print(f"manifest written to {args.output_dir}/manifest.json")
    return 0


def _cmd_triage(args: argparse.Namespace) -> int:
    clusters = triage(
        output_dir=args.output_dir,
        decoder=args.decoder,
        frame_depth=args.frame_depth,
    )
    total_members = sum(c.count for c in clusters)
    print(
        f"clustered {total_members} crash artifact(s) into "
        f"{len(clusters)} unique bug(s)"
    )
    for c in clusters:
        sig = c.signature if c.signature_kind == "asan" else f"stderr:{c.signature}"
        print(
            f"  cluster {c.cluster_id}: {c.count}x [{c.mutator}] "
            f"{c.signature_kind} {sig}"
        )
    print(f"triage written to {args.output_dir}/triage.jsonl")
    print(f"unique PoCs in {args.output_dir}/unique-crashes/")
    return 0


def _cmd_reduce(args: argparse.Namespace) -> int:
    result = reduce_file(
        crash_path=args.crash,
        output_path=args.output,
        decoder=args.decoder,
        timeout=args.timeout,
        frame_depth=args.frame_depth,
    )
    nal_drop = result.original_nals - result.minimal_nals
    byte_drop = result.original_bytes - result.minimal_bytes
    pct = (byte_drop / result.original_bytes * 100) if result.original_bytes else 0.0
    print(
        f"reduced {result.original_nals} -> {result.minimal_nals} NAL unit(s) "
        f"({nal_drop} removed)"
    )
    print(
        f"reduced {result.original_bytes} -> {result.minimal_bytes} bytes "
        f"({byte_drop} removed, {pct:.1f}% smaller)"
    )
    print(f"crash signature preserved: {result.signature}")
    print(f"decode probes: {result.probes}")
    print(f"minimal reproducer written to {args.output}")
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
