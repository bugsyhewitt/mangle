"""mangle command-line interface.

Subcommands:
  mutate  - apply one structured mutation to a seed and write the mutant
  fuzz    - run many mutations against a decoder and record outcomes
  diff    - run mutants through two decoders and record where they disagree
  corpus  - generate a diverse minimal seed corpus from one seed file
  corpus-trim - minimise a corpus directory to one seed per decode behaviour
  triage  - cluster and deduplicate the crashes from a fuzz run
  reduce  - minimise one crashing input to its minimal NAL-unit reproducer
  replay  - re-derive any fuzz iteration's mutant from the campaign metadata
  coverage - report which mutators a campaign exercised (structural coverage)
  heatmap - report fuzzing pressure and reward by bitstream region
  afl-mutate - stdin/stdout mutator wrapper for AFL++ harness integration
  mutators - list available mutator types
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .afl import mutate_stdin_to_stdout
from .corpus import build_corpus
from .corpus_trim import trim_corpus_dir
from .coverage import write_coverage
from .engine import diff_file, fuzz_file, mutate_file
from .heatmap import write_heatmap
from .mutators import list_mutators
from .reduce import reduce_file
from .replay import replay_iteration
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
    fuzz_seed_src = p_fuzz.add_mutually_exclusive_group(required=True)
    fuzz_seed_src.add_argument(
        "--seed", help="path to the seed H.265 file (single-seed campaign)"
    )
    fuzz_seed_src.add_argument(
        "--seed-from-crashes",
        help=(
            "directory of a PRIOR campaign's crash artifacts (its crashes/ "
            "directory of *.h265 files). Each crash becomes a base seed for this "
            "campaign — the fuzzing feedback loop: re-mutate a crashing input to "
            "explore the decoder state around it. Iterations are spread across the "
            "crash pool round-robin; mutually exclusive with --seed"
        ),
    )
    fuzz_seed_src.add_argument(
        "--seed-corpus-dir",
        help=(
            "directory of *.h265 seed files to spread iterations across — "
            "typically the output of `mangle corpus` or `mangle corpus-trim`, but "
            "any directory of valid H.265 streams works. Iterations are assigned "
            "across the pool round-robin by iteration index (deterministic); each "
            "iteration records the base seed's filename so the run stays fully "
            "replayable via `mangle replay --seed-dir <this-dir>`. Mutually "
            "exclusive with --seed and --seed-from-crashes. Non-*.h265 files in "
            "the directory (e.g. a sibling manifest.json) are ignored"
        ),
    )
    p_fuzz.add_argument(
        "--output-dir", required=True, help="directory for results.jsonl and crashes/"
    )
    p_fuzz.add_argument(
        "--iterations",
        type=int,
        default=100,
        help=(
            "number of mutate+decode cycles; with --time-limit this is an upper "
            "bound (whichever limit is hit first ends the campaign)"
        ),
    )
    p_fuzz.add_argument(
        "--time-limit",
        type=float,
        default=None,
        help=(
            "wall-clock budget for the campaign in seconds (default: unlimited). "
            "When set, dispatch stops as soon as the budget is spent — "
            "--iterations becomes a cap, not a target. Each iteration that runs "
            "is still individually replayable; only the iteration COUNT is "
            "wall-clock dependent. Omitting it preserves the exact "
            "iterations-only behaviour of earlier releases"
        ),
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
    p_fuzz.add_argument(
        "--strategy",
        default="uniform",
        choices=["uniform", "adaptive"],
        help=(
            "mutator scheduling policy: 'uniform' picks every mutator with equal "
            "probability (default); 'adaptive' learns from crash/abort outcomes "
            "and biases selection toward mutators that crash the decoder"
        ),
    )
    p_fuzz.add_argument(
        "--scheduler-state",
        type=Path,
        default=None,
        help=(
            "warm-start the adaptive scheduler from a prior campaign's "
            "scheduler.json (path). The saved per-mutator trial/reward counts "
            "are added to this campaign's bandit, so a multi-run campaign keeps "
            "the prioritisation it learned. Only meaningful with "
            "--strategy adaptive; unknown mutators in the saved state are dropped "
            "and new mutators in the pool start cold."
        ),
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
    p_diff.add_argument(
        "--compare-output",
        action="store_true",
        help=(
            "capture each decoder's raw YUV 4:2:0 output and compare SHA256 "
            "hashes; when both decoders return CLEAN but the hashes differ, "
            "record an 'output-divergence' (the TWINFUZZ silent-acceptor "
            "signal: both decoders said yes, but produced different pixels)"
        ),
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

    # corpus-trim
    p_trim = sub.add_parser(
        "corpus-trim",
        help="minimise a corpus directory to one seed per decode behaviour",
        description=(
            "Corpus minimiser (the afl-cmin step of a fuzzing workflow). Probe "
            "every seed in a directory through a decoder, bucket the seeds by "
            "their decode behaviour (crash signature for crash/abort seeds — the "
            "same ASAN-top-frame / normalised-stderr fingerprint mangle triage "
            "uses; one bucket for all clean seeds; per-bucket timeout/hang), and "
            "keep ONE representative per behaviour: the smallest file, tie-broken "
            "by name. Redundant seeds are dropped. The kept seeds are copied into "
            "--output-dir alongside a trim-manifest.json recording every seed's "
            "verdict. Deterministic; runs one decode per input seed."
        ),
    )
    p_trim.add_argument(
        "--input-dir",
        required=True,
        help="directory of seed files to minimise",
    )
    p_trim.add_argument(
        "--output-dir",
        required=True,
        help="directory to copy the kept seeds and trim-manifest.json into",
    )
    p_trim.add_argument(
        "--decoder",
        default="ffmpeg",
        choices=["ffmpeg", "libde265"],
        help="decoder used to probe each seed's behaviour",
    )
    p_trim.add_argument(
        "--timeout", type=float, default=5.0, help="per-decode wall-clock timeout (s)"
    )
    p_trim.add_argument(
        "--frame-depth",
        type=int,
        default=3,
        help="number of top sanitizer stack frames used in the crash signature",
    )
    p_trim.add_argument(
        "--pattern",
        default="*.h265",
        help="glob for which files in --input-dir count as seeds",
    )
    p_trim.set_defaults(func=_cmd_corpus_trim)

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

    # replay
    p_replay = sub.add_parser(
        "replay",
        help="re-derive any fuzz iteration's mutant from the campaign metadata",
        description=(
            "Deterministic mutation replay. A fuzz campaign records the exact "
            "mutator and per-iteration RNG seed for every iteration in "
            "results.jsonl; because each mutator is a pure function of (seed "
            "bytes, RNG), that pair fully reproduces the iteration's mutant. "
            "Given the original --seed file and the campaign --output-dir, "
            "reconstruct the byte-identical mutant for ANY iteration — including "
            "the clean / timeout / hang iterations the campaign never saved to "
            "crashes/. When the iteration was a crash, the re-derived bytes are "
            "cross-checked against the saved crashes/ artifact (a reproducibility "
            "/ tamper check). Runs no decoder; changes nothing in the pipeline."
        ),
    )
    p_replay.add_argument(
        "--seed",
        help=(
            "path to the ORIGINAL seed H.265 file the campaign fuzzed "
            "(single-seed campaigns)"
        ),
    )
    p_replay.add_argument(
        "--seed-dir",
        help=(
            "directory of base seeds for a --seed-from-crashes campaign (the prior "
            "campaign's crashes/ directory); replay resolves each iteration's "
            "recorded base seed from here"
        ),
    )
    p_replay.add_argument(
        "--output-dir",
        required=True,
        help="the fuzz output directory containing results.jsonl",
    )
    p_replay.add_argument(
        "--iteration",
        type=int,
        required=True,
        help="which iteration's mutant to reconstruct",
    )
    p_replay.add_argument(
        "--output",
        required=True,
        help="path to write the reconstructed mutant",
    )
    p_replay.set_defaults(func=_cmd_replay)

    # coverage
    p_coverage = sub.add_parser(
        "coverage",
        help="report which mutators a fuzz campaign exercised (structural coverage)",
        description=(
            "Mutation-coverage reporter. mangle is a black-box harness — it sees "
            "only each decode's pass/fail outcome, not edge coverage — so the "
            "coverage question it can answer is structural: did this campaign "
            "exercise the full mutator surface, how did each mutator's outcomes "
            "distribute, and which registered mutators did it never reach? This "
            "is a pure post-processing pass over the campaign's results.jsonl. "
            "For each mutator it reports iterations spent, the outcome breakdown, "
            "crash/abort count, and the number of DISTINCT crash signatures found "
            "(using the same triage fingerprint, so 500 crashes on one bug do not "
            "masquerade as breadth). At the campaign level it lists the exercised "
            "and the uncovered (blind-spot) mutators against the live registry, "
            "the coverage and productive fractions, and any unknown mutators in "
            "the results. Writes coverage.json. Runs no decoder; deterministic."
        ),
    )
    p_coverage.add_argument(
        "--output-dir",
        required=True,
        help="a fuzz output directory containing results.jsonl (and crashes/)",
    )
    p_coverage.add_argument(
        "--frame-depth",
        type=int,
        default=3,
        help="number of top sanitizer stack frames used for distinct-bug counting",
    )
    p_coverage.set_defaults(func=_cmd_coverage)

    # heatmap
    p_heatmap = sub.add_parser(
        "heatmap",
        help="report fuzzing pressure and reward by bitstream region",
        description=(
            "Mutation heat-map. Where ``coverage`` reports per-mutator stats as a "
            "flat list, ``heatmap`` aggregates the campaign's pressure (iterations, "
            "bytes changed) and reward (crashes/aborts, distinct bugs) by the "
            "BITSTREAM REGION each mutator targets — VPS, SPS, PPS, slice-header, "
            "RPS, SEI, or raw NAL framing — derived deterministically from the "
            "mutator name. The result is the 'where is the soft spot in the H.265 "
            "parser?' view: a region whose share of crashes far exceeds its share "
            "of iterations is the profitable target; a region that absorbs effort "
            "but yields nothing is wasted pressure. Pure post-processing over the "
            "campaign's results.jsonl — runs no decoder, deterministic, the same "
            "read-only shape as ``coverage`` / ``triage`` / ``replay``. Distinct "
            "bugs per region use the exact triage fingerprint so many crashes on "
            "one bug do not inflate a region. Writes heatmap.json."
        ),
    )
    p_heatmap.add_argument(
        "--output-dir",
        required=True,
        help="a fuzz output directory containing results.jsonl (and crashes/)",
    )
    p_heatmap.add_argument(
        "--frame-depth",
        type=int,
        default=3,
        help="number of top sanitizer stack frames used for distinct-bug counting",
    )
    p_heatmap.set_defaults(func=_cmd_heatmap)

    # afl-mutate
    p_afl = sub.add_parser(
        "afl-mutate",
        help="apply one mutation to a seed file, write the mutant to stdout",
        description=(
            "stdin/stdout adapter for AFL++ harness integration (POST_V01 item "
            "#7). Reads the seed bytes from --seed (the AFL '@@' convention — "
            "AFL replaces @@ with the candidate path before invoking) and "
            "writes the mutated bytes to stdout, with no other output on "
            "stdout. The byte count is reported on stderr. Designed to be "
            "called from a contrib/afl-harness/ persistent-mode driver, an "
            "afl-fuzz custom-mutator wrapper, or any out-of-process tool that "
            "wants mangle's grammar-aware mutators with byte-in/byte-out "
            "plumbing. Deterministic for (seed, mutator, --seed-rng)."
        ),
    )
    p_afl.add_argument("--seed", required=True, help="path to the seed H.265 file")
    p_afl.add_argument(
        "--mutator",
        required=True,
        choices=list_mutators(),
        help="mutator to apply",
    )
    p_afl.add_argument(
        "--seed-rng",
        type=int,
        default=0,
        help="RNG seed for the mutation (default 0; same seed -> same mutant)",
    )
    p_afl.set_defaults(func=_cmd_afl_mutate)

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
    scheduler_state = None
    if args.scheduler_state is not None:
        if args.strategy == "uniform":
            print(
                "error: --scheduler-state requires --strategy adaptive "
                "(the uniform scheduler does not learn from outcomes)",
                file=sys.stderr,
            )
            return 2
        try:
            scheduler_state = json.loads(Path(args.scheduler_state).read_text())
        except (OSError, json.JSONDecodeError) as exc:
            print(
                f"error: could not read --scheduler-state {args.scheduler_state}: {exc}",
                file=sys.stderr,
            )
            return 2
    results = fuzz_file(
        seed_path=args.seed,
        output_dir=args.output_dir,
        iterations=args.iterations,
        decoder=args.decoder,
        timeout=args.timeout,
        seed_rng=args.seed_rng,
        mutators=args.mutators,
        concurrency=args.concurrency,
        strategy=args.strategy,
        seed_from_crashes=args.seed_from_crashes,
        seed_corpus_dir=args.seed_corpus_dir,
        time_limit=args.time_limit,
        scheduler_state=scheduler_state,
    )
    counts = Counter(r.outcome for r in results)
    crashes = [r for r in results if r.crash_hash]
    # When a --time-limit budget cut the campaign short, say so against the cap.
    budget_note = ""
    if args.time_limit is not None:
        budget_note = (
            f", time-limited to {args.time_limit:g}s "
            f"(of up to {args.iterations} iteration cap)"
        )
    if args.seed_from_crashes:
        n_seeds = len({r.base_seed for r in results if r.base_seed is not None})
        print(
            f"ran {len(results)} iterations against {args.decoder} "
            f"({args.strategy} scheduler), fed from {n_seeds} crash seed(s)"
            f"{budget_note}"
        )
    elif args.seed_corpus_dir:
        n_seeds = len({r.base_seed for r in results if r.base_seed is not None})
        print(
            f"ran {len(results)} iterations against {args.decoder} "
            f"({args.strategy} scheduler), fed from {n_seeds} corpus seed(s)"
            f"{budget_note}"
        )
    else:
        print(
            f"ran {len(results)} iterations against {args.decoder} "
            f"({args.strategy} scheduler){budget_note}"
        )
    for outcome in ("clean", "crash", "abort", "timeout", "hang"):
        if counts.get(outcome):
            print(f"  {outcome}: {counts[outcome]}")
    print(f"results written to {args.output_dir}/results.jsonl")
    if crashes:
        print(f"{len(crashes)} crash artifact(s) in {args.output_dir}/crashes/")
    if args.strategy != "uniform":
        print(f"mutator scoreboard written to {args.output_dir}/scheduler.json")
        if scheduler_state is not None:
            prior_iters = scheduler_state.get("iterations", "?")
            prior_arms = scheduler_state.get("arms", {})
            prior_trials = sum(
                int(a.get("trials", 0)) for a in prior_arms.values()
                if isinstance(a, dict)
            )
            print(
                f"  resumed adaptive scheduler from {args.scheduler_state} "
                f"({prior_iters} prior iterations, {prior_trials} prior trials)"
            )
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
        compare_output=args.compare_output,
    )
    divergences = [r for r in results if r.diverged]
    by_kind = Counter(r.kind for r in divergences)
    print(
        f"ran {len(results)} iterations: "
        f"{args.left_decoder} vs {args.right_decoder}"
        + (" (with output compare)" if args.compare_output else "")
    )
    print(f"  divergences: {len(divergences)}")
    for kind in ("crash-split", "signal-split", "output-divergence"):
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


def _cmd_corpus_trim(args: argparse.Namespace) -> int:
    result = trim_corpus_dir(
        input_dir=args.input_dir,
        output_dir=args.output_dir,
        decoder=args.decoder,
        timeout=args.timeout,
        frame_depth=args.frame_depth,
        pattern=args.pattern,
    )
    print(
        f"trimmed {result.input_count} seed(s) -> {result.kept_count} kept "
        f"({result.dropped_count} redundant dropped)"
    )
    print(f"distinct decode behaviour(s) preserved: {result.behaviour_count}")
    by_outcome: Counter[str] = Counter(
        v.outcome for v in result.verdicts if v.kept
    )
    for outcome in sorted(by_outcome):
        print(f"  kept {by_outcome[outcome]} {outcome} representative(s)")
    print(f"decode probes: {result.probes}")
    print(f"kept seeds copied to {args.output_dir}")
    print(f"trim manifest written to {args.output_dir}/trim-manifest.json")
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


def _cmd_replay(args: argparse.Namespace) -> int:
    result = replay_iteration(
        seed_path=args.seed,
        output_dir=args.output_dir,
        iteration=args.iteration,
        out_path=args.output,
        seed_dir=args.seed_dir,
    )
    print(
        f"replayed iteration {result.iteration}: [{result.mutator}] "
        f"seed_rng={result.seed_rng} outcome={result.outcome}"
    )
    print(f"reconstructed {result.bytes_written} bytes")
    print(f"mutant sha256: {result.mutant_sha256}")
    if result.crash_hash is not None:
        if result.verified is True:
            print(
                f"verified: re-derived mutant matches saved crashes/"
                f"{result.crash_hash}.h265"
            )
        elif result.verified is False:
            print(
                f"WARNING: re-derived mutant does NOT match saved crashes/"
                f"{result.crash_hash}.h265 (artifact may be stale or tampered)"
            )
        else:
            print(
                f"note: iteration recorded crash_hash {result.crash_hash} but "
                f"no saved artifact found to verify against"
            )
    print(f"mutant written to {args.output}")
    return 0


def _cmd_coverage(args: argparse.Namespace) -> int:
    report = write_coverage(
        output_dir=args.output_dir,
        frame_depth=args.frame_depth,
    )
    print(
        f"mutator coverage: {report.exercised_count}/{report.registry_size} "
        f"registered mutators exercised "
        f"({report.coverage_fraction * 100:.0f}%) over "
        f"{report.total_iterations} iteration(s)"
    )
    print(
        f"  productive: {report.productive_count}/{report.registry_size} "
        f"crashed/aborted the decoder "
        f"({report.productive_fraction * 100:.0f}%)"
    )
    for m in report.mutators:
        flag = "" if m.known else " [unknown — not in registry]"
        bug_note = (
            f", {m.distinct_signatures} distinct bug(s)"
            if m.crash_aborts
            else ""
        )
        breakdown = " ".join(f"{o}={n}" for o, n in m.outcomes.items())
        print(
            f"  {m.mutator}{flag}: {m.iterations} iter "
            f"[{breakdown}]{bug_note}"
        )
    if report.uncovered:
        print(f"uncovered ({len(report.uncovered)} mutator(s) never selected):")
        for name in report.uncovered:
            print(f"  {name}")
    else:
        print("uncovered: none — every registered mutator was exercised")
    if report.unknown_mutators:
        print(
            f"warning: {len(report.unknown_mutators)} mutator(s) in results are "
            f"not in this build's registry: {', '.join(report.unknown_mutators)}"
        )
    print(f"coverage report written to {args.output_dir}/coverage.json")
    return 0


def _cmd_heatmap(args: argparse.Namespace) -> int:
    report = write_heatmap(
        output_dir=args.output_dir,
        frame_depth=args.frame_depth,
    )
    print(
        f"mutation heat-map: {report.total_iterations} iteration(s) across "
        f"{report.region_count} bitstream region(s), "
        f"{report.total_crash_aborts} crash/abort(s)"
    )
    if report.hottest_region is not None:
        print(f"  hottest region: {report.hottest_region}")
    for r in report.regions:
        breakdown = " ".join(f"{o}={n}" for o, n in r.outcomes.items())
        bug_note = (
            f", {r.distinct_signatures} distinct bug(s)" if r.crash_aborts else ""
        )
        print(
            f"  {r.region}: {r.iterations} iter "
            f"({r.iteration_share * 100:.0f}% pressure) "
            f"-> {r.crash_aborts} crash/abort "
            f"({r.crash_share * 100:.0f}% reward){bug_note} [{breakdown}]"
        )
    print(f"heat-map written to {args.output_dir}/heatmap.json")
    return 0


def _cmd_afl_mutate(args: argparse.Namespace) -> int:
    n = mutate_stdin_to_stdout(args.seed, args.mutator, args.seed_rng)
    # All progress/diagnostic output goes to stderr so stdout stays
    # byte-clean for the downstream decoder / AFL harness.
    print(
        f"afl-mutate: applied {args.mutator}; wrote {n} bytes to stdout",
        file=sys.stderr,
    )
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
