# mangle

A structured **H.265 (HEVC)** bitstream fuzzer for security research.

`mangle` generates **syntactically-correct but semantically spec-non-compliant**
H.265 video files by mutating HEVC bitstream parameters — Sequence Parameter Sets
(SPS), Picture Parameter Sets (PPS), slice headers, and NAL unit types — then
feeds the mutants through an existing decoder (ffmpeg or libde265) and records
crashes.

It is the H.265 counterpart to the H.264 tool
[`h26forge`](https://www.usenix.org/conference/usenixsecurity24) (Bhaskaran,
Shacham, et al., USENIX Security 2024), whose paper explicitly called out the
H.265 fuzzing gap. `mangle` fills that gap.

---

## Research-purpose statement (read this first)

`mangle` exists for **defensive security research**: finding and reporting
memory-safety and robustness bugs in HEVC decoders so they can be fixed.

`mangle` does **not** implement an HEVC encoder or decoder. It reads, mutates,
and writes HEVC bitstream *syntax*, and feeds the result to a **pre-existing,
separately-obtained** decoder (ffmpeg / libde265). Reading, parsing, and
generating bitstreams for interoperability and security research is widely
regarded as legitimate; nonetheless, see the patent acknowledgment below.

### HEVC patent acknowledgment

H.265 / HEVC is an ITU-T / ISO-IEC standard covered by patents licensed through
pools including **MPEG LA / Access Advance** and others. By using `mangle` you
acknowledge that:

- `mangle` ships **no** HEVC encoder or decoder — it relies on decoders you
  install yourself (ffmpeg, libde265).
- You are responsible for ensuring your own use of HEVC decoders/encoders
  complies with any patent-licensing obligations in your jurisdiction.
- `mangle`'s bitstream manipulation is provided for security research and
  interoperability analysis.

See [`NOTICE`](./NOTICE) for full attributions.

---

## Install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Requires **Python 3.13+**.

### System dependencies

`mangle`'s core mutation logic has **no runtime dependencies** and its unit tests
run without any decoder installed (the decoder shell-out is mocked). To run live
fuzzing you need a decoder on your `PATH`:

- **ffmpeg** (with HEVC decode support) — `--decoder ffmpeg` (default)
  - Debian/Ubuntu: `sudo apt install ffmpeg`
  - macOS: `brew install ffmpeg`
- **libde265** (the `dec265` CLI) — `--decoder libde265`
  - Debian/Ubuntu: `sudo apt install libde265-dev` (the `dec265` tool ships with
    the `libde265-examples` / `libde265` package on some distros)

---

## Usage

### Apply one structured mutation

```bash
mangle mutate \
  --seed tests/fixtures/clean.h265 \
  --output /tmp/mutant.h265 \
  --mutator sps-dimensions \
  --seed-rng 42
```

```
mutation applied: sps-dimensions; bytes changed: 17
detail: pic_width_in_luma_samples: 64 -> 62
```

`--seed-rng` makes mutation fully reproducible: the same seed file, mutator, and
RNG seed always produce byte-identical output.

### Run a fuzzing campaign

```bash
mangle fuzz \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/fuzz-out \
  --iterations 100 \
  --decoder ffmpeg \
  --timeout 5
```

This runs 100 mutate+decode cycles in parallel and writes:

- `/tmp/fuzz-out/results.jsonl` — one JSON object per iteration recording the
  mutator used, the outcome (`clean` / `crash` / `timeout` / `abort` / `hang`),
  the decoder return code, the mutation detail, and `base_seed` (the base input
  the iteration mutated — `null` for a single-`--seed` campaign, or the crash
  artifact's filename for a `--seed-from-crashes` campaign; see below).
- `/tmp/fuzz-out/crashes/<hash>.h265` — the mutant for any crash (segfault or
  non-zero decoder exit), alongside `<hash>.txt` containing the decoder's stderr.

#### Wall-clock campaign budget (`--time-limit`)

`--iterations` answers "how many inputs?"; `--time-limit` answers "for how
long?". Real campaigns are usually time-boxed — *fuzz overnight*, *fuzz this
PR for 10 minutes in CI* — not iteration-boxed, because per-decode time varies
with timeouts, hangs, and decoder load. `--time-limit SECONDS` adds that budget:

```bash
mangle fuzz \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/fuzz-out \
  --iterations 1000000 \
  --time-limit 600        # fuzz for ten minutes, up to a 1M-iteration cap
```

When `--time-limit` is set, `--iterations` becomes an **upper bound**, not a
target: the campaign stops dispatching new iterations as soon as the budget is
spent, and whichever limit is reached first ends the run. The budget is a
**soft** stop — iterations already in flight run to completion, so no in-progress
decode is killed mid-stream. `results.jsonl` (and the adaptive `scheduler.json`
`iterations` count) record exactly the iterations that actually ran.

Each iteration that runs is still individually replayable — its mutator and
per-iteration `seed_rng` are recorded just as in an iteration-only campaign, so
[`mangle replay`](#replay-any-iterations-mutant) reconstructs any of them
byte-for-byte. Only the iteration *count* of a time-budgeted run is wall-clock
dependent. Omitting `--time-limit` preserves the exact iterations-only behaviour
(and the byte-identical RNG stream) of earlier releases.

#### In-campaign crash deduplication (`--crash-dedup`)

At scale, one decoder bug fires from many distinct mutants — so the raw
`crashes/` directory's artifact count vastly exceeds the unique-bug count.
The [`mangle triage`](#triage-and-deduplicate-crashes) subcommand handles this
*after* the campaign by clustering the artifacts that were already written.
`--crash-dedup` does it *during* the campaign — the redundant artifact pair
is never written in the first place, so a long-running fuzz against a noisy
bug does not blow up the `crashes/` directory or the disk:

```bash
mangle fuzz \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/fuzz-out \
  --iterations 100000 \
  --crash-dedup
```

When `--crash-dedup` is set, each crashing iteration's decoder stderr is
fingerprinted with the *same* signature `mangle triage` uses
(ASAN/UBSAN top stack frames when present, normalised stderr hash otherwise),
and the `crashes/<hash>.{h265,txt}` artifact pair is written **only on the
first occurrence of each signature**. Subsequent crashes whose signature
matches an already-seen one are still recorded in `results.jsonl` (so the
outcome counts stay honest), and their row carries two new fields:

- `dedup_signature` — the signature this crash hashed to.
- `dedup_first` — `true` when this iteration was the first occurrence of
  the signature (so it wrote the artifact pair), `false` when it was a
  duplicate (suppressed).

The set of seen signatures is persisted to `dedup-signatures.json` so a
follow-on campaign into the *same* output directory resumes from the same
dedup state — a duplicate of a signature seen by the prior campaign is
suppressed even on the first iteration of the new one. `--dedup-frame-depth`
selects how many top sanitizer stack frames make up the signature (default 3,
matching `mangle triage --frame-depth`).

The summary line shifts to report both numbers so the operator can see what
dedup bought:

```
3 unique crash artifact(s) in /tmp/fuzz-out/crashes/ (147 duplicate(s)
suppressed by --crash-dedup; signatures persisted to
/tmp/fuzz-out/dedup-signatures.json)
```

Omitting `--crash-dedup` preserves the exact byte-identical behaviour of
earlier releases — every crash writes its artifact pair, no
`dedup-signatures.json` is touched, and the new results.jsonl fields are
recorded as `null`.

#### Adaptive mutator prioritisation (`--strategy`)

By default (`--strategy uniform`) every mutator is equally likely on every
iteration. That spends the same budget on a mutator that never crashes the
decoder as on one that crashes it repeatedly. `--strategy adaptive` turns the
campaign's own crash/abort outcomes into a feedback loop:

```bash
mangle fuzz \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/fuzz-out \
  --iterations 1000 \
  --strategy adaptive
```

mangle's harness is black-box — it shells out to ffmpeg / libde265 and never
sees edge coverage — so the only learning signal available is each decode's
verdict. The adaptive scheduler treats each mutator as an arm of a multi-armed
bandit: it tracks how often each mutator has been tried (`trials`) and how often
the result crashed or aborted (`rewards`), and weights selection toward the
productive mutators using a smoothed reward rate. A per-arm **exploration floor**
guarantees every mutator keeps being probed, so the long tail is never starved,
and with zero observations the scheduler starts out exactly uniform — it only
diverges as crashes accumulate. This is the realistic, in-architecture form of
"coverage-guided mutation prioritisation" for a harness that only sees pass/fail.

Adaptive mode runs iterations in rounds of `--concurrency` so each round's
verdicts update the scheduler before the next round is selected, and it writes
one extra artifact:

- `/tmp/fuzz-out/scheduler.json` — the learned per-mutator scoreboard
  (`trials` and `rewards` for every mutator), so the campaign's prioritisation
  decisions are auditable alongside the raw results.

Both strategies are fully deterministic for a given `--seed-rng` (the uniform
path's mutator/seed RNG stream is byte-identical to earlier mangle releases).

##### Resuming an adaptive scheduler (`--scheduler-state`)

Long fuzz campaigns are checkpointable: pass `--scheduler-state PATH` on a
follow-up `mangle fuzz` invocation and the adaptive scheduler warm-starts from
the prior campaign's `scheduler.json` instead of starting cold. The saved
per-mutator `trials` / `rewards` counts are *added* to the new scheduler's
counters, so a multi-run campaign keeps the prioritisation it learned — the
bandit's posterior is the same as if both runs had been one long run.

```bash
# First leg — runs cold, writes /tmp/fuzz-out/scheduler.json
mangle fuzz \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/fuzz-out \
  --iterations 1000 \
  --strategy adaptive

# Second leg — resumes with the bandit's accumulated knowledge
mangle fuzz \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/fuzz-out-2 \
  --iterations 1000 \
  --strategy adaptive \
  --scheduler-state /tmp/fuzz-out/scheduler.json
```

The new `scheduler.json` records a `resumed_from_prior_iterations` breadcrumb so
a chained `run -> run -> run` is self-documenting in the artifact itself. The
flag is only meaningful with `--strategy adaptive`; combining it with the
uniform scheduler is rejected with a clear error (the uniform scheduler does not
learn from outcomes, so resuming it is meaningless).

Cross-version resume is supported deliberately: mutators that appear in the
saved state but no longer exist in the current pool are dropped silently, and
mutators added to the pool since the prior run start cold. A stale
`scheduler.json` never blocks a resume — invalid count shapes
(`rewards > trials`, negatives, non-integer values) *do* fail fast so a corrupt
scoreboard cannot poison a new campaign.

#### Crash feedback loop (`--seed-from-crashes`)

The adaptive scheduler closes the loop on *which mutator* to spend budget on.
`--seed-from-crashes` closes a second loop — *which base input* to mutate.
Instead of fuzzing one `--seed`, point a new campaign at a previous campaign's
`crashes/` directory and every crash artifact becomes a base seed for the new
run:

```bash
# 1. an initial campaign produces /tmp/fuzz-out/crashes/
mangle fuzz --seed tests/fixtures/clean.h265 --output-dir /tmp/fuzz-out --iterations 1000

# 2. re-fuzz around those crashes — the feedback loop
mangle fuzz \
  --seed-from-crashes /tmp/fuzz-out/crashes \
  --output-dir /tmp/fuzz-loop \
  --iterations 2000
```

`--seed` and `--seed-from-crashes` are mutually exclusive — a campaign has
exactly one base-input source. A crashing mutant is a *deeper* input than the
original seed: it already drove the decoder off the spec-compliant path, so
re-mutating it explores the decoder state immediately around a known fault
(the classic AFL crash-corpus-reinjection step). The crash artifacts (`*.h265`)
are gathered into a base-seed pool, sorted by filename for determinism, and
iterations are assigned across the pool round-robin by iteration index. Each
iteration records the `base_seed` it mutated in `results.jsonl`, so a
crash-fed campaign stays exactly as replayable as a single-seed one — see
[Replay any iteration's mutant](#replay-any-iterations-mutant) for the
`--seed-dir` form replay uses to resolve those base seeds. Fully deterministic
for a given `--seed-rng`.

#### Multi-seed corpus (`--seed-corpus-dir`)

The engine-side companion of `mangle corpus` and `mangle corpus-trim`. Where
`--seed-from-crashes` re-mutates a *prior campaign's crashes*, `--seed-corpus-dir`
spreads a campaign's iterations across *any* directory of `*.h265` seed files —
typically the diverse, minimal corpus that `mangle corpus` produces (one seed
per SPS dimension class, chroma format, incomplete parameter-set shape, etc.),
optionally minimised through `mangle corpus-trim`:

```bash
# 1. Generate a diverse seed corpus from one seed file.
mangle corpus --seed tests/fixtures/clean.h265 --output-dir /tmp/corpus

# 2. (optional) Minimise the corpus to one seed per decode behaviour.
mangle corpus-trim --input-dir /tmp/corpus --output-dir /tmp/corpus-trimmed

# 3. Fuzz across the corpus — iterations spread round-robin across every seed.
mangle fuzz \
  --seed-corpus-dir /tmp/corpus-trimmed \
  --output-dir /tmp/fuzz-out \
  --iterations 2000
```

`--seed`, `--seed-from-crashes`, and `--seed-corpus-dir` are mutually exclusive
— a campaign has exactly one base-input source. The seeds are gathered into a
pool sorted by filename for determinism and iterations are assigned round-robin
by iteration index (the same dispatch as `--seed-from-crashes`). Each iteration
records the `base_seed` it mutated in `results.jsonl`, so the run stays fully
replayable via `mangle replay --seed-dir <the corpus dir>` (see
[Replay any iteration's mutant](#replay-any-iterations-mutant)). Non-`*.h265`
files in the directory are ignored, so a sibling `manifest.json` (the shape
`mangle corpus` writes) is left alone. Fully deterministic for a given
`--seed-rng`.

### Differential decoder oracle

```bash
mangle diff \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/diff-out \
  --iterations 100 \
  --left-decoder ffmpeg \
  --right-decoder libde265 \
  --timeout 5
```

A crash-only campaign (`mangle fuzz`) only catches inputs that make *one*
decoder fall over. It is blind to the larger class of bugs where two decoders
*disagree* on a malformed input — one crashes while the other silently accepts
and decodes it. Those disagreements are exactly the silent spec violations that
differential testing surfaces (TWINFUZZ, NDSS 2025): the silent-acceptor is
often the more dangerous target, because it decodes attacker-controlled garbage
without complaint.

`mangle diff` feeds every mutant through **two** decoders and records each
iteration's verdict. The two decoders must differ (`--left-decoder` ≠
`--right-decoder`). A **divergence** is recorded when they disagree on the crash
class:

- **`crash-split`** — exactly one decoder crashed/aborted while the other did
  not. The high-value signal: one decoder is vulnerable to an input the other
  tolerates.
- **`signal-split`** — both decoders failed, but with different outcomes (e.g.
  one `crash` via SIGSEGV, one `abort` via SIGABRT). A weaker but still
  actionable disagreement.
- **`output-divergence`** — both decoders accepted the input as `clean`, but
  produced different pixel data. Only surfaced when `--compare-output` is
  passed (see below).

A timeout is *not* treated as a crash-class failure, so a clean-vs-timeout pair
does not count as a divergence (but crash-vs-timeout does). Outputs:

- `/tmp/diff-out/diff.jsonl` — one JSON object per iteration: the mutator, both
  decoders' outcomes and return codes, whether it diverged, and the divergence
  kind. With `--compare-output`, each record additionally carries
  `left_output_hash` and `right_output_hash` (SHA256 of each decoder's raw
  YUV 4:2:0 stdout).
- `/tmp/diff-out/divergences/<hash>.h265` — the mutant for any divergence,
  alongside `<hash>.txt` holding a side-by-side report of **both** decoders'
  outcome, return code, captured `output_hash` (when present), and stderr, so
  the artifact alone explains why it was kept.

The mutator selection is seeded by `--seed-rng` and is fully reproducible.
Divergence artifacts feed directly into `mangle triage` for clustering.

#### `--compare-output` — silent-acceptor detection

```bash
mangle diff \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/diff-out \
  --iterations 100 \
  --left-decoder ffmpeg \
  --right-decoder libde265 \
  --compare-output
```

By default `mangle diff` only catches disagreements in the *crash class* —
inputs where one decoder falls over and the other doesn't. It is blind to the
TWINFUZZ "silent-acceptor" pattern: both decoders return successfully, but
produce **different pixel data** from the same bitstream. That class is the
gold-standard silent spec-violation signal — neither decoder complained, but
at least one of them got the math wrong.

With `--compare-output` each decoder is invoked via a raw-output command
(ffmpeg with `-f rawvideo -pix_fmt yuv420p -`, libde265 with `dec265 -q -o
/dev/stdout`) so its decoded YUV 4:2:0 frames flow to stdout. mangle hashes
the stdout bytes with SHA256 and stores the hex digest on each
`DecodeResult.output_hash`. When both decoders return `clean` but the hashes
differ, the iteration is classified as `output-divergence` and the mutant
plus a side-by-side report (including both `output_hash` values) is written
under `divergences/`, exactly like the existing crash-class kinds.

Crash-class divergences still take priority: if one decoder crashes the
iteration is still a `crash-split` regardless of any partial stdout. The
default (no `--compare-output`) campaign is byte-identical to the previous
behaviour — stdout is discarded and hashes are left `None`.

### Build a seed corpus

```bash
mangle corpus \
  --seed tests/fixtures/clean.h265 \
  --output-dir /tmp/corpus
```

Coverage-guided and manual fuzzing campaigns benefit from a diverse, compact
seed set rather than a single starting point. `mangle corpus` derives a spread
of distinct, still-well-framed seeds from one input file and writes them as
`<index>-<descriptor>.h265` plus a `manifest.json`. The generated classes are:

- **Dimension boundaries** — the full grid of widths × heights from
  `{1, 2, 16, 64, 256, 4096, 65535}`, each spliced into the seed's SPS
  (`pic_width/height_in_luma_samples`), covering tiny, typical, large, and
  overflow-prone buffer-sizing paths.
- **Chroma formats** — `chroma_format_idc` rewritten to each of
  `{0=monochrome, 1=4:2:0, 2=4:2:2}` the seed does not already use, without
  realigning the following bits (the inconsistent-format case is the
  `sps-chroma-format` *mutator's* job, not the corpus builder's).
- **Incomplete parameter sets** — VPS-only, SPS-only, and PPS-only single-NAL
  streams, exercising the "missing parameter set" code paths.
- **NAL ordering** — a non-IRAP slice moved ahead of the first IRAP, exercising
  the "no prior IRAP / missing reference" paths (emitted only when the seed
  actually contains a reorderable IRAP + non-IRAP VCL pair).

The builder never hand-rolls a parameter set: it reuses the same bitstream
assembly and SPS splice machinery the mutators use, so every emitted seed shares
the input's valid framing and only the targeted field differs. Output is fully
deterministic (no RNG). Any seed class that cannot be produced from a given input
(e.g. a chroma rewrite on an SPS that does not parse that far, or the ordering
seed on a single-frame input) is **skipped and recorded in the manifest** rather
than faked — `manifest.json` lists every emitted seed and every skip with its
reason code.

### Trim a corpus to one seed per behaviour

```bash
mangle corpus-trim \
  --input-dir /tmp/corpus \
  --output-dir /tmp/corpus-min
```

`mangle corpus` *builds* a diverse seed set and `mangle reduce` minimises a single
*crash*; neither shrinks a whole *corpus*. A corpus accumulated over many
campaigns (generated seeds, crash-derived seeds, samples from the wild) is almost
always redundant — many files exercise the exact same decoder behaviour and only
differ in incidental bytes. Carrying that redundancy slows every pass: each extra
seed is an extra decode that buys no new behaviour. `mangle corpus-trim` is the
`afl-cmin` step of the workflow — it keeps a **minimal subset** that preserves the
corpus's full set of observed decoder behaviours and drops every redundant seed.

It probes each seed through a decoder once and buckets seeds by their decode
**behaviour**:

- **crash / abort** — keyed by the same crash **signature** `mangle triage` uses
  (ASAN/UBSAN top `--frame-depth` frames when a sanitizer build is present, else a
  normalised-stderr hash). Two seeds that crash with the same fingerprint are the
  same behaviour.
- **clean** — all cleanly-decoding seeds collapse to one bucket (a corpus needs
  only one representative well-framed seed).
- **timeout / hang** — kept as their own buckets (a seed that wedges the decoder
  is worth a representative).

Within each bucket the **representative** is the smallest file (cheapest to
re-decode, most minimal), tie-broken by name for determinism. Outputs:

- the kept representatives are copied verbatim into `--output-dir`;
- `/tmp/corpus-min/trim-manifest.json` records every input seed's verdict: its
  byte size, decode outcome, behaviour key, whether it was kept, and (for a
  dropped seed) which representative subsumed it.

`corpus-trim` runs one decode per input seed and is fully deterministic (seeds are
processed in sorted-name order and the probe is a pure function of the bytes).
`--pattern` (default `*.h265`) controls which files count as seeds.

### Triage and deduplicate crashes

```bash
mangle triage \
  --output-dir /tmp/fuzz-out
```

At scale a single decoder bug fires from many distinct mutants, so the
`crashes/` directory holds far more artifacts than unique bugs. `mangle triage`
is a pure post-processing pass over a fuzz output directory — it reads
`results.jsonl` and the `crashes/<hash>.txt` stderr files and clusters crashes
by a stable **signature**:

- **ASAN / UBSAN stack frames** — when the decoder was built with a sanitizer,
  its stderr embeds a symbolised backtrace. The top frames (`--frame-depth`,
  default 3) are the gold-standard fingerprint: two inputs whose top frames match
  are the same bug. Function names only — addresses and line numbers (which shift
  between builds and inputs) are deliberately excluded.
- **Normalised-stderr fallback** — for a plain (non-sanitizer) build, the stderr
  is normalised (lower-cased, with hex addresses, integers, and `.h265`/`.hevc`
  paths scrubbed) and hashed, so two messages differing only in incidental
  numbers cluster together.

The cluster key is the triple `(signature, decoder, mutator)`. Each cluster keeps
its **most minimal** member as the representative (smallest mutant file, ties
broken deterministically). Outputs:

- `/tmp/fuzz-out/triage.jsonl` — one JSON line per cluster: cluster id, signature
  kind, signature, decoder, mutator, member count, representative hash, the
  representative's top stack frames, and all member hashes.
- `/tmp/fuzz-out/unique-crashes/<hash>.h265` + `<hash>.txt` — the representative
  PoC of each cluster, copied verbatim and ready for disclosure.

The `--decoder` label is recorded in the cluster key (so a combined triage of two
campaigns keeps per-decoder buckets distinct). Triage makes **no changes** to the
fuzzing pipeline and is fully deterministic.

### Minimise a crash to its smallest reproducer

```bash
mangle reduce \
  --crash /tmp/fuzz-out/unique-crashes/abc123.h265 \
  --output /tmp/poc-minimal.h265
```

`triage` picks the smallest crashing mutant a campaign *happened* to produce; it
does not shrink it. A mutant still carries the seed's full NAL framing (VPS, SPS,
PPS, SEI, several slices) even when a single NAL unit is the load-bearing cause of
the crash. `mangle reduce` is the `afl-tmin` / `creduce` step of the workflow: it
finds the **minimal NAL-unit subset** that still reproduces the same bug — the
reproducer you actually attach to a disclosure.

Because mangle understands HEVC framing, reduction works at the **NAL-unit**
granularity (not the raw-byte granularity a generic minimiser uses), applying the
classic **ddmin** delta-debugging algorithm (Zeller & Hildebrandt, IEEE TSE 2002)
over the NAL-unit list: try removing chunks (largest first), keep any removal that
still crashes, and increase granularity until nothing more can be dropped.

The "still crashes?" oracle is **signature-stable**: a candidate is kept only when
the decoder hits the *same* crash signature (the same ASAN-top-frame /
normalised-stderr fingerprint `mangle triage` uses). That stops the reducer from
"succeeding" by swapping the original bug for a different crash — the classic
failure mode of naive minimisers. `--decoder`, `--timeout`, and `--frame-depth`
control the oracle exactly as in `triage` / `fuzz`. The reduction is deterministic
and prints how many NAL units and bytes were removed:

```text
reduced 6 -> 2 NAL unit(s) (4 removed)
reduced 812 -> 196 bytes (616 removed, 75.9% smaller)
crash signature preserved: ff_hevc_decode_short_term_rps|hevc_parse_sps
decode probes: 11
minimal reproducer written to /tmp/poc-minimal.h265
```

The input must be a *confirmed* crash: if the decoder does not crash on it,
`reduce` errors out rather than emitting a meaningless "minimal" file.

### Replay any iteration's mutant

```bash
mangle replay \
  --seed seed.h265 \
  --output-dir /tmp/fuzz-out \
  --iteration 73 \
  --output /tmp/iter-73.h265
```

A `fuzz` campaign records, for every iteration, the exact mutator and
per-iteration RNG seed it used (the `mutator` and `seed_rng` columns in
`results.jsonl`). Because every mutator is a pure function of `(seed bytes,
random.Random(seed))` and the NAL split/assemble round-trips losslessly, that
pair fully reproduces the iteration's mutant. `mangle replay` re-applies it to
the original `--seed` file and re-derives the **byte-identical** mutant for *any*
iteration — running no decoder and changing nothing in the pipeline.

This closes the one gap `triage` and `reduce` leave open: both operate on the
*saved crash artifacts*, but a campaign only writes mutants to `crashes/` when
they crash/abort. The clean, timeout, and hang iterations are never saved. Replay
reconstructs those from metadata alone, so you can recover a timeout/hang input
the campaign discarded, or hand a colleague a one-line recipe (`--seed` +
iteration number) instead of a binary blob.

For a campaign fuzzed with `--seed-from-crashes`, each iteration mutated a
*different* base input (a specific crash artifact from the prior campaign's
pool), so there is no single `--seed` to re-apply. Replay records the base
artifact's filename in each row's `base_seed` column; pass `--seed-dir` (the
prior campaign's `crashes/` directory) instead of `--seed` and replay resolves
the right base seed per iteration automatically:

```bash
mangle replay \
  --seed-dir /tmp/fuzz-out/crashes \
  --output-dir /tmp/fuzz-loop \
  --iteration 73 \
  --output /tmp/iter-73.h265
```

`--seed` and `--seed-dir` mirror the `fuzz` side: use `--seed` to replay a
single-seed campaign, `--seed-dir` to replay a `--seed-from-crashes` one.

When the iteration *was* a crash, replay cross-checks the re-derived bytes
against the saved `crashes/<hash>.h265` artifact — a reproducibility / tamper
check that fails loudly if the on-disk artifact no longer matches what the
recorded seed produces:

```text
replayed iteration 73: [sps-rext-flags] seed_rng=2179419893 outcome=crash
reconstructed 3368 bytes
mutant sha256: a1e0dd48cc46177236bcba93eede19a47e91ed9ff60631f8675aa1e59935dc98
verified: re-derived mutant matches saved crashes/a1e0dd48cc461772.h265
mutant written to /tmp/iter-73.h265
```

### Report a campaign's mutation coverage

```bash
mangle coverage \
  --output-dir /tmp/fuzz-out
```

mangle is a **black-box** harness — it shells out to ffmpeg / libde265 and sees
only each decode's pass/fail outcome, not edge coverage, so it cannot produce a
libFuzzer/AFL-style coverage map. The coverage question it *can* answer is
**structural**: did this campaign exercise the full mutator surface, how did each
mutator's outcomes distribute, and which registered mutators did it never reach?

`mangle coverage` is a pure post-processing pass over the `results.jsonl` a
`fuzz` campaign already wrote (no decoder, fully deterministic — the same
read-only shape as `triage` and `replay`). For each mutator it reports the
iterations spent, the outcome breakdown, the crash/abort count, and — crucially —
the number of **distinct crash signatures** found, computed with the exact triage
fingerprint (ASAN top frames, else normalised-stderr hash). That distinct-bug
count stops a mutator that crashed 500 times on *one* bug from masquerading as
broad coverage.

At the campaign level it lists the **exercised** mutators and the **uncovered**
blind spots against the live registry, the coverage and productive fractions, and
any unknown mutators present in the results (e.g. a `results.jsonl` written by a
different mangle build):

```text
mutator coverage: 3/22 registered mutators exercised (14%) over 4 iteration(s)
  productive: 1/22 crashed/aborted the decoder (5%)
  nal-emulation-bytes: 1 iter [timeout=1]
  rps-overflow: 2 iter [crash=2], 1 distinct bug(s)
  sps-bit-depth: 1 iter [clean=1]
uncovered (19 mutator(s) never selected):
  nal-unit-type-swap
  pps-deblocking
  ...
coverage report written to /tmp/fuzz-out/coverage.json
```

Outputs:

- `/tmp/fuzz-out/coverage.json` — the full report: `registry_size`,
  `exercised_count`, `productive_count`, `coverage_fraction`,
  `productive_fraction`, the `exercised` / `uncovered` / `unknown_mutators`
  lists, and a per-mutator `mutators` array (`iterations`, `outcomes`,
  `crash_aborts`, `distinct_signatures`, `bytes_changed`, `known`).

`--frame-depth` (default 3) controls how many top sanitizer stack frames feed the
distinct-bug fingerprint, exactly as in `triage` / `reduce` / `corpus-trim`. Use
this to spot under-tested mutators (raise their `--mutator` weight or seed
diversity next campaign) and to quantify a campaign's breadth before disclosure.

### Report a mutation heat-map by bitstream region

```bash
mangle heatmap \
  --output-dir /tmp/fuzz-out
```

Where `coverage` reports per-mutator stats as a **flat list** of 22 rows,
`heatmap` rolls them up by the **bitstream region** each mutator targets — VPS,
SPS, PPS, slice-header, RPS, SEI, or raw NAL framing — derived deterministically
from the mutator name's prefix. mangle is a grammar-aware fuzzer, so every
mutator aims at a specific structural area of the H.265 stream; this is the
*"where is the soft spot in the parser?"* view that a flat per-mutator list does
not give you.

`mangle heatmap` is a pure post-processing pass over the campaign's
`results.jsonl` (no decoder, fully deterministic — the same read-only shape as
`coverage` / `triage` / `replay`). For each region it reports the iterations
spent (the **pressure** axis), the outcome breakdown, the crash/abort count and
the number of **distinct bugs** (the **reward** axis, deduplicated with the exact
triage fingerprint so many crashes on one bug do not inflate a region), the bytes
changed, the registry mutators that map to the region, and two intensities:
`iteration_share` (the region's fraction of all iterations) and `crash_share`
(its fraction of all crash/abort iterations).

That `iteration_share` vs `crash_share` pair *is* the heat-map. A region whose
crash share far exceeds its pressure share is hotter than its effort — the
profitable target to lean into next campaign; a region that soaks up iterations
but yields nothing is wasted pressure. Regions are listed hottest-first (most
crashes, then most iterations, then name):

```text
mutation heat-map: 4 iteration(s) across 3 bitstream region(s), 2 crash/abort(s)
  hottest region: rps
  rps: 2 iter (50% pressure) -> 2 crash/abort (100% reward), 2 distinct bug(s) [crash=2]
  pps: 1 iter (25% pressure) -> 0 crash/abort (0% reward) [clean=1]
  sps: 1 iter (25% pressure) -> 0 crash/abort (0% reward) [clean=1]
heat-map written to /tmp/fuzz-out/heatmap.json
```

Outputs:

- `/tmp/fuzz-out/heatmap.json` — the full report: `total_iterations`,
  `total_crash_aborts`, `region_count`, `hottest_region`, and a per-region
  `regions` array (`region`, `iterations`, `outcomes`, `crash_aborts`,
  `distinct_signatures`, `bytes_changed`, `mutators`, `iteration_share`,
  `crash_share`).

`--frame-depth` (default 3) controls how many top sanitizer stack frames feed the
per-region distinct-bug count, exactly as in `coverage` / `triage` / `reduce` /
`corpus-trim`. A mutator whose name carries an unmapped prefix buckets under an
`other` region rather than being dropped.

### AFL++ coverage-guided fuzzing integration (`mangle afl-mutate`)

`mangle`'s built-in `fuzz` loop is **black-box** — it only sees each
decoder's pass/fail outcome (see `src/mangle/scheduler.py` and
`src/mangle/coverage.py` for the design notes). The adaptive scheduler is
the in-architecture answer to "coverage-guided mutation prioritisation" but
it has no view of the decoder's execution traces; it cannot do *true*
coverage-guided fuzzing.

The honest path to real coverage-guided fuzzing is to bridge mangle's
grammar-aware mutators into [AFL++](https://aflplus.plus/), which provides
the edge-coverage feedback loop. Two integration paths are supported, both
documented in [`contrib/afl-harness/README.md`](contrib/afl-harness/README.md):

**Path 1 — corpus pre-processing (no harness build required).** Use `mangle
corpus` and `mangle corpus-trim` to build a diverse, minimal HEVC seed
corpus, then point `afl-fuzz` at it:

```bash
mangle corpus      --seed clean.h265 --output-dir seeds/
mangle corpus-trim --input-dir seeds/ --output-dir seeds-trimmed/ --decoder ffmpeg
afl-fuzz -i seeds-trimmed/ -o afl-out/ -- ffmpeg -v error -i @@ -f null -
```

Grammar-aware seed diversity is the single largest leverage point for
mutational fuzzers (TWINFUZZ NDSS 2025, FuzzWise 2025).

**Path 2 — persistent-mode harness (in-process, ~50× throughput).** Build
the reference `harness.c` in `contrib/afl-harness/` with `afl-clang-fast`
and let it call `mangle afl-mutate` in its inner loop:

```bash
make -C contrib/afl-harness CC=afl-clang-fast
AFL_AUTORESUME=1 afl-fuzz \
    -i seeds-trimmed/ \
    -o afl-out/ \
    -- ./contrib/afl-harness/mangle-afl-harness @@
```

The `afl-mutate` subcommand is the load-bearing glue — a stdin/stdout
adapter around the grammar-aware mutator engine:

```bash
mangle afl-mutate \
    --seed tests/fixtures/clean.h265 \
    --mutator sps-dimensions \
    --seed-rng 42 > mutant.h265
```

Reads the seed from `--seed` (the AFL `@@` convention — AFL replaces `@@`
with the candidate path before invoking the harness), applies one mutator,
writes the mutant bytes to **stdout** (no other output on stdout, so the
output is safe to pipe straight into a decoder), and reports the byte count
on **stderr**. Deterministic for `(seed, --mutator, --seed-rng)`.

### List the available mutators

```bash
mangle mutators
```

---

## Mutators

| Mutator | Target | What it does |
|---|---|---|
| `sps-dimensions` | SPS | Rewrites `pic_width/height_in_luma_samples` to spec-inconsistent values |
| `pps-tile-config` | PPS | Flips `tiles_enabled_flag` / `entropy_coding_sync_enabled_flag` without the dependent geometry |
| `slice-header-ref-pic-list` | Slice header | Corrupts the fields driving reference-picture-list management (PPS id, first-slice flag) |
| `nal-unit-type-swap` | NAL header | Relabels a NAL unit to a different, inconsistent `nal_unit_type` |
| `rps-overflow` | SPS short-term RPS | Sets `num_negative_pics` / `num_positive_pics` above `sps_max_dec_pic_buffering_minus1[0]` to overflow decoder DPB index arrays |
| `rps-lt-poc-ambiguity` | SPS long-term RPS | Crafts two long-term reference entries sharing one `poc_lsb_lt`, triggering the ambiguous-POC-LSB condition |
| `vps-layer-count` | VPS | Corrupts `vps_max_layers_minus1` / `vps_max_sub_layers_minus1` / `vps_temporal_id_nesting_flag` to overflow per-layer array bounds in hardware and software decoders |
| `pps-deblocking` | PPS | Corrupts the deblocking / loop-filter control fields — pushes `pps_beta_offset_div2` / `pps_tc_offset_div2` out of the spec range `[-6, 6]`, flips `pps_deblocking_filter_disabled_flag`, or flips `pps_loop_filter_across_slices_enabled_flag` |
| `sps-chroma-format` | SPS | Rewrites `chroma_format_idc` to a reserved value (4) or forces 4:4:4 (3) without a reserved `separate_colour_plane_flag` bit, desynchronising the sample format |
| `sps-bit-depth` | SPS | Pushes `bit_depth_luma_minus8` / `bit_depth_chroma_minus8` above the spec ceiling of 8 (>16-bit samples) to stress sample-buffer sizing |
| `pps-slice-qp` | PPS | Pushes `init_qp_minus26` out of the spec range `[-26, 25]`, or flips `transform_skip_enabled_flag` without the matching SPS range-extension flags |
| `nal-emulation-bytes` | NAL EBSP (raw bytes) | Inserts a phantom `0x000003` emulation sequence, drops a real emulation-prevention byte, or floods the payload head with `0x000003` triplets to stress the decoder's EBSP-to-RBSP scanner |
| `sps-feature-flags` | SPS | Flips `scaling_list_enabled_flag` or `pcm_enabled_flag` on without supplying the variable-length data block it gates, desynchronising the rest of the SPS |
| `sps-vui-hrd` | SPS VUI | Flips a VUI / HRD gate flag (`vui_hrd_parameters_present_flag`, `vui_timing_info_present_flag`, or `vui_parameters_present_flag`) on without supplying the sub-block it gates, forcing the decoder to read CPB/HRD fields out of unrelated downstream bits |
| `sps-rext-flags` | SPS extension | Flips an SPS extension gate (`sps_range_extension_flag`, preferred, or `sps_extension_present_flag`) on without supplying the `sps_range_extension()` body, forcing the decoder onto its HEVC Range-Extension parse path with no valid extension parameter set behind it |
| `pps-extension-flags` | PPS extension | Flips a PPS extension gate (`pps_extension_present_flag`, preferred, or `pps_scaling_list_data_present_flag`) on without supplying the dependent `scaling_list_data()` / profile-extension body, forcing the decoder to read scaling-list coefficients or extension flags out of the PPS trailing bits |
| `slice-no-output-prior-pics` | Slice header (IRAP) | Flips `no_output_of_prior_pics_flag` in an IRAP slice header, inverting the decoder's decision to discard the DPB without outputting its pictures when a new coded-video-sequence begins |
| `vps-timing-info` | VPS | Flips `vps_timing_info_present_flag` on without supplying the dependent `vps_timing_info` / `hrd_parameters()` sub-block, forcing the decoder to read `num_units_in_tick` / `time_scale` and an HRD walk out of the VPS trailing bits |
| `pps-slice-header-extension` | PPS → slice header | Flips `slice_segment_header_extension_present_flag` on in the PPS without the slices carrying the dependent extension block, so every slice header desyncs reading a `slice_segment_header_extension_length` ue(v) out of unrelated bits |
| `pps-lists-modification` | PPS → slice header | Flips `lists_modification_present_flag` on in the PPS without any slice carrying `ref_pic_list_modification()`, so every inter slice header desyncs reading `list_entry_lX` reference-list reorder indices — out-of-range entries are an out-of-bounds reference-list access |
| `pps-deblocking-control-gate` | PPS | Flips `deblocking_filter_control_present_flag` on without the dependent override / disable / beta-tc-offset sub-block, so the decoder reads the deblocking fields out of the PPS tail (`pps_scaling_list_data_present_flag` and beyond) and desyncs every following gate |

All structured mutators keep the stream a parseable Annex-B bitstream while pushing
it out of semantic spec-compliance — the input class that exercises decoder edge
cases. The one exception is `nal-emulation-bytes`, which deliberately malforms the
on-wire byte encoding (see below) to target the decoder's emulation-prevention
scanner directly.

### Reference Picture Set (RPS) mutators

The two RPS mutators target the reference-picture-set syntax in the SPS
(H.265 §7.3.7), the region that informs decoder-picture-buffer (DPB) sizing and
long-term reference resolution:

- **`rps-overflow`** raises `num_negative_pics` (or `num_positive_pics`) in the
  short-term RPS above `sps_max_dec_pic_buffering_minus1[0]`. Decoders that size
  DPB index arrays from the DPB bound but loop on the raw RPS count walk past the
  end of those arrays — the DPB-sizing bug class behind **CVE-2026-33164**
  (libde265 `set_derived_values()`). When the seed declares zero short-term RPS
  sets (an intra-only stream), the mutator synthesises one carrying the overflow
  count; otherwise it rewrites the first existing set.

- **`rps-lt-poc-ambiguity`** emits two long-term RPS entries with an identical
  `poc_lsb_lt` and no `delta_poc_msb` override, reproducing the ambiguous POC-LSB
  condition of **HEVC trac #1097** — where multiple DPB entries share the same
  long-term POC LSB and the reference model (and downstream forks) miscalculate
  which picture a long-term reference resolves to.

### VPS (Video Parameter Set) mutator

- **`vps-layer-count`** targets the three fixed-width fields that open the VPS
  RBSP (H.265 §7.3.2.1). One mutation is chosen per invocation:
  - **Layer overflow**: sets `vps_max_layers_minus1` to 63 (the 6-bit field max),
    overflowing the `HEVC_MAX_LAYERS = 63` array-bound guard used by decoders
    (e.g. ffmpeg `hevcdec.c`) that loop on this value to allocate per-layer state.
  - **Sub-layer overflow**: sets `vps_max_sub_layers_minus1` to 7 (3-bit field
    max; spec range 0..6), overflowing per-sublayer DPB arrays indexed up to this
    value.
  - **Nesting-flag violation**: flips `vps_temporal_id_nesting_flag` while
    clamping `vps_max_sub_layers_minus1` to 0 — a direct spec violation (the
    standard requires nesting_flag=1 when sub_layers=0) that exercises
    "nesting check" code paths in conformance validators and decoders.

  Motivation: the **TWINFUZZ** paper (NDSS 2025) showed hardware-acceleration
  stacks are disproportionately vulnerable to spec violations in the
  parameter-set layer.

- **`vps-timing-info`** reaches deeper into the same VPS RBSP than
  `vps-layer-count`: the parser now walks past `profile_tier_level`, the
  sub-layer DPB-ordering loop and the layer-set inclusion loop to the
  `vps_timing_info_present_flag` gate (H.265 §7.3.2.1). That single u(1) flag
  gates a variable-length `vps_timing_info` sub-block — `vps_num_units_in_tick`
  u(32), `vps_time_scale` u(32), `vps_poc_proportional_to_timing_flag`, an
  optional `vps_num_ticks_poc_diff_one_minus1` ue(v), and a
  `vps_num_hrd_parameters` ue(v) loop of `hrd_parameters()` structures. The
  mutator flips the gate *on* without supplying any of that data, so the decoder
  consumes 64+ bits of timing fields and an `hrd_parameters()` walk out of the
  VPS trailing bits, forcing it onto the HRD-timing parse path with no valid
  parameter set behind it. HRD timing arithmetic is the field class behind
  **CVE-2022-22675**, and the VPS timing block is the VPS analogue of the SPS
  `sps-vui-hrd` gate — an entirely untouched VPS attack surface. The mutator only
  fires when the seed's gate is currently off (the "claims data that isn't there"
  direction that desynchronises the tail without being rejected as broken
  framing); when the VPS uses multi-layer / multi-sub-layer geometry the parser
  does not model, is truncated, or already has the gate on, the mutator raises so
  the engine picks another.

### PPS deblocking / loop-filter mutator

- **`pps-deblocking`** targets the deblocking-filter control region of the PPS
  (H.265 §7.3.2.3) — the per-picture loop-filter syntax that feeds the same
  `set_derived_values()` derive path behind **CVE-2026-33164** (libde265
  `<1.0.17`). The parser advances past the (optional, untiled) entropy/loop-filter
  flags to reach the control block; tiled PPSes carry variable-length geometry and
  are deliberately skipped. One mutation is chosen per invocation from those the
  seed PPS actually exposes:
  - **Out-of-range beta/tc offset**: rewrites `pps_beta_offset_div2` or
    `pps_tc_offset_div2` (se(v), spec range `[-6, 6]`) to a far out-of-range
    magnitude (±32/±64), pushing filter-strength table lookups past their bounds.
  - **Disable-flag flip**: toggles `pps_deblocking_filter_disabled_flag`, making
    the PPS claim the filter is on/off inconsistently with the offsets that follow.
  - **Loop-filter-scope flip**: toggles
    `pps_loop_filter_across_slices_enabled_flag`, exercising the slice-boundary
    filter path. This field is reachable in any untiled PPS, so it is the
    conservative fallback when the deeper control block is absent.

- **`pps-deblocking-control-gate`** is the companion to `pps-deblocking`: it
  targets the deblocking-control *gate* itself — `deblocking_filter_control_present_flag`
  (H.265 §7.3.2.3) — which `pps-deblocking` reads to choose its menu but never
  flips. Reachable in any untiled PPS, the gate sits right after
  `pps_loop_filter_across_slices_enabled_flag`. The mutator flips it from 0 to 1
  without the dependent `deblocking_filter_override_enabled_flag` /
  `pps_deblocking_filter_disabled_flag` / `pps_beta_offset_div2` /
  `pps_tc_offset_div2` sub-block actually present, so the decoder reads those
  fields out of the bits that really hold `pps_scaling_list_data_present_flag`,
  `lists_modification_present_flag` and the gates that follow — desyncing the entire
  PPS tail and deriving the deblocking state (the **CVE-2026-33164**
  `set_derived_values()` derive path) from garbage. It is the deblocking-side
  member of the gate-on desync family (`pps-extension-flags`,
  `pps-slice-header-extension`, `pps-lists-modification`, `sps-vui-hrd`,
  `sps-rext-flags`, `vps-timing-info`). It raises on a tiled / truncated PPS or one
  whose control gate is already on, so the engine can pick another mutator. Note
  `deblocking_filter_override_enabled_flag` is *not* a reachable target on an
  off-gate seed: it exists in the bitstream only when the control gate is already
  on, which is why the gate bit itself is the field this mutator targets.

### Chroma-format and bit-depth SPS mutators

These two mutators target the sample-format fields of the SPS (H.265 §7.3.2.2.1)
— the values that drive chroma subsampling and per-sample buffer sizing
throughout a decoder:

- **`sps-chroma-format`** rewrites `chroma_format_idc` (ue(v)). Valid values are
  0 (monochrome), 1 (4:2:0), 2 (4:2:2), 3 (4:4:4). One of two corruptions is
  chosen per invocation: setting it to **4** (reserved — one entry past the
  chroma-subsampling lookup table), or, when the seed is not already 4:4:4,
  forcing it to **3** so the decoder expects a `separate_colour_plane_flag` bit
  the bitstream never reserved, desynchronising every following field. This is the
  sample-format analogue of the width/height/container mismatch class behind
  **CVE-2022-3266** (Firefox).

- **`sps-bit-depth`** rewrites `bit_depth_luma_minus8` or `bit_depth_chroma_minus8`
  (ue(v), spec range `[0, 8]`) to a value well past 8 — i.e. claiming >16-bit
  samples. Decoders that size sample buffers as `(bit_depth + 1)` bytes (or shift
  by the raw value) over-allocate, mis-shift, or wrap a size computation; many
  hardware HEVC decoders branch 8-bit and 10-bit paths into separate firmware,
  and a bit depth they do not recognise forces a guess or a fault.

### Slice-QP / transform-skip PPS mutator

- **`pps-slice-qp`** targets the picture-level quantization and transform-skip
  controls in the PPS (H.265 §7.4.3.3), which precede the tile-config flags and so
  are reachable for any PPS that parses at all. One of two corruptions is chosen
  per invocation:
  - **Out-of-range `init_qp_minus26`**: rewrites the se(v) picture-QP baseline to
    ±52, well outside the spec range `[-26, 25]`. Decoders that pre-allocate a
    dequant coefficient table sized by `maxQP - minQP + 1` and clamp the baseline
    incorrectly can compute a zero or negative allocation size, or index a scaling
    table out of bounds — a productive integer-overflow class.
  - **`transform_skip_enabled_flag` flip**: toggles the u(1) flag. Enabling it
    without the matching SPS range-extension flags (`transform_skip_rotation_enabled_flag`
    etc.) creates an inconsistency that exercises range-extension handling paths.

### SPS feature-toggle flag mutator

- **`sps-feature-flags`** flips an SPS feature-toggle flag *on* without supplying
  the variable-length data block it gates (H.265 §7.3.2.2.1), creating an internal
  inconsistency that desynchronises every field after the flag. One reachable
  flag that is currently *off* is chosen per invocation:
  - **`scaling_list_enabled_flag`**: when set to 1 the decoder expects an
    `sps_scaling_list_data_present_flag` (and, if set, a full `scaling_list_data()`
    structure) that the bitstream never reserved. Scaling lists are a previously
    untouched SPS attack surface (gap-analysis item #8) and feed quantization
    matrices that several decoders copy into fixed-size tables.
  - **`pcm_enabled_flag`**: when set to 1 a five-element PCM configuration block
    follows; forcing it on without that block makes the decoder read PCM geometry
    out of unrelated downstream bits, exercising the I_PCM sample-copy path that
    has historically produced out-of-bounds sample writes.

  Both targets are single u(1) bits, so the splice never shifts the bitstream
  length — only one flag bit changes; the downstream desync is purely semantic,
  exactly the input class that exercises decoder code paths without being rejected
  as malformed framing. Only flags the seed currently has *off* are offered; if
  neither reachable flag is off (or the SPS truncates before the flag region) the
  mutator raises so the engine picks another.

### SPS VUI / HRD gate mutator

- **`sps-vui-hrd`** targets the Video Usability Information block at the tail of the
  SPS (H.265 §E.2.1) — gap-analysis item #7 ("HRD parameters in VUI"), a previously
  untouched SPS attack surface. The VUI block is reached by parsing past the
  reference-picture-set region and the two trailing feature flags
  (`sps_temporal_mvp_enabled_flag`, `strong_intra_smoothing_enabled_flag`). Inside
  it, three nested single-bit gates each guard a variable-length sub-block; the
  mutator flips one (currently *off*) gate *on* without supplying the sub-block it
  gates, the cleaner "claims data that isn't there" direction:
  - **`vui_hrd_parameters_present_flag`** (preferred when reachable): forcing it on
    makes the decoder expect an `hrd_parameters()` structure that the bitstream never
    reserved, reading CPB/HRD register fields (`cpb_cnt_minus1`,
    `initial_cpb_removal_delay`) out of unrelated downstream bits. HRD arithmetic is
    the field class behind CVE-2022-22675.
  - **`vui_timing_info_present_flag`**: gates 64 bits of timing info
    (`num_units_in_tick`, `time_scale`) plus the HRD gate; flipping it on consumes
    those from the wrong bits.
  - **`vui_parameters_present_flag`**: the outermost gate; flipping it on forces the
    whole `vui_parameters()` walk over absent data.

  Every target is a single u(1) bit, so the splice never shifts the bitstream length
  — only one gate bit changes and the downstream desync is purely semantic. Only
  gates the seed currently has *off* are offered; if every reachable gate is already
  on (or the SPS truncates before the VUI) the mutator raises so the engine picks
  another.

### SPS Range-Extension (RExt) gate mutator

- **`sps-rext-flags`** targets the SPS profile-extension region that follows the VUI
  block (H.265 §7.3.2.2.1) — gap-analysis item #8 ("HEVC range extensions (RExt)
  flags"), the last untouched SPS attack surface. To reach it the parser now walks
  *past* the VUI block: when VUI is absent the extension gate follows immediately,
  and when VUI is present (but its HRD sub-block is not) the parser walks the VUI
  tail (`bitstream_restriction_flag` block) to land on the extension gate. The region
  is guarded by single-bit gates that each turn on additional syntax:
  - **`sps_range_extension_flag`** (preferred when reachable): forcing it on makes the
    decoder expect an `sps_range_extension()` structure — nine RExt feature bits
    (`transform_skip_rotation_enabled_flag`, `transform_skip_context_enabled_flag`,
    `implicit_rdpcm_enabled_flag`, `explicit_rdpcm_enabled_flag`,
    `extended_precision_processing_flag`, `intra_smoothing_disabled_flag`,
    `high_precision_offsets_enabled_flag`, `persistent_rice_adaptation_enabled_flag`,
    `cabac_bypass_alignment_enabled_flag`) — that the bitstream never reserved. The
    decoder reads those bits out of the SPS trailing bits, switching coefficient
    coding onto the Range-Extension path (extended precision, RDPCM, transform-skip
    rotation/context) with no valid parameter set behind it.
  - **`sps_extension_present_flag`**: the outermost gate; flipping it on forces the
    decoder to read the four profile-extension flags and `sps_extension_4bits` (and
    any extension body they enable) out of absent data.

  Every target is a single u(1) bit, so the splice never shifts the bitstream length
  — only one gate bit changes and the downstream desync is purely semantic. Only
  gates the seed currently has *off* are offered; if no off gate is reachable (e.g.
  the extension is already on, or the seed's VUI carries an HRD sub-block whose
  variable-length body blocks the walk to the extension region) the mutator raises so
  the engine picks another.

- **`pps-extension-flags`** is the PPS analogue of `sps-rext-flags` — it targets the
  PPS extension gate region (H.265 §7.3.2.1), the PPS half of gap-analysis items #8
  (scaling lists) and #10 (extension flags). To reach it the PPS parser walks *past*
  the deblocking-filter control region into the short, fully-modellable run of flags
  that precede the extension gates. The region is guarded by two single-bit gates,
  each of which promises a variable-length sub-block when set:
  - **`pps_extension_present_flag`** (preferred when reachable): forcing it on makes
    the decoder read four PPS profile-extension flags (`pps_range_extension_flag`,
    `pps_multilayer_extension_flag`, `pps_3d_extension_flag`, `pps_scc_extension_flag`)
    plus a 4-bit `pps_extension_4bits` (and any enabled extension body) out of the PPS
    trailing bits.
  - **`pps_scaling_list_data_present_flag`**: forcing it on makes the decoder read a
    `scaling_list_data()` structure (H.265 §7.3.4) — DC-coefficient and
    delta-coefficient loops sized by the scaling lists' dimensions, a region prone to
    out-of-bounds reads — that the bitstream never reserved.

  Each target is a single u(1) bit, so the splice never shifts the bitstream length —
  only one gate bit changes and the downstream desync is purely semantic. Only gates
  the seed currently has *off* are offered; the parser reaches these gates only for an
  untiled, non-truncated PPS (variable-length tile geometry is out of scope), and the
  extension-present gate is unreachable once the scaling-list gate is already on (its
  variable-length body is not walked). If no off gate is reachable the mutator raises
  so the engine picks another.

### Slice-header DPB no-output mutator

- **`slice-no-output-prior-pics`** is the first mutator to target a *slice-header*
  gate rather than a parameter set, addressing the slice-side of the systematic
  bitstream walk. `no_output_of_prior_pics_flag` (H.265 §7.3.6.1) is a single bit
  present only on IRAP slices (NAL types `[16, 23]` — BLA / IDR / CRA). When an IRAP
  begins a new coded-video-sequence the flag tells the decoder whether to *discard*
  the pictures already buffered in the DPB **without outputting them**. Flipping it
  inverts that decision:
  - `0 -> 1` forces the decoder to drop a full DPB of valid, not-yet-output pictures —
    exercising the early DPB-flush path with live buffers.
  - `1 -> 0` forces the decoder to keep and attempt to output pictures whose POC and
    reference state the new sequence has invalidated — exercising the DPB
    bumping / output-reorder logic with stale entries.

  Both directions drive the same DPB output / flush machinery (the `bumping` process,
  and the derived DPB sizing set by `set_derived_values()`) that the CVE-2026-33164
  crash family runs through. The flag is fully self-contained — it is located and
  rewritten without any SPS/PPS context — and the 1-bit splice never changes the slice
  length, so every other byte of the stream is preserved exactly. The parser promotes
  the flag (previously read and discarded) to a tracked span only for IRAP slices; on
  a stream with no IRAP slice the mutator raises so the engine picks another.

### PPS slice-header extension gate mutator

- **`pps-slice-header-extension`** is the first mutator whose target lives in the
  PPS but whose dependent sub-block lives in the *slice header*, bridging the PPS
  and slice-header sides of the systematic bitstream walk.
  `slice_segment_header_extension_present_flag` (H.265 §7.3.2.1) is a single u(1)
  PPS flag that sits between `log2_parallel_merge_level_minus2` and
  `pps_extension_present_flag`. When it is 1, the spec requires *every* slice
  segment header that references this PPS to carry, near its end (H.265 §7.3.6.1):
  - `slice_segment_header_extension_length` — ue(v), range `0..256`.
  - that many `slice_segment_header_extension_data_byte` bytes — u(8) each.

  Flipping the gate `0 -> 1` in the PPS **without** the slices carrying that
  extension block makes the decoder, on entry to each slice, read a
  `slice_segment_header_extension_length` ue(v) out of whatever bits follow the
  real slice-header fields, then skip that many bytes — desynchronising the
  byte-alignment and entropy-decode entry point for the entire coded picture. A
  length read as a large value drives the decoder to skip far past the slice
  payload; decoders that do not bounds-check the skip against the NAL size read out
  of bounds. This is the same "claims data that isn't there" gate-on desync used by
  `sps-vui-hrd`, `sps-rext-flags`, `pps-extension-flags`, and `vps-timing-info`, but
  it is the only one whose desync lands in the *slice-header* parse path rather than
  in the parameter set itself.

  The parser promotes the flag (previously read and discarded) to a tracked span
  only for an untiled, non-truncated PPS whose scaling-list gate is off (a present
  `scaling_list_data()` body is not modelled). The 1-bit splice is length-preserving.
  The mutator only fires when the seed has the gate off; if the PPS did not parse to
  the gate, or the gate is already on, it raises so the engine picks another.

### PPS ref-pic-list modification gate mutator

- **`pps-lists-modification`** is the second PPS gate whose dependent sub-block
  lives in the *slice header* (after `pps-slice-header-extension`), this time landing
  the desync in the reference-picture-list reordering path.
  `lists_modification_present_flag` (H.265 §7.3.2.1) is a single u(1) PPS flag that
  sits immediately after `pps_scaling_list_data_present_flag` and just before
  `log2_parallel_merge_level_minus2`. When it is 1, the spec allows a slice segment
  header that uses inter prediction (P/B slices) to carry a
  `ref_pic_list_modification()` sub-block (H.265 §7.3.6.2): a
  `ref_pic_list_modification_flag_l0` (and, for B slices, `..._l1`) followed, when
  set, by `num_ref_idx_lX_active_minus1 + 1` entries of `list_entry_lX[i]` — each a
  `Ceil(Log2(NumPicTotalCurr))`-bit u(v) index that *reorders* the reference picture
  list.

  This is the **reachable** analogue of the slice-side ref-pic-list reorder fields
  (`num_ref_idx_active_override_flag`, `list_entry_l0`) that mangle's self-contained
  per-NAL slice parser cannot reach without SPS/PPS cross-context (it would need
  `num_extra_slice_header_bits`, `slice_type`, the slice RPS, and the active ref-idx
  counts to locate the reorder block). Rather than parse deep into the slice header,
  the mutator flips the PPS gate that *enables* that block. Flipping it `0 -> 1`
  **without** any slice actually being structured around list modification makes the
  decoder read the `ref_pic_list_modification()` syntax out of bits that hold the real
  slice-header fields, then index the reference lists with the indices it reads.
  `list_entry_lX[i]` indices that exceed `NumPicTotalCurr` are a classic out-of-bounds
  reference-list access — the same DPB / reference-management surface the
  CVE-2026-33164 derive path (`set_derived_values()`) and ffmpeg's `hevcdec.c`
  ref-list construction run through. It is the same "claims data that isn't there"
  gate-on desync as the other gate-flag mutators.

  The parser promotes the flag (previously read and discarded) to a tracked span only
  for an untiled, non-truncated PPS whose scaling-list gate is off. The 1-bit splice
  is length-preserving. The mutator only fires when the seed has the gate off; if the
  PPS did not parse to the gate, or the gate is already on, it raises so the engine
  picks another.

### Emulation-prevention byte stress mutator

- **`nal-emulation-bytes`** is the one mutator that operates on the raw on-wire
  *EBSP* bytes of a NAL rather than on a parsed field. HEVC carries NAL payloads
  as EBSP: to stop a start code (`0x000001`) appearing inside payload data, the
  encoder inserts an *emulation-prevention byte* (`0x03`) after any `0x0000` that
  would otherwise be followed by a byte in `{0x00, 0x01, 0x02, 0x03}`. Every
  conformant decoder must strip those `0x03` bytes back out before parsing, and
  that scanner is a known extreme-value attack surface — **CVE-2022-32939**
  (h26forge; iOS kernel; 0-click arbitrary write) was triggered by an HEVC NAL
  carrying an out-of-spec density of emulation-prevention bytes. One of three
  corruptions is chosen per invocation (the menu adapts to the picked NAL):
  - **Insert a phantom emulation sequence**: splices a fresh `0x00 0x00 0x03`
    triplet at a byte boundary inside the payload. A compliant decoder removes the
    `0x03` and recovers `0x0000`; a scanner that miscounts the run or fails to
    re-scan desynchronises every field after the insertion point.
  - **Drop an existing emulation-prevention byte**: removes the `0x03` from a
    genuine `0x000003` sequence, leaving the raw `0x0000` + following byte exposed
    (a `0x000001` left behind reads as a phantom start code). Decoders that do not
    re-scan after their first pass misread the now-shorter payload.
  - **Emulation-byte flood**: injects 64–300 consecutive `0x000003` triplets at
    the payload head, reproducing the high-density CVE-2022-32939 pattern that
    overran a fixed-size scratch buffer in an EBSP scanner.

  `nal-emulation-bytes` exercises the *decoder's* EBSP scanner, not mangle's: the
  bitstream assembler concatenates each NAL's bytes verbatim (it does not re-run
  emulation-prevention insertion), so the malformed encoding reaches the decoder
  exactly as written. NAL framing — the start codes between units — is preserved.

---

## How it works

1. Split the Annex-B stream into NAL units (start-code framing).
2. Strip emulation-prevention bytes to recover each NAL's RBSP.
3. Parse just far enough to locate the target field's exact bit span
   (Exp-Golomb-aware).
4. Splice a re-encoded value into that span, re-insert emulation bytes, and
   reassemble the stream.
5. Feed the mutant to the decoder under a timeout and classify the outcome.

Mutation is parameter-level and surgical — `mangle` never blindly flips random
bytes; it targets real HEVC syntax elements.

---

## Development

```bash
pip install -e ".[dev]"

# fast unit tests (no decoder required — ffmpeg is mocked)
pytest -m "not integration"

# integration tests (require a real ffmpeg on PATH)
pytest -m integration
```

---

## Ethical use

`mangle` is a **defensive security research tool**. Use it only against software
you own or are explicitly authorized to test. Responsibly disclose any decoder
bugs you find to the relevant maintainers (ffmpeg, libde265, hardware/firmware
vendors) before any public disclosure. Do **not** use `mangle` or its outputs to
attack systems you do not have permission to test, to craft malicious media for
distribution, or for any unlawful purpose. You are responsible for your use of
this tool.

---

## License

See [`LICENSE`](./LICENSE). Attributions in [`NOTICE`](./NOTICE).
