# mangle ↔ AFL++ harness

This directory bridges mangle's grammar-aware HEVC mutators into
[AFL++](https://aflplus.plus/)'s coverage-guided fuzzing loop.

It is the answer to the question *"can mangle do coverage-guided fuzzing?"*:
**not from inside Python — but it can drive AFL++**, which provides the edge-
coverage feedback loop that Python-level black-box fuzzers cannot. See
`POST_V01.md` item #7 and the design notes in `src/mangle/scheduler.py` and
`src/mangle/coverage.py` for the architectural background.

The split of responsibilities:

| Layer | Provided by | What it does |
|---|---|---|
| Edge-coverage feedback loop | AFL++ (`afl-fuzz`) | Tracks which decoder edges each input hit, biases the corpus toward inputs that find new edges. |
| Grammar-aware mutators | `mangle` | 30+ HEVC-syntax mutators that target SPS/PPS/VPS/slice-header gates. |
| Glue | this directory | A `harness.c` for AFL++ persistent-mode + a `mangle afl-mutate` CLI wrapper. |

Two integration paths are supported.

---

## Path 1 — Custom-mutator pre-processing (no harness build required)

The simplest integration. Use `mangle afl-mutate` as a one-shot
pre-processing step on each AFL++ input.

```bash
# 1. Build a diverse seed corpus from a clean HEVC sample.
mangle corpus \
    --seed clean.h265 \
    --output-dir seeds-mangle/

# 2. Trim it to one seed per decode behaviour against the decoder under test.
mangle corpus-trim \
    --input-dir seeds-mangle/ \
    --output-dir seeds-trimmed/ \
    --decoder ffmpeg

# 3. Run afl-fuzz on the trimmed corpus against the ffmpeg HEVC decoder.
afl-fuzz \
    -i seeds-trimmed/ \
    -o afl-out/ \
    -- ffmpeg -v error -i @@ -f null -
```

AFL++ supplies the coverage-guided mutation; mangle supplies the *initial
corpus diversity* — a seeded campaign that already covers VPS/SPS/PPS/slice
boundaries and incomplete parameter sets is far more productive than AFL++'s
default bit-flip starting point. The TWINFUZZ paper (NDSS 2025) and FuzzWise
(2025) both report that grammar-aware seeds are the single largest leverage
point for mutational fuzzers.

This path requires no harness build, no `afl-clang-fast`, and no patching of
the decoder. It is the recommended starting point.

---

## Path 2 — Persistent-mode harness (in-process, ~50× throughput)

For sustained campaigns, the subprocess overhead of running `ffmpeg` per
AFL++ iteration is the bottleneck. AFL++'s persistent-mode harness amortises
the fork cost by running many iterations inside one process.

The `harness.c` in this directory is a minimal persistent-mode driver. The
critical design choice: **the harness itself does not re-implement mutation
logic**. It calls `mangle afl-mutate` as a subprocess (or a co-process pipe)
in the inner loop. This keeps the mutation logic in one place (Python) and
the harness focused on the parts that need to be C: the AFL++ fork-server
protocol, the coverage map, and the in-process decoder API call.

### Build

```bash
make CC=afl-clang-fast
```

You will need:

- `afl-clang-fast` from a recent AFL++ build (`make source-only` in the
  AFL++ tree).
- `mangle` installed and on `$PATH` (typically `pip install -e .` in the
  mangle source tree, with the resulting venv activated).
- An HEVC decoder you want to fuzz. The default harness shells out to
  `ffmpeg`; the `DECODER` Makefile variable lets you swap it.

### Run

```bash
AFL_AUTORESUME=1 afl-fuzz \
    -i ../../seeds-trimmed/ \
    -o afl-out/ \
    -- ./mangle-afl-harness @@
```

Inside the inner loop the harness reads the AFL-supplied candidate file,
pipes it through `mangle afl-mutate`, and feeds the mutant to the decoder.
The decoder's edge-coverage map is what AFL++ scores; mangle's mutation
output is what drives the input distribution toward HEVC-valid syntax.

### Caveats

- The harness in this directory is a **reference template**, not a
  production fuzzer. It is documented to ~150 lines so it is easy to read
  and adapt; a real persistent-mode harness against `libavcodec`'s C API
  (rather than the `ffmpeg` CLI) would shave another order of magnitude off
  per-iteration cost.
- `afl-clang-fast` builds and runs are not covered by this repo's CI — the
  Python tests in `tests/test_afl.py` cover the `mangle afl-mutate` CLI and
  the structure / `make -n` of this directory; live AFL++ runs require local
  installation.
- The fork-server interface and the `__AFL_LOOP` macro are AFL++ specifics;
  the harness here will compile under plain `gcc` (a no-op single-iteration
  binary), useful for verifying the build chain before involving AFL++.

---

## What gets tested

The Python wrapper (`mangle afl-mutate`) is fully covered by
`tests/test_afl.py`:

- Pure-function `mutate_stream` round-trip.
- The CLI subcommand reads `--seed`, writes byte-clean stdout, all other
  output to stderr.
- Unknown mutator name fails cleanly with the available list.
- Same `(seed, mutator, --seed-rng)` produces byte-identical output (the
  reproducibility contract every other mangle subcommand honours).

The contrib artifacts are covered by structural tests:

- `harness.c`, `Makefile`, `README.md` exist.
- `make -n` parses cleanly against this directory's `Makefile` (catches
  typos without requiring `afl-clang-fast`).

Live AFL++ campaign throughput is not measured in CI; that is a separate
operational benchmark.

---

## References

- AFL++ docs: https://aflplus.plus/docs/
- AFL++ custom-mutator API:
  https://github.com/AFLplusplus/AFLplusplus/blob/stable/docs/custom_mutators.md
- AFL++ persistent mode:
  https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.persistent_mode.md
- TWINFUZZ (NDSS 2025), Leonelli et al. — grammar-aware seeds + coverage
  feedback for video decoders.
- FuzzWise (2025) — seed-corpus quality dominates throughput for mutational
  fuzzers.
