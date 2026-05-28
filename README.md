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
  the decoder return code, and the mutation detail.
- `/tmp/fuzz-out/crashes/<hash>.h265` — the mutant for any crash (segfault or
  non-zero decoder exit), alongside `<hash>.txt` containing the decoder's stderr.

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

All mutators keep the stream a parseable Annex-B bitstream while pushing it out of
semantic spec-compliance — the input class that exercises decoder edge cases.

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
  parameter-set layer. No prior mangle mutator touched the VPS at all.

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
