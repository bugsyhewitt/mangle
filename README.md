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
