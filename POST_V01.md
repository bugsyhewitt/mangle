# mangle — Post-v0.1 Improvement Directions

Research lap completed: 2026-05-26. Ranked by expected security-research yield vs.
implementation cost. Items are self-contained — each can be shipped in one Phase 2
lap without disturbing the v0.1 architecture.

---

## Ranking methodology

Each item is scored on three axes (H/M/L):

- **Attack-surface coverage** — does it target a field class that has produced real
  CVEs or is theoretically high-risk?
- **Decoder breadth** — does it work across ffmpeg AND libde265 (or hit hardware
  paths)?
- **Implementation cost** — how many lines of parser + mutator code?

Items sorted by `coverage × breadth / cost`.

---

## 1. Reference Picture Set (RPS) mutator [HIGHEST PRIORITY] — ✅ IMPLEMENTED (2026-05-26)

**Status:** Shipped. `parse_sps` in `hevc.py` now advances through the conformance
window, bit-depths, DPB sizing and coding-block geometry to the RPS region,
recording `sps_max_dec_pic_buffering_minus1[i]`, `log2_max_pic_order_cnt_lsb_minus4`,
`num_short_term_ref_pic_sets`, the `st_ref_pic_set()` block, and the long-term RPS
block. Two mutators were added to `builtin.py`: `rps-overflow` (DPB index-array
overflow via `num_negative_pics`/`num_positive_pics` > `sps_max_dec_pic_buffering_minus1[0]`)
and `rps-lt-poc-ambiguity` (two long-term entries sharing one `poc_lsb_lt`, trac
#1097). Both synthesise the RPS structure when the seed declares none. Tests in
`tests/test_mutators.py` and `tests/test_hevc.py` cover the overflow invariant, the
matching-`poc_lsb_lt` invariant, and Annex-B framing integrity.

**What:** Add a mutator that corrupts the short-term and long-term RPS fields in
the SPS and/or in the slice header delta-RPS syntax. Targets include:

- `num_negative_pics` / `num_positive_pics` (ue(v)) — set above
  `sps_max_dec_pic_buffering_minus1` to overflow DPB index arrays.
- `delta_poc_s0_minus1` / `delta_poc_s1_minus1` — craft wrap-around or zero-delta
  sequences that produce duplicate POC entries.
- Long-term RPS: `poc_lsb_lt` + `delta_poc_msb_present_flag` — trigger the
  ambiguous POC LSB condition documented in HEVC trac #1097, where multiple DPB
  entries share the same LSB.

**Why now:** CVE-2026-33164 (libde265 ≥ v1.0.17, patched Feb 2026) was triggered
by a malformed PPS — but the crash path runs through `set_derived_values()`, which
depends on DPB sizing that RPS fields inform. The h26forge paper (USENIX Sec 2023)
identified RPS mutation as a key gap in the H.265 extension. JVET trac #1097 shows
even the reference decoder miscalculates long-term POC when `delta_poc_msb_cycle_lt`
is absent and current POC MSB is non-zero — a bug pattern that remains in downstream
forks.

**Implementation notes:**

- `parse_sps` in `hevc.py` already advances past `sps_seq_parameter_set_id` and
  `chroma_format_idc`; add parsing of `sps_max_dec_pic_buffering_minus1[i]` and the
  short-term/long-term RPS block (H.265 §7.3.7).
- New mutator `rps-overflow` in `builtin.py`: pick `num_negative_pics` or
  `num_positive_pics`, replace with value > `sps_max_dec_pic_buffering_minus1[0]`.
- New mutator `rps-lt-poc-ambiguity`: craft two long-term entries with the same
  `poc_lsb_lt` value.

**Estimated LOC:** ~180 (hevc.py parser extension ~90 + two mutators ~90).

---

## 2. VPS (Video Parameter Set) mutator — ✅ IMPLEMENTED (2026-05-28)

**Status:** Shipped. `parse_vps()` and the `VideoParameterSet` dataclass in
`hevc.py` parse the VPS RBSP (H.265 §7.3.2.1) through the first 16 fixed-width bits,
recording spans for `vps_max_layers_minus1` (6 bits), `vps_max_sub_layers_minus1`
(3 bits), and `vps_temporal_id_nesting_flag` (1 bit). The `vps-layer-count` mutator
in `builtin.py` picks one of three branches per invocation: push
`vps_max_layers_minus1` to 63/127 (overflowing `HEVC_MAX_LAYERS = 63`), push
`vps_max_sub_layers_minus1` to 7 (out of spec range [0, 6]), or flip
`vps_temporal_id_nesting_flag` while clamping `vps_max_sub_layers_minus1` to 0 (a
spec violation). Tests in `tests/test_vps.py` cover the parser spans, all three
mutation branches, single-NAL containment, reproducibility, and framing integrity.

**What:** Parse the VPS NAL (type 32) up to and including `vps_max_layers_minus1`
and `vps_max_sub_layers_minus1`, then mutate those fields to out-of-spec values.

Target fields:

- `vps_max_layers_minus1` — spec range [0, 62]; mutate to 63 or 127 to blow past
  `HEVC_MAX_LAYERS = 63` array bounds in decoders that use the raw value as a loop
  bound.
- `vps_max_sub_layers_minus1` — spec range [0, 6]; mutate to 7+ to overflow
  `vps_max_dec_pic_buffering_minus1[i]` arrays indexed up to this value.
- `vps_temporal_id_nesting_flag` — flip while leaving `vps_max_sub_layers_minus1`
  at 0, which is a spec violation; exercises "nesting check" code paths.

**Why now:** The TWINFUZZ paper (NDSS 2025) showed hardware acceleration stacks are
disproportionately vulnerable to spec violations in the parameter-set layer because
hardware decoders often read these fields directly into fixed-size register banks.
VPS fields feed downstream array sizes in both software and hardware decoders;
ffmpeg's `hevcdec.c` uses them to bound per-layer loops. No existing mangle mutator
touches the VPS at all.

**Implementation notes:**

- VPS parsing is simpler than SPS: fixed-width fields only (4 + 3 + 1 bits) before
  the `profile_tier_level` block, which can be skipped with the existing
  `_parse_profile_tier_level` helper.
- Add `NalUnit.VPS_NUT = 32` constant and a `parse_vps()` function to `hevc.py`.
- New mutator `vps-layer-count` in `builtin.py`.

**Estimated LOC:** ~90 (parser ~40 + mutator ~50).

---

## 3. SEI message mutators (buffering period + pic timing) — ✅ IMPLEMENTED (2026-05-28)

**Status:** Shipped. `parse_sei()` in `hevc.py` walks the SEI NAL payload framing
(H.265 §7.3.2.4) — the variable-length `payloadType` / `payloadSize` prefixes — into
a list of `SeiMessage` records. The `sei-buffering-overflow` mutator in `builtin.py`
targets the buffering-period (payloadType 0) and recovery-point (payloadType 6)
payloads, pushing HRD-timing fields to overflow values and `recovery_poc_cnt` to a
large negative se(v). Tests live in `tests/test_mutators.py` and `tests/test_hevc.py`.

**What:** Parse the SEI NAL (type 39 / 40) payload dispatch table, locate
`buffering_period` (payloadType 0) and `pic_timing` (payloadType 1) payloads, and
corrupt their fields:

- `initial_cpb_removal_delay` — ue(v); set to UINT32_MAX to trigger HRD conformance
  arithmetic overflow.
- `cpb_removal_delay_length_minus1` — referenced for `pic_timing` parsing; mismatch
  between this and the actual payload length exercises decoder length-check paths.
- `recovery_poc_cnt` in recovery-point SEI (payloadType 6) — set to a large
  negative value (se(v)) to underflow POC arithmetic.

**Why now:** CVE-2022-22675 was a missing bounds check on `cpb_count_minus1`, a
VUI/HRD field that feeds SEI parsing. JVET trac #1349 documented that the HEVC
reference model misparsed buffering-period SEI on the first IDR. SEI messages arrive
as their own NAL units and are typically processed before slice decoding — making
them a clean, early-stage attack surface with no dependency on coded picture data.
Neither mangle nor any public HEVC-specific fuzzer currently mutates SEI payloads.

**Implementation notes:**

- SEI parsing requires a payload-type dispatch loop; limit to the three payloads
  above for the first iteration.
- `payloadSize` is a multibyte prefix; a simple length-field mutator can be added
  alongside the payload-content mutator.
- New mutator `sei-hrd-timing` in `builtin.py`.

**Estimated LOC:** ~160 (parser ~80 + mutator ~80).

---

## 4. Multi-seed corpus builder (mangle corpus subcommand)

**What:** Add a `mangle corpus` CLI subcommand that generates a diverse, minimal
seed corpus from one or more input files and/or synthetic templates. Outputs N seed
files covering distinct SPS dimension classes, color formats, and NAL unit orderings.

Corpus-building strategies:
- Enumerate all combinations of {width, height} from a predefined boundary set
  (1, 2, 16, 64, 256, 4096, 65535) × {4:2:0, 4:2:2, 4:4:4} — 63 distinct
  dimension + chroma seeds.
- Generate seeds with a VPS-only NAL, SPS-only NAL, or PPS-only NAL — triggering
  incomplete-parameter-set code paths.
- Generate a seed with a non-IRAP slice before any IRAP — exercises "missing
  reference" paths.

**Why now:** Coverage-guided fuzzers (AFL++, libFuzzer) and manual campaigns both
benefit from diverse, compact seed corpora. The TWINFUZZ paper notes that mutational
fuzzers underperform grammar-based tools specifically because they lack diverse valid
seeds. FuzzWise (2025) showed that 63 well-chosen seeds outperform thousands of
random ones. Currently mangle ships only `tests/fixtures/clean.h265` as a seed — a
single point in the space.

**Implementation notes:**

- Reuse the existing bitstream assembly layer (`assemble_nal_units`) and the SPS
  splice functions.
- `corpus` is a pure subcommand with no new parser complexity; the hard part is
  constructing minimal valid SPS/PPS/slice stubs, which the existing test fixture
  generation code can inform.
- Output directory contains `<index>-<descriptor>.h265` files and a `manifest.json`.

**Estimated LOC:** ~140 (CLI ~20 + corpus generator ~120).

---

## 5. Chroma format and bit-depth SPS mutators — ✅ IMPLEMENTED (2026-05-28)

**Status:** Shipped. `parse_sps` in `hevc.py` now records `separate_colour_plane_flag`
and adds tracked spans for `bit_depth_luma_minus8` and `bit_depth_chroma_minus8`
(the two ue(v) fields that immediately follow the conformance window). Two
mutators were added to `builtin.py`: `sps-chroma-format` (rewrites
`chroma_format_idc` to the reserved value 4, or forces 4:4:4 = 3 without a
reserved `separate_colour_plane_flag` bit when the seed is not already 4:4:4) and
`sps-bit-depth` (pushes either bit-depth field past the spec ceiling of 8). Tests
in `tests/test_hevc.py` (`TestSpsChromaBitDepthParsing`) cover the new spans and a
bit-depth splice round-trip; tests in `tests/test_mutators.py`
(`TestSpsChromaFormat`, `TestSpsBitDepth`) cover both chroma branches, the
out-of-range bit-depth invariant, SPS-only containment, reproducibility, and the
clean bail when an SPS does not parse to the bit-depth region.

**What:** Extend the SPS mutator family with two new targeted mutators:

- `sps-chroma-format`: mutate `chroma_format_idc` to inconsistent values (e.g.,
  set 4:4:4 = 3 without setting `separate_colour_plane_flag`, or set it to 4 which
  is reserved/invalid) while leaving the rest of the SPS unchanged.
- `sps-bit-depth`: mutate `bit_depth_luma_minus8` / `bit_depth_chroma_minus8` (both
  ue(v), valid range [0, 8]) to values > 8 — decoders that allocate sample buffers
  based on `bit_depth + 1` bytes per sample will over-allocate or underflow.

**Why now:** CVE-2022-3266 (Firefox) was triggered by a width/height mismatch between
the container and SPS — a class of inconsistency the existing `sps-dimensions`
mutator already exercises. Bit-depth inconsistency is the analogous path for sample-
buffer sizing. Many hardware HEVC decoders handle 8-bit and 10-bit paths in separate
firmware branches; a chroma-format mismatch forces the hardware to guess or crash.
These are short mutators building directly on already-parsed SPS fields.

**Implementation notes:**

- `parse_sps` already records `chroma_format_idc` with a span; `bit_depth` fields
  follow immediately after the conformance-window block (which follows the dimensions).
- Extend `parse_sps` by ~30 lines to record bit-depth spans; then each mutator is
  ~40 lines.
- Two new registrations in `builtin.py`.

**Estimated LOC:** ~100 (parser extension ~30 + two mutators ~70).

---

## 6. Differential decoder oracle (mangle diff subcommand)

**What:** Add a `mangle diff` subcommand that runs the same mutant through two
decoders (e.g., ffmpeg and libde265) and reports whether they disagree on the
outcome (crash vs. clean, or different error messages). Disagreements are written to
a separate `divergences/` directory alongside the matching crash artifacts.

**Why now:** TWINFUZZ (NDSS 2025) showed that differential testing finds a different
class of bugs than crash-only testing — in particular, silent spec violations where
one decoder crashes and another silently corrupts output, or where both decoders
produce different but non-crash outputs (useful for device fingerprinting and
targeted exploit construction). The h26forge paper used differential output to
distinguish PoC crashes from spec-compliant behavior. Mangle already parallelizes
decoder invocations — adding a second decoder call per iteration is ~10% overhead.

**Implementation notes:**

- Extend `DecodeResult` with an optional `decoder` label field.
- Add a `run_decoder_pair()` function in `decoder.py`.
- Add `DivergenceResult` dataclass and a `divergences/` writer to `engine.py`.
- New `diff` subcommand in `cli.py` wrapping `fuzz_file` with `decoder_pair` mode.

**Estimated LOC:** ~120 (decoder.py ~40 + engine.py ~50 + cli.py ~30).

---

## 7. Coverage-instrumented harness (mangle-afl wrapper)

**What:** Add a thin `contrib/afl-harness/` directory with:
- A `harness.c` that calls `mangle mutate` via the Python C API (or a compiled C
  extension) and feeds the output to ffmpeg's `libavcodec` via the API — avoiding
  the subprocess overhead that limits AFL throughput.
- A `Makefile` and `README` describing how to build with `afl-clang-fast` and run
  `afl-fuzz` using mangle's corpus as an initial seed set.

**Why now:** mangle's current loop is I/O-bound (writes a temp file, forks ffmpeg
per iteration). AFL++'s in-process persistent mode can run 50–100× faster. Research
papers (FuzzWise, TWINFUZZ) show that grammar-guided seeds + coverage feedback
dominate blind mutation. This item bridges mangle's grammar-aware seed generation
with AFL++'s coverage feedback loop.

**Implementation notes:**

- The harness itself does not need to re-implement mutation logic — it can shell out
  to `mangle mutate --seed /dev/stdin --output /dev/stdout` in persistent mode.
- Primary deliverable is the Makefile + README + a working harness.c (~150 lines).
- No changes to the core mangle Python library.

**Estimated LOC:** ~200 (harness.c ~150 + Makefile ~30 + README ~20).

---

## 8. Crash triage and deduplication engine — ✅ IMPLEMENTED (2026-05-28)

**Status:** Shipped. New module `triage.py` plus a `mangle triage` subcommand. It
is a pure post-processing pass over a fuzz `output-dir`: it reads `results.jsonl`
(for the per-crash iteration/mutator metadata) and `crashes/<hash>.txt` (decoder
stderr) and clusters crashes by a stable signature. When the decoder was built
with ASAN/UBSAN, `signature_for()` extracts the top `frame_depth` (default 3)
stack-frame *function names* via `extract_frames()` (addresses and line numbers
are deliberately excluded so the signature is build- and input-stable). When no
sanitizer trace is present it falls back to a hash of normalised stderr (hex
addresses, integers, and `.h265`/`.hevc` paths scrubbed). The cluster key is the
triple `(signature, decoder, mutator)`; each cluster keeps its smallest mutant as
the representative (most-minimal PoC, deterministically tie-broken). Outputs
`triage.jsonl` (one cluster per line) and a `unique-crashes/` directory holding
each cluster representative's `<hash>.h265` + `<hash>.txt`. Zero changes to the
mutation/fuzzing pipeline; fully deterministic. Tests in `tests/test_triage.py`
(24 cases) cover frame extraction, both signature kinds, number-insensitive
clustering, the mutator/decoder key, representative minimisation, sort order,
clean-iteration filtering, the missing-results error, determinism, the output
schema, PoC-byte fidelity, and the CLI.

**What:** Add a `mangle triage` subcommand that reads a `results.jsonl` and the
`crashes/` directory, clusters crashes by:
1. Hash of the first 8 bytes of decoder stderr (signature clustering).
2. Stack-frame extraction if the decoder was built with ASAN/UBSAN (parse the ASAN
   output to extract the top N frames).
3. Mutation replay: re-run the exact RNG seed to confirm reproducibility.

Outputs a `triage.jsonl` with cluster IDs and a deduplicated `unique-crashes/`
directory.

**Why now:** At scale (10K+ iterations), the raw `crashes/` directory becomes
unmanageable. Bug-bounty workflows and responsible disclosure both require dedup
before submission. ASAN integration is the critical path: ffmpeg and libde265 can
both be compiled with ASAN, and their ASAN output includes the crash stack trace
that is the gold standard for dedup.

**Implementation notes:**

- Triage is a pure post-processing pass over existing output files; zero changes to
  the core mutation or fuzzing pipeline.
- Stack-frame parsing from ASAN output is regex-based (~40 lines).
- Cluster by: `(top_frame_func, second_frame_func, mutation_type)` triple.

**Estimated LOC:** ~180 (triage.py ~140 + cli.py extension ~20 + tests ~20).

---

## 9. Slice QP and transform-skip mutators — ✅ IMPLEMENTED (2026-05-28)

**Status:** Shipped. `parse_pps` in `hevc.py` now promotes the previously
read-and-discarded `init_qp_minus26` (se(v)) and `transform_skip_enabled_flag`
(u(1)) to tracked spans — both sit before the tile-config flags, so they are
reachable for any PPS that parses. One mutator, `pps-slice-qp`, was added to
`builtin.py`; it picks one of two branches per invocation: push `init_qp_minus26`
to ±52/±64 (out of the spec range [-26, 25]) via the existing `splice_se_field`
helper, or flip `transform_skip_enabled_flag`. Tests in `tests/test_hevc.py`
(`TestPpsQpParsing`) cover the new spans, signed/unsigned round-trips, and
tail-preservation across an se(v) length-shift; tests in `tests/test_mutators.py`
(`TestPpsSliceQpMutator`) cover both branches, the out-of-range invariant, the
flag flip, PPS-only containment, reproducibility, and Annex-B framing integrity.

**What:** Parse deeper into the PPS to reach:
- `init_qp_minus26` (se(v)) — mutate to ±52 (spec range is [-26, 25]); decoders
  that clamp this incorrectly produce out-of-range quantization steps.
- `transform_skip_enabled_flag` — flip to 1 without providing
  `transform_skip_rotation_enabled_flag` in the SPS range extension; inconsistency
  exercises range-extension handling paths.
- `pic_init_qp_minus26` is already adjacent to `pps_tile_config` in the current
  parse path; the PPS parser in `hevc.py` currently reads and discards it — promote
  it to a tracked span.

**Why now:** QP-related mutations are historically productive for integer overflow
bugs: many decoders pre-allocate quantization coefficient arrays sized by
`maxQP - minQP + 1`, and an out-of-range `init_qp` can produce a zero or negative
allocation size. The parser already reaches this region of the PPS; extending
coverage requires ~30 additional lines.

**Estimated LOC:** ~80 (parser extension ~30 + two mutators ~50).

---

## 10. Emulation-prevention byte stress mutator — ✅ IMPLEMENTED (2026-05-28)

**Status:** Shipped. A new `nal-emulation-bytes` mutator was added to `builtin.py`.
Unlike every other mangle mutator it operates on the raw on-wire EBSP bytes of a
chosen NAL rather than on a parsed field — `assemble_nal_units` concatenates each
NAL's `ebsp` verbatim (it does not re-run `rbsp_to_ebsp`), so a deliberately
malformed EBSP reaches the decoder exactly as written, exercising the decoder's
emulation-prevention scanner rather than mangle's. A helper
`_find_emulation_byte_offsets` locates genuine emulation-prevention bytes (mirroring
the `ebsp_to_rbsp` rule). The mutator picks one of three corruptions per invocation,
adapting the menu to the chosen NAL: **insert** a phantom `0x000003` triplet at a
payload byte boundary; **drop** a real emulation-prevention byte (exposing raw
`0x0000` + following byte, which can leave a phantom `0x000001` start code); or
**flood** the payload head with 64–300 consecutive `0x000003` triplets, reproducing
the CVE-2022-32939 high-density pattern. The 2-byte NAL header and all NAL framing
(start codes) are always preserved. Tests in `tests/test_mutators.py`
(`TestNalEmulationBytesMutator`, 11 cases) cover registration, reproducibility,
framing integrity, single-NAL containment, each of the three branches, full branch
reachability, and the no-existing-emulation-byte skip-drop invariant.

**What:** A dedicated `nal-emulation-bytes` mutator that deliberately inserts or
removes RBSP emulation-prevention bytes (0x000003 sequences) at the bitstream level
(bypassing the normal parse-and-splice flow) to exercise EBSP-to-RBSP conversion
bugs in decoders.

Specific patterns:
- Insert a legitimate 0x000003 sequence at a byte boundary that would create a
  phantom emulation-prevention byte when re-read.
- Remove an existing emulation-prevention byte so the 0x000002 pattern is exposed
  raw — decoders that do not re-scan after removal will misparse the stream.

**Why now:** CVE-2022-32939 (h26forge, iOS kernel, arbitrary write, 0-click) was
directly triggered by an HEVC bitstream with >256 emulation-prevention bytes in a
single NAL — showing that EBSP processing is an extreme-value attack surface. Mangle
currently uses `rbsp_to_ebsp` correctly for all mutations; this mutator deliberately
introduces *incorrect* EBSP to exercise the decoder's EBSP scanner, not mangle's.

**Implementation notes:**

- Operates at raw byte level on the assembled Annex-B stream rather than on the RBSP;
  requires a scan for 0x000000 / 0x000001 / 0x000002 / 0x000003 sequences.
- No parser extension needed — pure byte-level splice.
- New mutator class that bypasses the NAL-parse flow and operates post-assembly.

**Estimated LOC:** ~70.

---

## 11. PPS deblocking / loop-filter mutator — ✅ IMPLEMENTED (2026-05-28)

**Status:** Shipped. `parse_pps` in `hevc.py` now advances past the (untiled)
entropy/loop-filter flags into the deblocking-filter control region
(H.265 §7.3.2.3), recording spans for `pps_loop_filter_across_slices_enabled_flag`,
`deblocking_filter_control_present_flag`, `deblocking_filter_override_enabled_flag`,
`pps_deblocking_filter_disabled_flag`, `pps_beta_offset_div2`, and
`pps_tc_offset_div2`. A `splice_se_field` helper was added for re-encoding the se(v)
offsets in place. One mutator, `pps-deblocking`, was added to `builtin.py`; it picks
from the branches the seed PPS actually exposes — out-of-range beta/tc offset
(spec range [-6, 6] → ±32/±64), disable-flag flip, or loop-filter-scope flip —
raising cleanly on tiled PPSes so the engine can choose another mutator. Tests in
`tests/test_hevc.py` (`TestPpsDeblockingParsing`) and `tests/test_mutators.py`
(`TestPpsDeblockingMutator`) cover each parse branch, the out-of-range offset
invariant, reproducibility, framing integrity, and PPS-only-NAL containment.

**What:** Corrupt the PPS deblocking-filter control fields, addressing gap-analysis
item #9 ("Deblocking filter parameters in PPS/slice header"). Targets:

- `pps_beta_offset_div2` / `pps_tc_offset_div2` (se(v), spec range [-6, 6]) — set
  far out of range to push filter-strength table lookups past their bounds.
- `pps_deblocking_filter_disabled_flag` — flip to create an inconsistency between
  the claimed filter state and the offsets that follow.
- `pps_loop_filter_across_slices_enabled_flag` — flip to exercise the slice-
  boundary loop-filter path (reachable in any untiled PPS; conservative fallback).

**Why now:** CVE-2026-33164 (libde265 <1.0.17) crashes in `set_derived_values()`
on a malformed PPS — the deblocking control fields sit in that same derive path.
The deblocking region was an untouched PPS attack surface; the existing PPS parser
already reached the tile-config flags just before it, so the extension was low-cost.

**Estimated LOC:** ~110 (parser extension ~95 + splice_se_field ~15 + mutator ~85).

---

## 12. Slice-header DPB no-output mutator — ✅ IMPLEMENTED (2026-05-29)

**Status:** Shipped. This is the first mutator to target a *slice-header* gate
rather than a parameter set, opening the slice-side of the systematic bitstream
walk. `parse_slice_header` in `hevc.py` now promotes the previously
read-and-discarded `no_output_of_prior_pics_flag` (H.265 §7.3.6.1) to a tracked
single-bit span — but only for IRAP NAL types [16, 23], the only slices that carry
it; for non-IRAP slices the field is absent and the attribute is left `None`. One
mutator, `slice-no-output-prior-pics`, was added to `builtin.py`; it locates the
first IRAP VCL slice and flips the flag, inverting the decoder's decision to discard
the DPB without outputting its pictures when a new coded-video-sequence begins. It
raises `ValueError` on streams with no IRAP slice so the engine selects another
mutator. Tests in `tests/test_hevc.py` (`TestSliceNoOutputPriorPicsParsing`, 6
cases) cover the IRAP span, its position between the first-slice flag and the PPS id,
the non-IRAP absence, a synthetic-value round-trip, the length-preserving splice, and
the full IRAP NAL-type range; tests in `tests/test_mutators.py`
(`TestSliceNoOutputPriorPicsRegistered` + `TestSliceNoOutputPriorPicsMutator`, 11
cases) cover registration, reproducibility, the flag flip, length preservation,
IRAP-only containment, framing integrity, double-application idempotence, and the
no-IRAP-slice raise.

**What:** Flip `no_output_of_prior_pics_flag` in an IRAP slice header. The flag
controls whether the decoder discards the pictures already buffered in the DPB
*without outputting them* when the IRAP begins a new coded-video-sequence:

- `0 -> 1` forces the decoder to drop a full DPB of valid, not-yet-output pictures —
  exercising the early DPB-flush path with live buffers.
- `1 -> 0` forces the decoder to keep and attempt to output pictures whose POC and
  reference state the new sequence has invalidated — exercising the DPB
  bumping / output-reorder logic with stale entries.

**Why now:** Both directions drive the same DPB output / flush machinery (the
`bumping` process and the derived DPB sizing from `set_derived_values()`) that the
CVE-2026-33164 crash family runs through. The flag is fully self-contained — located
and rewritten with no SPS/PPS context — making it the cleanest first slice-header
gate target. It is the slice-header complement to the parameter-set gate mutators
(`sps-vui-hrd`, `sps-rext-flags`, `pps-extension-flags`).

**Implementation notes:**

- `parse_slice_header` already read `no_output_of_prior_pics_flag` and discarded it;
  promoting it to a span is ~6 lines plus the dataclass field.
- The mutator is a 1-bit `splice_fixed_bits` on the located span (length-preserving).
- A `_first_irap_vcl` helper locates the first IRAP slice; the mutator raises when
  none exists.

**Estimated LOC:** ~75 (parser extension ~12 + mutator ~50 + helper ~10).

---

## 13. VPS timing-info gate mutator — ✅ IMPLEMENTED (2026-05-29)

**Status:** Shipped. `parse_vps()` in `hevc.py` now has a second stage that walks
past the fixed 16-bit header, `vps_reserved_0xffff_16bits`, `profile_tier_level`
(via the existing `_parse_profile_tier_level` helper), the sub-layer DPB-ordering
loop and the layer-set inclusion loop to record the `vps_timing_info_present_flag`
gate (H.265 §7.3.2.1) as a tracked single-bit span. For multi-layer /
multi-sub-layer geometry the parser does not model, or a truncated VPS, the second
stage bails cleanly and the attribute is left `None` (the layer/sublayer view of
`vps-layer-count` still stands). One mutator, `vps-timing-info`, was added to
`builtin.py`; it flips the gate off→on without supplying the dependent
`vps_timing_info` sub-block (`vps_num_units_in_tick` u(32), `vps_time_scale`
u(32), `vps_poc_proportional_to_timing_flag`, optional
`vps_num_ticks_poc_diff_one_minus1` ue(v), and the `vps_num_hrd_parameters` ue(v)
`hrd_parameters()` loop), forcing the decoder to read 64+ bits of timing fields
and an HRD walk out of the VPS trailing bits. It raises when the VPS did not parse
to the gate or the gate is already on, so the engine picks another. Tests in
`tests/test_vps.py` (`TestVpsTimingInfoParsing` + `TestVpsTimingInfoRegistered` +
`TestVpsTimingInfoNoVps` + `TestVpsTimingInfoMutation`, 16 cases) cover the gate
span, its position past the header, the truncated-VPS `None` path, the
length-preserving splice round-trip, registration, the no-VPS raise, the gate
flip, single-NAL containment, reproducibility, framing integrity, and the
already-on double-application raise.

**What:** Flip `vps_timing_info_present_flag` (H.265 §7.3.2.1) on without
supplying the variable-length `vps_timing_info` / `hrd_parameters()` body it
gates. This is the VPS analogue of the SPS `sps-vui-hrd` / `sps-rext-flags`
gate-inconsistency mutators and the VPS complement to `vps-layer-count` (which
touches only the fixed layer/sublayer counts, not a gated sub-block).

**Why now:** HRD timing arithmetic (`num_units_in_tick`, CPB removal delays) is
the field class behind CVE-2022-22675, and the VPS timing block is an entirely
untouched attack surface — no prior mangle mutator reached past the VPS header.
The clean, fully-modellable walk to the gate (the seed's single-layer geometry
makes the DPB-ordering and layer-set loops trivially bounded) makes it the natural
next VPS extension gate after `vps-layer-count`.

**Implementation notes:**

- `parse_vps` second stage reuses `_parse_profile_tier_level`; the DPB-ordering
  and layer-set loops are bounded by already-parsed `vps_max_sub_layers_minus1`,
  `vps_max_layer_id`, and `vps_num_layer_sets_minus1`, so the walk is exact for
  the single-layer seed and any conformant single-layer stream.
- The mutator is a 1-bit `splice_fixed_bits` on the located gate span
  (length-preserving).

**Estimated LOC:** ~90 (parser extension ~40 + mutator ~50).

---

## 14. PPS slice-header extension gate mutator — ✅ IMPLEMENTED (2026-05-29)

**Status:** Shipped. `parse_pps` in `hevc.py` now promotes the previously
read-and-discarded `slice_segment_header_extension_present_flag` (H.265 §7.3.2.1)
to a tracked single-bit span. It sits in the PPS third stage between
`log2_parallel_merge_level_minus2` and `pps_extension_present_flag`, reached for
any untiled, non-truncated PPS whose scaling-list gate is off (the same walk the
`pps-extension-flags` gates use). One mutator, `pps-slice-header-extension`, was
added to `builtin.py`; it flips the gate off→on in the PPS without the slices
carrying the dependent extension block, so every slice header that references the
PPS must read a `slice_segment_header_extension_length` ue(v) plus that many
extension data bytes (H.265 §7.3.6.1) out of bits that hold the real slice-header
fields. The length read out of unrelated bits drives the decoder to skip past the
slice payload — an out-of-bounds read on decoders that do not bound the skip
against the NAL size. It raises when the PPS did not parse to the gate or the gate
is already on, so the engine picks another. Tests in `tests/test_hevc.py`
(`TestPpsSliceHeaderExtensionGateParsing`, 7 cases) cover the seed span, its
single-bit width, its position between the scaling-list and extension gates, the
recorded-when-on case, the scaling-list-on and tiles-on skip cases, and the
length-preserving splice round-trip (asserting the neighbouring extension gate is
untouched); tests in `tests/test_mutators.py`
(`TestPpsSliceHeaderExtensionRegistered` + `TestPpsSliceHeaderExtensionMutator`,
13 cases) cover registration, reproducibility, the gate flip, the detail string,
PPS-only containment, length preservation, the neighbouring-gate-untouched
invariant, framing integrity, double-application raise, the gate-already-on raise,
and the tiled-PPS raise.

**What:** Flip `slice_segment_header_extension_present_flag` (H.265 §7.3.2.1) on in
the PPS without the slices carrying the per-slice-header extension block it gates.
This is the first mutator whose target field is in the PPS but whose dependent
sub-block is in the *slice header*, bridging the two sides of the systematic walk.

**Why now:** It is the natural next gate in the PPS third-stage walk — the parser
already reached and discarded it just before `pps_extension_present_flag` — and it
is the only PPS gate whose desync lands in the slice-header parse path. The
slice-header extension mechanism is an untouched attack surface; a
`slice_segment_header_extension_length` read out of unrelated bits exercises the
slice-skip / NAL-bound check that several decoders implement without a guard.

**Implementation notes:**

- `parse_pps` third stage already read `slice_segment_header_extension_present_flag`
  and discarded it; promoting it to a span is ~10 lines plus the dataclass field.
- The mutator is a 1-bit `splice_fixed_bits` on the located gate span
  (length-preserving), matching the established gate-flag mutators.

**Estimated LOC:** ~80 (parser extension ~12 + mutator ~55 + dataclass field).

---

## 15. PPS ref-pic-list modification gate mutator — ✅ IMPLEMENTED (2026-05-29)

**Status:** Shipped. `parse_pps` in `hevc.py` now promotes the previously
read-and-discarded `lists_modification_present_flag` (H.265 §7.3.2.1) to a tracked
single-bit span. It sits in the PPS third stage immediately after
`pps_scaling_list_data_present_flag` and just before
`log2_parallel_merge_level_minus2` — reached for any untiled, non-truncated PPS
whose scaling-list gate is off (the same walk `pps-slice-header-extension` and the
`pps-extension-flags` gates use). One mutator, `pps-lists-modification`, was added
to `builtin.py`; it flips the gate off→on in the PPS without any slice actually
being structured around list modification, so the decoder must read a
`ref_pic_list_modification()` sub-block (H.265 §7.3.6.2) — `list_entry_l0[]` /
`list_entry_l1[]` reorder indices, each a `Ceil(Log2(NumPicTotalCurr))`-bit u(v) —
out of bits that hold the real inter slice-header fields, then index the reference
picture lists with the values it reads. `list_entry_lX[i]` indices that exceed
`NumPicTotalCurr` are a classic out-of-bounds reference-list access. It raises when
the PPS did not parse to the gate or the gate is already on, so the engine picks
another. Tests in `tests/test_hevc.py` (`TestPpsListsModificationGateParsing`, 8
cases) cover the seed span, its single-bit width, its position between the
scaling-list and slice-header-extension gates, the recorded-when-on case, the
scaling-list-on and tiles-on skip cases, and the length-preserving splice round-trip
(asserting the neighbouring slice-header gate is untouched); tests in
`tests/test_mutators.py` (`TestPpsListsModificationRegistered` +
`TestPpsListsModificationMutator`, 13 cases) cover registration, reproducibility,
the gate flip, the detail string, PPS-only containment, length preservation, the
neighbouring-gate-untouched invariant, framing integrity, double-application raise,
the gate-already-on raise, the scaling-list-on raise, and the tiled-PPS raise.

**What:** Flip `lists_modification_present_flag` (H.265 §7.3.2.1) on in the PPS
without any slice carrying the per-slice-header `ref_pic_list_modification()`
sub-block it gates. It is the second PPS gate whose dependent sub-block is in the
*slice header* (after `slice_segment_header_extension_present_flag`), landing the
desync in the reference-picture-list reordering path.

**Why now:** The suggested next slice candidates from R17 — `slice_pic_order_cnt_lsb`
and `num_ref_idx_active_override_flag` — are **not reachable** with mangle's
self-contained per-NAL slice parser: both sit past `slice_pic_parameter_set_id`
(where `parse_slice_header` deliberately stops) and require SPS/PPS cross-context
(`num_extra_slice_header_bits`, `slice_type`, `separate_colour_plane_flag`, the
`log2_max_pic_order_cnt_lsb` width, the slice RPS) to even locate. `pps-lists-
modification` is the *reachable* analogue: it flips the PPS gate that *enables* the
slice-header ref-pic-list reorder block rather than parsing into the slice header to
reach the reorder fields. It is the natural next gate in the PPS third-stage walk —
the parser already reached and discarded it, sitting between the two gates already
covered by `pps-extension-flags` and `pps-slice-header-extension`.

**Implementation notes:**

- `parse_pps` third stage already read `lists_modification_present_flag` and
  discarded it; promoting it to a span is ~6 lines plus the dataclass field.
- The mutator is a 1-bit `splice_fixed_bits` on the located gate span
  (length-preserving), matching the established gate-flag mutators.

**Estimated LOC:** ~75 (parser extension ~8 + mutator ~60 + dataclass field).

---

## Summary table

| # | Name | Attack surface | New CVE class | Cost (LOC) | Priority |
|---|---|---|---|---|---|
| 1 | rps-overflow / rps-lt-poc-ambiguity | RPS / DPB sizing | DPB OOB write | ~180 | ✅ DONE |
| 2 | vps-layer-count | VPS layer/sublayer arrays | Array index OOB | ~90 | ✅ DONE |
| 3 | sei-buffering-overflow | SEI HRD / timing payloads | Integer overflow | ~160 | ✅ DONE |
| 4 | corpus builder | Seed diversity | Coverage breadth | ~140 | ✅ DONE |
| 5 | sps-chroma-format / sps-bit-depth | Sample buffer sizing | Buffer underflow | ~100 | ✅ DONE |
| 6 | Differential oracle | Cross-decoder divergence | Silent corruption | ~120 | MEDIUM |
| 7 | AFL harness | Coverage feedback | Throughput | ~200 | MEDIUM |
| 8 | Crash triage | Dedup / disclosure | Operational | ~180 | ✅ DONE |
| 9 | pps-slice-qp | QP arithmetic / transform-skip | Integer overflow | ~80 | ✅ DONE |
| 10 | nal-emulation-bytes | EBSP scanning | Parse confusion | ~70 | ✅ DONE |
| 11 | pps-deblocking | PPS deblocking/loop-filter | OOB table lookup | ~110 | ✅ DONE |
| 12 | slice-no-output-prior-pics | Slice-header DPB no-output | DPB flush/output desync | ~75 | ✅ DONE |
| 13 | vps-timing-info | VPS timing / HRD gate | HRD-timing desync | ~90 | ✅ DONE |
| 14 | pps-slice-header-extension | PPS→slice-header extension gate | Slice-header skip OOB read | ~80 | ✅ DONE |
| 15 | pps-lists-modification | PPS→slice-header ref-pic-list reorder gate | Ref-list index OOB read | ~75 | ✅ DONE |

---

## Research notes

### Active CVE landscape (as of 2026-05-26)

- **CVE-2025-61147** (libde265): segfault in `compute_framedrop_table()` via crafted
  HEVC file; fixed post-commit d9fea9d. Root: missing metadata check during frame-
  drop logic.
- **CVE-2026-33164** (libde265 <1.0.17): PPS `set_derived_values()` crash on
  malformed PPS. Directly related to item #3 and #9 above.
- **CVE-2026-33165** (libde265 <1.0.18): out-of-bounds heap write.
- **FFmpeg** saw 26 CVEs in 2025; HEVC-specific paths in `hevcdec.c` (duplicate
  first-slice handling, NULL pointer dereference) remain active.

### Key papers

- **h26forge** (USENIX Security 2023 / 2024): structured H.264/H.265 bitstream
  generation; found CVE-2022-42850 (Apple iOS H.265 heap overflow) and
  CVE-2022-32939 (>256 emulation-prevention bytes → arbitrary iOS kernel write).
  Explicitly called out H.265 as understudied.
- **TWINFUZZ** (NDSS 2025, Leonelli et al., CISPA): differential testing of hardware
  video acceleration stacks; found bugs in Firefox, VLC, and four hardware
  acceleration frameworks. Showed grammar-aware seeds + coverage feedback dominate.
  Recommends Nautilus (grammar-based AFL++) as the natural counterpart to generative
  tools.

### Gap analysis: what mangle v0.1 does NOT cover

The four v0.1 mutators touch SPS dimensions, PPS tile flags, slice header PPS ID /
first-slice flag, and NAL type swaps. The following high-value HEVC syntax regions
are entirely untouched:

1. VPS (all fields) — ✅ layer/sublayer/nesting gates covered by `vps-layer-count`
   (item #2); the `vps_timing_info_present_flag` gate (and the variable-length
   `vps_timing_info` / `hrd_parameters()` sub-block it guards) is now covered by
   `vps-timing-info` (item #13). `parse_vps` walks past `profile_tier_level`, the
   sub-layer DPB-ordering loop and the layer-set inclusion loop to the timing gate;
   the mutator flips it off→on without supplying the dependent timing/HRD body. The
   `vps_extension_flag` tail and the timing/HRD sub-block bodies themselves are
   still not synthesised.
2. RPS block in SPS and slice header — ✅ SPS short-term/long-term RPS covered by
   `rps-overflow` / `rps-lt-poc-ambiguity` (item #1); the slice-header delta-RPS
   syntax is not yet modelled.
3. SEI NAL units (any payload type) — ✅ buffering-period / recovery-point payloads
   covered by `sei-buffering-overflow` (item #3)
4. Bit depth and chroma format SPS fields — ✅ covered (item #5)
5. QP fields in PPS — ✅ covered (item #9)
6. EMSP / EBSP byte-level malformation — ✅ covered (item #10)
7. HRD parameters in VUI — ✅ covered. `parse_sps` now walks past the RPS region
   and the two trailing feature flags into the SPS `vui_parameters()` block
   (H.265 §E.2.1), recording the three nested gate flags
   `vui_parameters_present_flag`, `vui_timing_info_present_flag`, and
   `vui_hrd_parameters_present_flag`. The `sps-vui-hrd` mutator flips one off-gate
   on without supplying the sub-block it gates (preferring the HRD gate), forcing
   the decoder to read CPB/HRD fields out of unrelated downstream bits. The
   variable-length `hrd_parameters()` body itself is still not synthesised.
8. Scaling lists (SPS/PPS) — ✅ SPS `scaling_list_enabled_flag` (and
   `pcm_enabled_flag`) inconsistency covered by the `sps-feature-flags` mutator;
   the PPS `pps_scaling_list_data_present_flag` gate is now covered by the
   `pps-extension-flags` mutator (`parse_pps` walks past the deblocking region into
   the PPS extension gate region, H.265 §7.3.2.1, recording the scaling-list gate;
   the mutator flips it off→on without supplying the dependent `scaling_list_data()`
   body, forcing the decoder to read scaling-list coefficients out of the PPS
   trailing bits). The variable-length `scaling_list_data()` body itself is still
   not synthesised.
9. Deblocking filter parameters in PPS/slice header — ✅ PPS portion covered (item #11)
10. HEVC range extensions (RExt) flags — ✅ covered. `parse_sps` now walks *past*
    the VUI block (immediately when VUI is absent, or via the VUI tail's
    `bitstream_restriction_flag` block when VUI is present without an HRD sub-block)
    into the SPS profile-extension region (H.265 §7.3.2.2.1), recording
    `sps_extension_present_flag` and `sps_range_extension_flag`. The `sps-rext-flags`
    mutator flips one off-gate on (preferring `sps_range_extension_flag`) without
    supplying the dependent `sps_range_extension()` body, forcing the decoder onto its
    Range-Extension coefficient-coding path with no valid extension parameter set. The
    variable-length `sps_range_extension()` body (nine RExt feature bits) and the
    HRD-present walk-through are still not synthesised. The PPS analogue —
    `pps_extension_present_flag` (H.265 §7.3.2.1) — is now also covered by the
    `pps-extension-flags` mutator, which flips the PPS extension gate off→on without
    supplying the four PPS profile-extension flags / `pps_extension_4bits` / extension
    bodies they gate. The PPS extension bodies themselves are not synthesised.
11. Slice-header gate flags — ✅ first slice-header gate covered. `parse_slice_header`
    now promotes `no_output_of_prior_pics_flag` (H.265 §7.3.6.1) to a tracked span for
    IRAP NAL types [16, 23]; the `slice-no-output-prior-pics` mutator flips it,
    inverting the IRAP DPB no-output decision (item #12). The PPS-side gate that
    controls *all* slice headers — `slice_segment_header_extension_present_flag`
    (H.265 §7.3.2.1) — is now also covered by the `pps-slice-header-extension`
    mutator (item #14): `parse_pps` promotes the gate (previously read and
    discarded) to a tracked span and the mutator flips it off→on without the slices
    carrying the dependent extension block, desyncing every slice header's
    `slice_segment_header_extension_length` read. The PPS-side gate that controls the
    slice-header *ref-pic-list reordering* path — `lists_modification_present_flag`
    (H.265 §7.3.2.1) — is now also covered by the `pps-lists-modification` mutator
    (item #15): the parser promotes that gate (also previously read and discarded) to
    a tracked span and the mutator flips it off→on without any slice carrying
    `ref_pic_list_modification()`, desyncing every inter slice header's
    `list_entry_lX` reorder-index read. This is the reachable analogue of the
    R17-suggested slice candidates `slice_pic_order_cnt_lsb` /
    `num_ref_idx_active_override_flag`, which are **not reachable** with the
    self-contained per-NAL slice parser (they sit past `slice_pic_parameter_set_id`,
    where `parse_slice_header` stops, and need SPS/PPS cross-context to locate). The
    deeper slice-header fields that need SPS/PPS context (`slice_segment_address`,
    the slice-level RPS, `dependent_slice_segment_flag`, `slice_pic_order_cnt_lsb`,
    `num_ref_idx_active_override_flag`) remain unmodelled.

Items 1–6 above correspond directly to items 1–10 in the ranked list.
