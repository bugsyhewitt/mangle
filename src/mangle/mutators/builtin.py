"""The four v0.1 built-in mutators.

Each mutator locates a real field in the bitstream and rewrites it to a value
that keeps the stream syntactically parseable but pushes it out of semantic
spec-compliance — exactly the class of input that exercises decoder edge cases.

[Worker decision: targeted-splice mutation strategy]
We mutate by locating a specific field's bit span (via the minimal parsers in
hevc.py) and splicing a re-encoded value in place, rather than fully re-encoding
the parameter set. This is robust against the parts of the syntax we do not
model, and it is exactly how structured codec fuzzers like h26forge operate.
"""

from __future__ import annotations

import random

from ..bitstream import (
    NalUnit,
    assemble_nal_units,
    ebsp_to_rbsp,
    rbsp_to_ebsp,
    split_nal_units,
)
from ..hevc import (
    ShortTermRps,
    parse_pps,
    parse_sei,
    parse_slice_header,
    parse_sps,
    parse_vps,
    splice_fixed_bits,
    splice_replace_region,
    splice_se_field,
    splice_ue_field,
)
from .registry import MutationResult, count_changed_bytes, register


def _clone(nals: list[NalUnit]) -> list[NalUnit]:
    return [NalUnit(n.start_code_len, n.offset, n.ebsp) for n in nals]


def _first(nals: list[NalUnit], nal_type: int) -> int:
    for i, n in enumerate(nals):
        if n.nal_unit_type == nal_type:
            return i
    raise ValueError(f"no NAL of type {nal_type} found in stream")


def _first_vcl(nals: list[NalUnit]) -> int:
    for i, n in enumerate(nals):
        if n.is_vcl:
            return i
    raise ValueError("no VCL (slice) NAL found in stream")


def _rewrite_payload(nal: NalUnit, new_rbsp: bytes) -> NalUnit:
    """Rebuild a NAL from a new RBSP payload, keeping its 2-byte header."""
    header = nal.ebsp[:2]
    new_ebsp = header + rbsp_to_ebsp(new_rbsp)
    return NalUnit(nal.start_code_len, nal.offset, new_ebsp)


@register("sps-dimensions")
def sps_dimensions(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Mutate the SPS picture width/height to spec-inconsistent values.

    Picks one of width/height and rewrites it to an odd, mismatched, or
    over-large value. The stream still parses but the declared dimensions no
    longer agree with the coded picture, exercising decoder buffer-sizing paths.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    target = rng.choice(["pic_width_in_luma_samples", "pic_height_in_luma_samples"])
    span = sps.span(target)
    candidates = [
        span.value + rng.choice([-2, 2, 16, -16]),
        rng.choice([1, 3, 7, 65535, 0]),
        span.value * 2,
    ]
    new_value = max(0, rng.choice(candidates))
    new_rbsp = splice_ue_field(rbsp, span, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)

    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="sps-dimensions",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=f"{target}: {span.value} -> {new_value}",
    )


@register("pps-tile-config")
def pps_tile_config(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Flip PPS tile/entropy-sync flags to inconsistent settings.

    Toggling tiles_enabled_flag (and/or entropy_coding_sync_enabled_flag) without
    supplying the dependent tile-geometry syntax makes the PPS internally
    inconsistent, exercising tile-setup code paths.
    """
    out = _clone(nals)
    idx = _first(out, 34)  # PPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    pps = parse_pps(rbsp)

    target = rng.choice(["tiles_enabled_flag", "entropy_coding_sync_enabled_flag"])
    span = pps.span(target)
    new_value = 1 - span.value
    new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)

    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="pps-tile-config",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=f"{target}: {span.value} -> {new_value}",
    )


@register("pps-deblocking")
def pps_deblocking(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Corrupt the PPS deblocking-filter / loop-filter control fields.

    The PPS deblocking-filter control region (H.265 §7.3.2.3) gates per-picture
    loop-filter behaviour and carries two signed offsets with a tight spec range.
    Decoders that trust these fields without re-clamping can index filter
    strength tables out of bounds or skip a filter pass the slice header still
    references. CVE-2026-33164 (libde265 <1.0.17) crashed in
    ``set_derived_values()`` on a malformed PPS — the deblocking control fields
    sit in that same derive path.

    One of three mutations is chosen per invocation, falling back to an
    always-available one when the seed PPS does not reach the deeper fields:

      1. **out-of-range beta/tc offset** — rewrite ``pps_beta_offset_div2`` or
         ``pps_tc_offset_div2`` (se(v), spec range [-6, 6]) to a far out-of-range
         magnitude (±64), pushing filter-strength table lookups past their bounds.
      2. **flip pps_deblocking_filter_disabled_flag** — toggle the disable flag,
         making the PPS claim the filter is on/off inconsistently with the
         beta/tc offsets that follow (or are now expected to follow).
      3. **flip pps_loop_filter_across_slices_enabled_flag** — toggle the
         cross-slice loop-filter scope flag, exercising the slice-boundary filter
         path. This field is reached whenever the PPS has no tiles, so it is the
         conservative fallback.

    Only PPS streams without tiles enabled are mutated here — tile geometry is
    variable-length and out of the structured-mutation scope; if no deblocking
    span is reachable the mutator raises so the engine can pick another mutator.
    """
    out = _clone(nals)
    idx = _first(out, 34)  # PPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    pps = parse_pps(rbsp)

    if not pps.has_span("pps_loop_filter_across_slices_enabled_flag"):
        raise ValueError(
            "PPS did not parse to the deblocking region (tiles enabled or truncated)"
        )

    # Build the menu of available mutations based on which spans were reached.
    choices: list[str] = ["loop_filter_across_slices"]
    if pps.has_span("pps_deblocking_filter_disabled_flag"):
        choices.append("disabled_flag")
    if pps.has_span("pps_beta_offset_div2") and pps.has_span("pps_tc_offset_div2"):
        choices.append("beta_tc_offset")

    choice = rng.choice(choices)

    if choice == "beta_tc_offset":
        target = rng.choice(["pps_beta_offset_div2", "pps_tc_offset_div2"])
        span = pps.span(target)
        # Spec range is [-6, 6]; pick a far out-of-range magnitude.
        new_value = rng.choice([-64, -32, 32, 64, span.value + 32, span.value - 32])
        new_rbsp = splice_se_field(rbsp, span, new_value)
        detail = (
            f"{target}: {span.value} -> {new_value} "
            f"(out of spec range [-6, 6])"
        )

    elif choice == "disabled_flag":
        span = pps.span("pps_deblocking_filter_disabled_flag")
        new_value = 1 - span.value
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
        detail = f"pps_deblocking_filter_disabled_flag: {span.value} -> {new_value}"

    else:  # loop_filter_across_slices
        span = pps.span("pps_loop_filter_across_slices_enabled_flag")
        new_value = 1 - span.value
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
        detail = (
            f"pps_loop_filter_across_slices_enabled_flag: {span.value} -> {new_value}"
        )

    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="pps-deblocking",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


@register("pps-extension-flags")
def pps_extension_flags(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Flip a PPS extension gate flag to desynchronise the PPS tail.

    Past the deblocking-filter control region the PPS (H.265 §7.3.2.1) carries two
    single-bit gates, each of which promises a variable-length sub-block when set:

      * ``pps_scaling_list_data_present_flag`` — when 1, a ``scaling_list_data()``
        structure (H.265 §7.3.4) follows: a series of ue(v)/se(v)-coded
        scaling-list coefficients whose length depends on the lists' sizes.
      * ``pps_extension_present_flag`` — when 1, four PPS profile-extension flags
        (``pps_range_extension_flag``, ``pps_multilayer_extension_flag``,
        ``pps_3d_extension_flag``, ``pps_scc_extension_flag``) plus a 4-bit
        ``pps_extension_4bits`` follow, then any enabled extension's body.

    This is the PPS analogue of ``sps-rext-flags`` and addresses the PPS half of
    gap-analysis item #8 (scaling lists) / item #10 (extension flags): both SPS
    gates are already covered, but the PPS scaling-list and extension gates were
    untouched. The mutator flips one gate the seed currently has *off* to *on*
    without supplying the dependent sub-block. The decoder then reads
    ``scaling_list_data()`` coefficients (or the extension flags and their bodies)
    out of the PPS trailing bits — RBSP stop bits and whatever follows — forcing
    it onto its scaling-list / profile-extension parse path with no valid data
    behind the gate. Scaling-list parsing in particular walks DC-coefficient and
    delta-coefficient loops sized by list dimensions, a region historically prone
    to out-of-bounds reads when fed garbage.

    Only gates the seed currently has off are offered: flipping a gate on is the
    "claims data that isn't there" direction that desynchronises the tail without
    being rejected as broken framing. ``pps_extension_present_flag`` is preferred
    when reachable (it pulls the decoder through the most additional syntax). The
    parser only reaches these gates for an untiled, non-truncated PPS — and the
    extension-present gate is unreachable once the scaling-list gate is already on,
    since its variable-length body is not walked. If neither off gate is present
    the mutator raises so the engine picks another.

    [Worker decision: gate-flip splice keeps the PPS byte-stable]
    Each target is a single u(1) bit, so the splice never shifts the stream's
    bit-length — only the one gate bit changes and the downstream desync is purely
    semantic, matching the established gate-flag mutators (``sps-vui-hrd``,
    ``sps-rext-flags``).
    """
    out = _clone(nals)
    idx = _first(out, 34)  # PPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    pps = parse_pps(rbsp)

    # Prefer the extension-present gate (pulls the decoder through the most
    # additional unmodelled syntax), then the scaling-list gate.
    gate_names = (
        "pps_extension_present_flag",
        "pps_scaling_list_data_present_flag",
    )
    candidates = [
        name
        for name in gate_names
        if pps.has_span(name) and pps.span(name).value == 0
    ]
    if not candidates:
        raise ValueError(
            "PPS did not parse to a scaling-list / extension gate flag that is "
            "currently off; cannot mutate PPS extension flags"
        )

    target = rng.choice(candidates)
    span = pps.span(target)
    new_value = 1  # turn the gate on; the dependent sub-block is absent
    new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="pps-extension-flags",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=(
            f"{target}: 0 -> 1 (PPS extension gate enabled without its dependent "
            f"sub-block; downstream PPS-tail desync)"
        ),
    )


@register("pps-slice-qp")
def pps_slice_qp(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Corrupt the PPS quantization / transform-skip control fields.

    The PPS carries the picture-level quantization baseline and the transform-skip
    enable that downstream slice QP arithmetic and coefficient-array sizing both
    depend on (H.265 §7.4.3.3):

      * ``init_qp_minus26`` (se(v)) — picture QP baseline; spec range is
        [-(26 + 6*bit_depth_offset), 25], i.e. [-26, 25] for 8-bit. Decoders that
        pre-allocate a quantization coefficient table sized by ``maxQP - minQP + 1``
        and clamp ``init_qp`` incorrectly can produce a zero or negative allocation
        size, or index a dequant scaling table out of bounds.
      * ``transform_skip_enabled_flag`` (u(1)) — gates transform-skip coding.
        Flipping it to 1 without the matching SPS range-extension flags
        (``transform_skip_rotation_enabled_flag`` etc.) creates an inconsistency
        that exercises range-extension handling paths.

    One of two mutations is chosen per invocation:

      1. **out-of-range init_qp_minus26** — rewrite the se(v) field to ±52, well
         outside the spec range [-26, 25], driving the picture QP baseline past the
         valid [0, 51] derived-QP window.
      2. **flip transform_skip_enabled_flag** — toggle the u(1) flag, exercising
         the transform-skip / range-extension consistency check.

    Both fields precede the tile-config flags, so they are always reachable for any
    PPS that parses at all — this mutator never has to fall back. QP-related
    mutations are historically productive for integer-overflow bugs in dequant
    array sizing.
    """
    out = _clone(nals)
    idx = _first(out, 34)  # PPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    pps = parse_pps(rbsp)

    if not pps.has_span("init_qp_minus26") or not pps.has_span(
        "transform_skip_enabled_flag"
    ):
        raise ValueError(
            "PPS did not parse to the QP / transform-skip region (truncated PPS)"
        )

    choice = rng.choice(["init_qp", "transform_skip"])

    if choice == "init_qp":
        span = pps.span("init_qp_minus26")
        # Spec range is [-26, 25]; pick a far out-of-range magnitude.
        new_value = rng.choice([-52, -64, 52, 64])
        new_rbsp = splice_se_field(rbsp, span, new_value)
        detail = (
            f"init_qp_minus26: {span.value} -> {new_value} "
            f"(out of spec range [-26, 25])"
        )
    else:  # transform_skip
        span = pps.span("transform_skip_enabled_flag")
        new_value = 1 - span.value
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
        detail = (
            f"transform_skip_enabled_flag: {span.value} -> {new_value} "
            f"(no matching SPS range-extension flags)"
        )

    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="pps-slice-qp",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


@register("slice-header-ref-pic-list")
def slice_header_ref_pic_list(
    nals: list[NalUnit], rng: random.Random
) -> MutationResult:
    """Corrupt slice-header fields driving reference-picture-list management.

    We rewrite slice_pic_parameter_set_id to a non-existent PPS id, which makes
    the slice point at a parameter set that does not exist, breaking the chain
    that feeds reference-picture-list construction. Also occasionally flips
    first_slice_segment_in_pic_flag, which alters slice-address handling.
    """
    out = _clone(nals)
    idx = _first_vcl(out)
    original_stream = assemble_nal_units(nals)
    nal = out[idx]
    rbsp = ebsp_to_rbsp(nal.ebsp[2:])
    sh = parse_slice_header(rbsp, nal.nal_unit_type)

    if rng.random() < 0.5:
        span = sh.span("slice_pic_parameter_set_id")
        new_value = span.value + rng.choice([1, 2, 7, 63])
        new_rbsp = splice_ue_field(rbsp, span, new_value)
        detail = f"slice_pic_parameter_set_id: {span.value} -> {new_value}"
    else:
        span = sh.span("first_slice_segment_in_pic_flag")
        new_value = 1 - span.value
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
        detail = f"first_slice_segment_in_pic_flag: {span.value} -> {new_value}"

    out[idx] = _rewrite_payload(nal, new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="slice-header-ref-pic-list",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


def _first_irap_vcl(nals: list[NalUnit]) -> int:
    """Index of the first IRAP VCL slice (NAL types [16, 23]).

    IRAP slices are the only slices that carry ``no_output_of_prior_pics_flag``.
    Raises ``ValueError`` when the stream has none.
    """
    for i, n in enumerate(nals):
        if 16 <= n.nal_unit_type <= 23:
            return i
    raise ValueError("no IRAP VCL slice (NAL types 16..23) found in stream")


@register("slice-no-output-prior-pics")
def slice_no_output_prior_pics(
    nals: list[NalUnit], rng: random.Random
) -> MutationResult:
    """Flip ``no_output_of_prior_pics_flag`` in an IRAP slice header.

    ``no_output_of_prior_pics_flag`` (H.265 §7.3.6.1) appears only on IRAP slices
    (NAL types [16, 23]). It tells the decoder whether to discard the pictures
    already buffered in the DPB *without outputting them* when this IRAP begins a
    new coded-video-sequence. Flipping it inverts that decision:

      * 0 -> 1 forces the decoder to drop a full DPB of valid, not-yet-output
        pictures — exercising the early DPB-flush path with live buffers.
      * 1 -> 0 forces the decoder to *keep* and attempt to output pictures whose
        POC / reference state the new CVS has invalidated — exercising the DPB
        bumping / output-reorder logic with stale entries.

    Both directions drive the same DPB output / flush machinery (``bumping``,
    ``set_derived_values()`` derived DPB sizing) that the CVE-2026-33164 crash
    family runs through, and the flag is fully self-contained: it is located and
    rewritten with no SPS/PPS context. The 1-bit splice never changes the slice
    length, so every other byte of the stream is preserved exactly.

    Raises ``ValueError`` if the stream contains no IRAP slice (the engine then
    picks a different mutator).
    """
    out = _clone(nals)
    idx = _first_irap_vcl(out)
    original_stream = assemble_nal_units(nals)
    nal = out[idx]
    rbsp = ebsp_to_rbsp(nal.ebsp[2:])
    sh = parse_slice_header(rbsp, nal.nal_unit_type)

    if not sh.has_span("no_output_of_prior_pics_flag"):
        # Should not happen for an IRAP slice, but guard so the engine can retry.
        raise ValueError("IRAP slice header did not expose no_output_of_prior_pics_flag")

    span = sh.span("no_output_of_prior_pics_flag")
    new_value = 1 - span.value
    new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
    detail = (
        f"no_output_of_prior_pics_flag: {span.value} -> {new_value} "
        f"(IRAP NAL #{idx}, type {nal.nal_unit_type}; DPB flush/output inversion)"
    )

    out[idx] = _rewrite_payload(nal, new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="slice-no-output-prior-pics",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


@register("nal-unit-type-swap")
def nal_unit_type_swap(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Swap a NAL unit's nal_unit_type to an inconsistent type.

    The nal_unit_type lives in bits 1..6 of the first NAL header byte. Changing
    it (e.g. relabelling a slice as a different slice type, or a parameter set as
    another) makes the access-unit structure inconsistent while keeping every
    byte otherwise intact.
    """
    out = _clone(nals)
    # Prefer a VCL slice; fall back to any NAL.
    try:
        idx = _first_vcl(out)
    except ValueError:
        idx = rng.randrange(len(out))
    original_stream = assemble_nal_units(nals)
    nal = out[idx]
    old_type = nal.nal_unit_type

    # Choose a different, still-defined VCL/IRAP type to keep it "plausible".
    candidate_types = [0, 1, 4, 6, 8, 19, 20, 21]
    candidate_types = [t for t in candidate_types if t != old_type]
    new_type = rng.choice(candidate_types)

    header0 = nal.ebsp[0]
    forbidden_and_lsb = header0 & 0x81  # keep forbidden_zero_bit + low bit
    new_header0 = forbidden_and_lsb | (new_type << 1)
    new_ebsp = bytes([new_header0]) + nal.ebsp[1:]
    out[idx] = NalUnit(nal.start_code_len, nal.offset, new_ebsp)

    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="nal-unit-type-swap",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=f"nal_unit_type: {old_type} -> {new_type} (NAL #{idx})",
    )


def _write_st_ref_pic_set(writer, rps: ShortTermRps) -> None:
    """Serialise an ``st_ref_pic_set()`` block (stRpsIdx==0, H.265 7.3.7)."""
    writer.write_ue(rps.num_negative_pics)
    writer.write_ue(rps.num_positive_pics)
    for delta, used in zip(rps.delta_poc_s0_minus1, rps.used_by_curr_pic_s0_flag):
        writer.write_ue(delta)
        writer.write_bit(used)
    for delta, used in zip(rps.delta_poc_s1_minus1, rps.used_by_curr_pic_s1_flag):
        writer.write_ue(delta)
        writer.write_bit(used)


@register("rps-overflow")
def rps_overflow(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Overflow DPB index arrays via an out-of-range short-term RPS picture count.

    Sets ``num_negative_pics`` (or ``num_positive_pics``) in the SPS short-term
    RPS above ``sps_max_dec_pic_buffering_minus1[0]``. Decoders that size DPB index
    arrays from the DPB bound but then loop on the raw RPS count walk past the end
    of those arrays — the bug class behind CVE-2026-33164's DPB-sizing path.

    The seed's SPS may declare zero short-term RPS sets (an intra-only stream). In
    that case the mutator *synthesises* one ``st_ref_pic_set()`` carrying the
    overflow count, bumping ``num_short_term_ref_pic_sets`` to 1, so the malformed
    RPS reaches the decoder. If the SPS already carries an RPS set, its first set's
    ``num_negative_pics`` is rewritten in place.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    if not sps.sps_max_dec_pic_buffering_minus1:
        raise ValueError("SPS did not parse to the DPB-sizing region; cannot overflow RPS")
    dpb_bound = sps.sps_max_dec_pic_buffering_minus1[0]
    overflow_count = dpb_bound + 1 + rng.choice([1, 2, 8, 16])

    num_st = sps.num_short_term_ref_pic_sets
    if num_st:
        # Mutate the first existing short-term RPS in place: rewrite its
        # num_negative_pics span by rebuilding the whole st_ref_pic_set(0).
        first = sps.short_term_rps[0]
        target = rng.choice(["num_negative_pics", "num_positive_pics"])
        crafted = ShortTermRps(
            num_negative_pics=overflow_count if target == "num_negative_pics" else first.num_negative_pics,
            num_positive_pics=overflow_count if target == "num_positive_pics" else first.num_positive_pics,
        )
        # Keep the deltas parseable: emit one zero-delta used pair per picture.
        crafted.delta_poc_s0_minus1 = [0] * crafted.num_negative_pics
        crafted.used_by_curr_pic_s0_flag = [1] * crafted.num_negative_pics
        crafted.delta_poc_s1_minus1 = [0] * crafted.num_positive_pics
        crafted.used_by_curr_pic_s1_flag = [1] * crafted.num_positive_pics
        # The region to replace is the first st_ref_pic_set(0): from the bit just
        # after num_short_term_ref_pic_sets to the bit before the long-term flag,
        # only valid when there is exactly one set. With >1 set, replace just the
        # first by recomputing its encoded length.
        st_span = sps.span("num_short_term_ref_pic_sets")
        prefix = st_span.bit_offset + st_span.bit_length
        old_region = _encoded_st_rps_bits(first)
        new_rbsp = splice_replace_region(
            rbsp, prefix, old_region, lambda w: _write_st_ref_pic_set(w, crafted)
        )
        detail = (
            f"{target}: {getattr(first, target)} -> {overflow_count} "
            f"(> sps_max_dec_pic_buffering_minus1[0]={dpb_bound})"
        )
    else:
        # Synthesise a single short-term RPS carrying the overflow count.
        target = rng.choice(["num_negative_pics", "num_positive_pics"])
        neg = overflow_count if target == "num_negative_pics" else 0
        pos = overflow_count if target == "num_positive_pics" else 0
        crafted = ShortTermRps(
            num_negative_pics=neg,
            num_positive_pics=pos,
            delta_poc_s0_minus1=[0] * neg,
            used_by_curr_pic_s0_flag=[1] * neg,
            delta_poc_s1_minus1=[0] * pos,
            used_by_curr_pic_s1_flag=[1] * pos,
        )
        st_span = sps.span("num_short_term_ref_pic_sets")

        def _emit(w):
            w.write_ue(1)  # num_short_term_ref_pic_sets = 1
            _write_st_ref_pic_set(w, crafted)

        new_rbsp = splice_replace_region(
            rbsp, st_span.bit_offset, st_span.bit_length, _emit
        )
        detail = (
            f"injected st_ref_pic_set with {target}={overflow_count} "
            f"(> sps_max_dec_pic_buffering_minus1[0]={dpb_bound})"
        )

    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="rps-overflow",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


def _encoded_st_rps_bits(rps: ShortTermRps) -> int:
    """Number of RBSP bits the given st_ref_pic_set(0) occupies when re-encoded."""
    from ..bitstream import BitWriter

    w = BitWriter()
    _write_st_ref_pic_set(w, rps)
    return w.bit_length


@register("rps-lt-poc-ambiguity")
def rps_lt_poc_ambiguity(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Craft two long-term RPS entries sharing one ``poc_lsb_lt`` value.

    Triggers the ambiguous POC-LSB condition of HEVC trac #1097: when two DPB
    entries carry the same long-term POC LSB and ``delta_poc_msb_present_flag`` is
    absent, the reference model (and downstream forks) miscalculate which picture
    a long-term reference resolves to. The two entries are emitted in the SPS
    long-term RPS block with identical ``poc_lsb_lt`` and no MSB-cycle override.

    The seed's SPS may have ``long_term_ref_pics_present_flag == 0``; the mutator
    flips it on and synthesises the two-entry block. ``poc_lsb_lt`` is u(v) with
    width ``log2_max_pic_order_cnt_lsb_minus4 + 4``.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    if sps.log2_max_pic_order_cnt_lsb_minus4 is None or sps.long_term_ref_pics_present_flag is None:
        raise ValueError("SPS did not parse to the long-term RPS region")

    poc_bits = sps.log2_max_pic_order_cnt_lsb_minus4 + 4
    shared_lsb = rng.randrange(0, 1 << poc_bits)

    lt_span = sps.span("long_term_ref_pics_present_flag")

    def _emit(w):
        w.write_bit(1)  # long_term_ref_pics_present_flag = 1
        w.write_ue(2)  # num_long_term_ref_pics_sps = 2
        for _ in range(2):
            w.write_bits(shared_lsb, poc_bits)  # lt_ref_pic_poc_lsb_sps (identical)
            w.write_bit(1)  # used_by_curr_pic_lt_sps_flag

    new_rbsp = splice_replace_region(rbsp, lt_span.bit_offset, lt_span.bit_length, _emit)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="rps-lt-poc-ambiguity",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=(
            f"two long-term entries share poc_lsb_lt={shared_lsb} "
            f"({poc_bits}-bit), delta_poc_msb absent (trac #1097)"
        ),
    )


@register("vps-layer-count")
def vps_layer_count(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Corrupt VPS layer/sublayer counts and temporal-nesting flag.

    The VPS carries two small integer fields that downstream hardware and
    software decoders use to bound per-layer loops and allocate DPB arrays:

      * ``vps_max_layers_minus1``     — spec range [0, 62]; overflow target: 63+
      * ``vps_max_sub_layers_minus1`` — spec range [0, 6];  overflow target: 7+
      * ``vps_temporal_id_nesting_flag`` — flip when sub_layers=0 (spec violation)

    One of three mutations is chosen at random:

      1. Set ``vps_max_layers_minus1`` to 63 or 127, overflowing the
         ``HEVC_MAX_LAYERS = 63`` array-bound guard in decoders that use the raw
         field value as a loop count.
      2. Set ``vps_max_sub_layers_minus1`` to 7, overflowing per-layer DPB
         arrays indexed up to this value.
      3. Flip ``vps_temporal_id_nesting_flag`` while clamping
         ``vps_max_sub_layers_minus1`` to 0 — the spec requires nesting_flag=1
         when sub_layers=0; the violation exercises "nesting check" code paths.

    Reference: TWINFUZZ (NDSS 2025); ffmpeg hevcdec.c layer-loop guards.
    """
    out = _clone(nals)
    idx = _first(out, 32)  # VPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    vps = parse_vps(rbsp)

    choice = rng.randint(0, 2)

    if choice == 0:
        # Mutation 1: vps_max_layers_minus1 overflow
        new_layers = rng.choice([63, 127])
        span = vps.span("vps_max_layers_minus1")
        # Field is 6 bits; 63 fits (0x3F), 127 does not — clamp to 6-bit max
        new_layers_encoded = min(new_layers, 63)  # 6-bit field max is 63 (0x3F)
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_layers_encoded)
        detail = f"vps_max_layers_minus1: {vps.vps_max_layers_minus1} -> {new_layers_encoded} (overflow HEVC_MAX_LAYERS=63)"

    elif choice == 1:
        # Mutation 2: vps_max_sub_layers_minus1 overflow (3-bit field, max=7)
        span = vps.span("vps_max_sub_layers_minus1")
        new_sub = 7  # max 3-bit value; spec range is 0..6, so 7 is the violation
        new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_sub)
        detail = f"vps_max_sub_layers_minus1: {vps.vps_max_sub_layers_minus1} -> {new_sub} (spec range 0..6)"

    else:
        # Mutation 3: flip nesting_flag with sub_layers clamped to 0
        # First clamp vps_max_sub_layers_minus1 to 0
        sub_span = vps.span("vps_max_sub_layers_minus1")
        tmp_rbsp = splice_fixed_bits(rbsp, sub_span.bit_offset, sub_span.bit_length, 0)
        # Re-parse to get updated nesting_flag position (offsets unchanged, same field)
        nesting_span = vps.span("vps_temporal_id_nesting_flag")
        flipped = 1 - vps.vps_temporal_id_nesting_flag
        new_rbsp = splice_fixed_bits(tmp_rbsp, nesting_span.bit_offset, nesting_span.bit_length, flipped)
        detail = (
            f"vps_temporal_id_nesting_flag: {vps.vps_temporal_id_nesting_flag} -> {flipped} "
            f"(vps_max_sub_layers_minus1 clamped to 0; spec violation)"
        )

    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="vps-layer-count",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


def _first_sei(nals: list[NalUnit]) -> int:
    """Return the index of the first PREFIX_SEI_NUT (39) or SUFFIX_SEI_NUT (40) NAL."""
    for i, n in enumerate(nals):
        if n.nal_unit_type in (39, 40):
            return i
    raise ValueError("no SEI NAL (type 39 or 40) found in stream")


def _sei_inject_buffering_period_overflow(
    out: list[NalUnit],
    idx: int | None,
    nal: "NalUnit | None",
    rbsp: "bytes | None",
    messages: list,
) -> tuple[list[NalUnit], str]:
    """Apply the buffering_period overflow mutation.  Returns (updated_nals, detail)."""
    from ..bitstream import BitWriter

    w = BitWriter()
    w.write_ue(0xFFFFFFFF)
    payload_bytes = w.to_bytes()
    if len(payload_bytes) > 254:
        payload_bytes = payload_bytes[:254]
    sei_rbsp_synth = bytes([0x00, len(payload_bytes)]) + payload_bytes + b"\x80"

    if idx is not None and messages:
        assert nal is not None and rbsp is not None
        bp_msg = next((m for m in messages if m.payload_type == 0), None)
        if bp_msg is None:
            trail_pos = rbsp.rfind(b"\x80")
            if trail_pos < 0:
                trail_pos = len(rbsp)
            insert = bytes([0x00, len(payload_bytes)]) + payload_bytes
            new_rbsp = rbsp[:trail_pos] + insert + rbsp[trail_pos:]
        else:
            pre = rbsp[: bp_msg.payload_offset]
            post = rbsp[bp_msg.payload_offset + bp_msg.payload_size :]
            new_payload = (payload_bytes + b"\x00" * bp_msg.payload_size)[: bp_msg.payload_size]
            new_rbsp = pre + new_payload + post
        out[idx] = _rewrite_payload(nal, new_rbsp)
        detail = (
            f"buffering_period.initial_cpb_removal_delay -> 0xFFFFFFFF "
            f"(ue(v) overflow, SEI NAL #{idx})"
        )
    else:
        param_set_types = {32, 33, 34}
        last_ps = -1
        for i, n in enumerate(out):
            if n.nal_unit_type in param_set_types:
                last_ps = i
        sei_header = bytes([0x4E, 0x01])
        sei_ebsp = sei_header + rbsp_to_ebsp(sei_rbsp_synth)
        sei_nal = NalUnit(start_code_len=4, offset=0, ebsp=sei_ebsp)
        out.insert(last_ps + 1, sei_nal)
        detail = (
            "synthetic PREFIX_SEI injected: buffering_period.initial_cpb_removal_delay "
            "= 0xFFFFFFFF (HRD arithmetic overflow)"
        )
    return out, detail


@register("sei-buffering-overflow")
def sei_buffering_overflow(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Corrupt SEI message fields to trigger HRD and POC arithmetic edge cases.

    Three targeted SEI payload corruptions, one chosen per invocation:

      1. **buffering_period (payloadType 0) — HRD overflow**
         Overwrites the first ue(v) field (``initial_cpb_removal_delay``) with
         ``0xFFFFFFFF``, encoded as exp-Golomb. Decoders that compute HRD
         conformance timing arithmetic from the raw delay value may overflow
         when adding this to a base clock.

      2. **pic_timing (payloadType 1) — cpb_removal_delay length mismatch**
         Overwrites the first two bytes of the payload with ``0xFF 0xFF``,
         placing max-value bit patterns into whatever fixed-width fields
         ``cpb_removal_delay`` occupies. This creates a length-field mismatch
         that exercises the decoder's payload-length-check path.

      3. **recovery_point (payloadType 6) — POC underflow**
         Overwrites the first se(v) (``recovery_poc_cnt``) with the most
         negative se(v) value encodable in 32 bits (``-2147483648``). Decoders
         that add this to the current POC without a signed-overflow guard
         underflow the POC counter.

    If the stream has no SEI NAL, a synthetic PREFIX_SEI NAL carrying a
    buffering_period payload is injected immediately after the last parameter-
    set NAL (VPS/SPS/PPS), so the mutation always exercises a code path.
    """
    from ..bitstream import BitWriter

    out = _clone(nals)
    original_stream = assemble_nal_units(nals)
    mutation_choice = rng.randint(0, 2)

    try:
        idx = _first_sei(out)
        nal = out[idx]
        rbsp = ebsp_to_rbsp(nal.ebsp[2:])
        messages = parse_sei(rbsp)
    except ValueError:
        idx = None
        nal = None
        rbsp = None
        messages = []

    def _encode_se(v: int) -> bytes:
        w = BitWriter()
        w.write_se(v)
        return w.to_bytes()

    detail: str

    if not messages or mutation_choice == 0:
        # Mutation 0 / fallback: buffering_period overflow
        out, detail = _sei_inject_buffering_period_overflow(out, idx, nal, rbsp, messages)

    elif mutation_choice == 1:
        # Mutation 1: pic_timing — overwrite first two payload bytes with 0xFF 0xFF
        pt_msg = next((m for m in messages if m.payload_type == 1), None)
        if pt_msg is not None and pt_msg.payload_size >= 2:
            assert nal is not None and rbsp is not None
            rbsp_list = bytearray(rbsp)
            rbsp_list[pt_msg.payload_offset] = 0xFF
            rbsp_list[pt_msg.payload_offset + 1] = 0xFF
            new_rbsp = bytes(rbsp_list)
            out[idx] = _rewrite_payload(nal, new_rbsp)
            detail = (
                f"pic_timing payload bytes [0:2] -> 0xFF 0xFF "
                f"(cpb_removal_delay length-mismatch, SEI NAL #{idx})"
            )
        else:
            # No suitable pic_timing — fall back to buffering_period overflow
            out, detail = _sei_inject_buffering_period_overflow(out, idx, nal, rbsp, messages)

    else:
        # Mutation 2: recovery_point (payloadType 6) — POC underflow
        rp_msg = next((m for m in messages if m.payload_type == 6), None)
        if rp_msg is not None and rp_msg.payload_size >= 1:
            assert nal is not None and rbsp is not None
            underflow_se = _encode_se(-2147483648)
            pre = rbsp[: rp_msg.payload_offset]
            post = rbsp[rp_msg.payload_offset + rp_msg.payload_size :]
            new_payload = (underflow_se + b"\x00" * rp_msg.payload_size)[: rp_msg.payload_size]
            new_rbsp = pre + new_payload + post
            out[idx] = _rewrite_payload(nal, new_rbsp)
            detail = (
                f"recovery_point.recovery_poc_cnt -> -2147483648 "
                f"(se(v) underflow, SEI NAL #{idx})"
            )
        else:
            # No recovery_point — fall back to buffering_period overflow
            out, detail = _sei_inject_buffering_period_overflow(out, idx, nal, rbsp, messages)

    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="sei-buffering-overflow",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


@register("sps-chroma-format")
def sps_chroma_format(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Mutate ``chroma_format_idc`` to an inconsistent or reserved value.

    ``chroma_format_idc`` (ue(v), H.265 §7.3.2.2.1) selects the sample format:
    0 = monochrome, 1 = 4:2:0, 2 = 4:2:2, 3 = 4:4:4. The value also gates the
    presence of ``separate_colour_plane_flag`` (present only when idc == 3) and
    drives chroma sample-buffer sizing throughout the decoder. Two corruptions
    are chosen per invocation:

      1. **reserved value** — set ``chroma_format_idc`` to 4, which is reserved
         (the valid range is [0, 3]). Decoders that index a chroma-subsampling
         lookup table by the raw value walk one entry past the table.
      2. **4:4:4 / separate-plane inconsistency** — set ``chroma_format_idc`` to 3
         (4:4:4). When the seed's idc was *not* 3, the decoder will now expect a
         ``separate_colour_plane_flag`` bit that the bitstream never reserved,
         desynchronising every field that follows — the inconsistency class behind
         width/height/format mismatch CVEs (e.g. CVE-2022-3266).

    The chroma field is always reachable (it sits before the dimensions), so this
    mutator never has to fall back. CVE-2022-3266 (Firefox) was triggered by a
    width/height mismatch between container and SPS; chroma-format inconsistency
    is the analogous sample-format path, and many hardware HEVC decoders branch
    4:2:0 / 4:2:2 / 4:4:4 into separate firmware paths.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    span = sps.span("chroma_format_idc")

    # Offer the "reserved 4" mutation always; offer the "force 4:4:4" mutation
    # only when it actually creates an inconsistency (seed idc != 3).
    choices = ["reserved"]
    if span.value != 3:
        choices.append("force_444")
    choice = rng.choice(choices)

    if choice == "force_444":
        new_value = 3
        detail = (
            f"chroma_format_idc: {span.value} -> 3 (4:4:4 without a reserved "
            f"separate_colour_plane_flag bit; downstream desync)"
        )
    else:
        new_value = 4
        detail = f"chroma_format_idc: {span.value} -> 4 (reserved; valid range [0, 3])"

    new_rbsp = splice_ue_field(rbsp, span, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="sps-chroma-format",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


@register("sps-bit-depth")
def sps_bit_depth(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Push the SPS luma/chroma bit-depth fields past their spec range.

    ``bit_depth_luma_minus8`` and ``bit_depth_chroma_minus8`` (ue(v),
    H.265 §7.3.2.2.1) carry the coded sample bit depth minus 8. The HEVC spec
    constrains both to [0, 8] (i.e. 8- to 16-bit samples). A decoder that
    allocates sample buffers as ``(bit_depth + 1)`` bytes (or shifts by the raw
    value) from an out-of-range field will over-allocate, mis-shift, or wrap a
    size computation. Many hardware HEVC decoders implement 8-bit and 10-bit
    paths in separate firmware branches; a bit depth they do not recognise forces
    the hardware to guess or fault.

    One of the two fields is picked and rewritten to a value well above 8 (the
    spec ceiling), exercising the sample-buffer-sizing path. This mutator requires
    the SPS to have parsed through the bit-depth region; if it did not (truncated
    or scaling-list SPS reached before bit depth), it raises so the engine can
    pick another mutator.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    if not sps.has_span("bit_depth_luma_minus8") or not sps.has_span(
        "bit_depth_chroma_minus8"
    ):
        raise ValueError(
            "SPS did not parse to the bit-depth region; cannot mutate bit depth"
        )

    target = rng.choice(["bit_depth_luma_minus8", "bit_depth_chroma_minus8"])
    span = sps.span(target)
    # Spec range is [0, 8]; pick a value well past the ceiling.
    new_value = rng.choice([9, 16, 24, 56, 248])
    new_rbsp = splice_ue_field(rbsp, span, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="sps-bit-depth",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=(
            f"{target}: {span.value} -> {new_value} "
            f"(>8; spec range [0, 8], i.e. >16-bit samples)"
        ),
    )


@register("sps-feature-flags")
def sps_feature_flags(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Flip an SPS feature-toggle flag on without supplying its data block.

    The SPS carries several single-bit feature flags (H.265 §7.3.2.2.1) that each
    gate a *variable-length* data block immediately following:

      * ``scaling_list_enabled_flag`` — when 1, an
        ``sps_scaling_list_data_present_flag`` (and, if set, a full
        ``scaling_list_data()`` structure) follows. Flipping a seed's 0 to a 1
        makes the decoder expect scaling-list syntax the bitstream never reserved,
        desynchronising every field after it. Scaling lists are gap-analysis item
        #8 — a previously untouched SPS attack surface — and feed quantization
        matrices that several decoders copy into fixed-size tables.
      * ``pcm_enabled_flag`` — when 1, a five-element PCM configuration block
        (``pcm_sample_bit_depth_luma_minus1`` etc.) follows. Flipping it on
        without the block forces the decoder to read PCM geometry out of unrelated
        downstream bits, exercising the I_PCM sample-copy path that has historically
        produced out-of-bounds sample writes.

    Only flags the seed currently has *off* are offered (flipping an enabled flag
    off would be a no-op for the inconsistency we want, since the data block stays
    in the stream and the tail is still desynchronised — we want the cleaner
    "claims data that isn't there" direction). Each flag's span is reachable
    whenever the SPS parses through the coding-block geometry; if neither flag was
    reached, or both are already on, the mutator raises so the engine picks another.

    [Worker decision: flag-flip splice keeps the SPS byte-stable]
    Both targets are single u(1) bits, so the splice never shifts the bit-length of
    the stream — only the one flag bit changes; the downstream desync is purely
    semantic, which is exactly the input class that exercises decoder code paths
    without being rejected as malformed framing.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    candidates = []
    for name in ("scaling_list_enabled_flag", "pcm_enabled_flag"):
        if sps.has_span(name) and sps.span(name).value == 0:
            candidates.append(name)
    if not candidates:
        raise ValueError(
            "SPS did not parse to a togglable feature flag that is currently off; "
            "cannot mutate feature flags"
        )

    target = rng.choice(candidates)
    span = sps.span(target)
    new_value = 1  # turn the gate on; the data block it expects is absent
    new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="sps-feature-flags",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=(
            f"{target}: 0 -> 1 (gate enabled without its dependent data block; "
            f"downstream SPS desync)"
        ),
    )


@register("sps-vui-hrd")
def sps_vui_hrd(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Flip an SPS VUI / HRD gate flag to desynchronise the VUI block.

    The SPS optionally carries a ``vui_parameters()`` block (H.265 §E.2.1) whose
    timing and HRD sub-blocks are each gated by a single u(1) flag. This mutator
    addresses gap-analysis item #7 ("HRD parameters in VUI") — a previously
    untouched SPS attack surface — by flipping one of three nested gate flags:

      * ``vui_hrd_parameters_present_flag`` — when flipped 0 -> 1, the decoder
        expects an ``hrd_parameters()`` structure the bitstream never reserved,
        reading CPB/HRD register fields out of unrelated downstream bits. HRD
        arithmetic (``cpb_cnt_minus1``, ``initial_cpb_removal_delay``) is the field
        class behind CVE-2022-22675, so forcing the decoder onto this path with no
        real data exercises exactly those length/bounds checks.
      * ``vui_timing_info_present_flag`` — gates 64 bits of timing info plus the
        HRD gate; flipping it on makes the decoder consume ``num_units_in_tick`` /
        ``time_scale`` from the wrong bits.
      * ``vui_parameters_present_flag`` — the outermost gate; flipping it on
        forces the whole ``vui_parameters()`` walk over absent data.

    Only gates the seed currently has *off* are offered: flipping a gate on is the
    "claims data that isn't there" direction that desynchronises the tail, which is
    the input class that exercises the VUI/HRD parser without being rejected as
    broken framing. If the SPS did not parse to any off gate (e.g. all reachable
    gates are already on, or the SPS is too truncated to reach the VUI), the
    mutator raises so the engine picks another.

    [Worker decision: gate-flip splice keeps the SPS byte-stable]
    Every target is a single u(1) bit, so the splice never shifts the stream's
    bit-length — only the one gate bit changes and the downstream desync is purely
    semantic.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    # Innermost-first so the most-targeted HRD gate is preferred when reachable.
    gate_names = (
        "vui_hrd_parameters_present_flag",
        "vui_timing_info_present_flag",
        "vui_parameters_present_flag",
    )
    candidates = [
        name
        for name in gate_names
        if sps.has_span(name) and sps.span(name).value == 0
    ]
    if not candidates:
        raise ValueError(
            "SPS did not parse to a VUI/HRD gate flag that is currently off; "
            "cannot mutate VUI/HRD gates"
        )

    target = rng.choice(candidates)
    span = sps.span(target)
    new_value = 1  # turn the gate on; the sub-block it expects is absent
    new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="sps-vui-hrd",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=(
            f"{target}: 0 -> 1 (VUI gate enabled without its dependent sub-block; "
            f"downstream VUI/HRD desync)"
        ),
    )


@register("sps-rext-flags")
def sps_rext_flags(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Flip an SPS Range-Extension gate flag to desynchronise the SPS tail.

    After ``vui_parameters()`` the SPS carries a profile-extension region
    (H.265 §7.3.2.2.1) gated by single u(1) flags:

      * ``sps_extension_present_flag`` — when 1, four profile-extension flags
        (``sps_range_extension_flag``, ``sps_multilayer_extension_flag``,
        ``sps_3d_extension_flag``, ``sps_scc_extension_flag``) and a 4-bit
        ``sps_extension_4bits`` follow, then any enabled extension's body.
      * ``sps_range_extension_flag`` — when 1, an ``sps_range_extension()``
        structure (nine RExt feature bits, H.265 §7.3.2.2.2:
        ``transform_skip_rotation_enabled_flag``,
        ``transform_skip_context_enabled_flag``,
        ``implicit_rdpcm_enabled_flag``, ``explicit_rdpcm_enabled_flag``,
        ``extended_precision_processing_flag``, ``intra_smoothing_disabled_flag``,
        ``high_precision_offsets_enabled_flag``,
        ``persistent_rice_adaptation_enabled_flag``,
        ``cabac_bypass_alignment_enabled_flag``) follows.

    This mutator addresses gap-analysis item #8 ("HEVC range extensions (RExt)
    flags") — the last untouched SPS attack surface. It flips one of these gates
    *on* without supplying the dependent extension body: the decoder then reads
    RExt feature bits (and the variable extension bodies that follow) out of the
    SPS trailing bits, forcing it onto its Range-Extension parse path with no
    valid parameter set behind it. The RExt feature bits change coefficient
    coding (extended precision, RDPCM, transform-skip rotation/context) — paths
    that diverge sharply from baseline HEVC and are a known under-tested region.

    Only gates the seed currently has *off* are offered (flipping a gate on is
    the "claims data that isn't there" direction that desynchronises the tail —
    the input class that exercises the parser without being rejected as broken
    framing). The ``sps_range_extension_flag`` gate is preferred when reachable,
    since it lands the decoder directly in RExt coefficient-coding handling. If
    the SPS did not parse to an off extension gate (e.g. VUI present so the parser
    could not walk to the extension region, the gate is already on, or the SPS is
    truncated), the mutator raises so the engine picks another.

    [Worker decision: gate-flip splice keeps the SPS byte-stable]
    Every target is a single u(1) bit, so the splice never shifts the stream's
    bit-length — only the one gate bit changes and the downstream desync is purely
    semantic.
    """
    out = _clone(nals)
    idx = _first(out, 33)  # SPS_NUT
    original_stream = assemble_nal_units(nals)
    rbsp = ebsp_to_rbsp(out[idx].ebsp[2:])
    sps = parse_sps(rbsp)

    # Prefer the range-extension gate (lands directly in RExt handling), then the
    # outer extension-present gate.
    gate_names = (
        "sps_range_extension_flag",
        "sps_extension_present_flag",
    )
    candidates = [
        name
        for name in gate_names
        if sps.has_span(name) and sps.span(name).value == 0
    ]
    if not candidates:
        raise ValueError(
            "SPS did not parse to an SPS extension / RExt gate flag that is "
            "currently off; cannot mutate RExt flags"
        )

    target = rng.choice(candidates)
    span = sps.span(target)
    new_value = 1  # turn the gate on; the dependent extension body is absent
    new_rbsp = splice_fixed_bits(rbsp, span.bit_offset, span.bit_length, new_value)
    out[idx] = _rewrite_payload(out[idx], new_rbsp)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="sps-rext-flags",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=(
            f"{target}: 0 -> 1 (SPS extension gate enabled without its dependent "
            f"sps_range_extension() body; downstream RExt desync)"
        ),
    )


def _find_emulation_byte_offsets(ebsp: bytes) -> list[int]:
    """Return offsets of emulation-prevention bytes (the 0x03) within an EBSP.

    An emulation-prevention byte is the 0x03 in a ``0x00 0x00 0x03`` sequence
    whose following byte is in {0x00, 0x01, 0x02, 0x03} (or end-of-NAL). This is
    the exact rule mirrored from :func:`ebsp_to_rbsp`, so the two stay in lockstep.
    """
    offsets: list[int] = []
    i = 0
    n = len(ebsp)
    while i < n:
        if (
            i + 2 < n
            and ebsp[i] == 0
            and ebsp[i + 1] == 0
            and ebsp[i + 2] == 3
            and (i + 3 >= n or ebsp[i + 3] <= 3)
        ):
            offsets.append(i + 2)  # the 0x03 itself
            i += 3
        else:
            i += 1
    return offsets


@register("nal-emulation-bytes")
def nal_emulation_bytes(nals: list[NalUnit], rng: random.Random) -> MutationResult:
    """Stress the decoder's EBSP-to-RBSP (emulation-prevention) scanner.

    HEVC carries NAL payloads as EBSP (Encapsulated Byte Sequence Payload): to
    keep a start code (``0x00 0x00 0x01``) from appearing inside payload data,
    the encoder inserts an *emulation-prevention byte* (``0x03``) after any
    ``0x00 0x00`` that would otherwise be followed by a byte in
    {0x00, 0x01, 0x02, 0x03}. Every conformant decoder must strip those 0x03
    bytes back out before parsing — and that scanner is a known extreme-value
    attack surface: CVE-2022-32939 (h26forge, iOS kernel, 0-click arbitrary
    write) was triggered by an HEVC NAL carrying an out-of-spec density of
    emulation-prevention bytes.

    Unlike every other mangle mutator, this one operates on the raw on-wire
    *EBSP* bytes directly rather than on a parsed field. ``assemble_nal_units``
    concatenates each NAL's ``ebsp`` verbatim (it does *not* re-run
    ``rbsp_to_ebsp``), so a deliberately malformed EBSP we splice here reaches the
    decoder exactly as written — exercising the decoder's scanner, not mangle's.
    NAL framing (start codes between units) is left untouched.

    One of three corruptions is chosen per invocation, restricted to whichever
    are applicable to the picked NAL:

      1. **insert a phantom emulation sequence** — splice a fresh
         ``0x00 0x00 0x03`` triplet at a byte boundary inside the payload. A
         compliant decoder removes the 0x03 and recovers ``0x00 0x00``; a buggy
         scanner that miscounts the run, or fails to re-scan after removal,
         desynchronises every field after the insertion point.
      2. **drop an existing emulation-prevention byte** — remove the 0x03 from a
         genuine ``0x00 0x00 0x03`` sequence, leaving the raw ``0x00 0x00`` +
         following byte exposed. Decoders that do not re-scan after their first
         pass will misread the now-shorter payload (and a ``0x00 0x00 0x01``
         left behind reads as a phantom start code).
      3. **emulation-byte flood** — inject many ``0x00 0x00 0x03`` triplets in a
         row near the NAL header, reproducing the CVE-2022-32939 high-density
         pattern that overran a fixed-size scratch buffer in the EBSP scanner.

    A NAL with no existing emulation-prevention byte cannot offer mutation (2);
    the menu adapts accordingly. The 2-byte NAL header is always preserved so the
    unit keeps its identity.
    """
    out = _clone(nals)
    original_stream = assemble_nal_units(nals)

    # Pick a non-trivial NAL to corrupt: prefer one with payload past the header.
    candidate_indices = [i for i, n in enumerate(out) if len(n.ebsp) > 2]
    if not candidate_indices:
        raise ValueError("no NAL with payload bytes to corrupt")
    idx = rng.choice(candidate_indices)
    nal = out[idx]
    header = nal.ebsp[:2]
    payload = nal.ebsp[2:]

    existing = _find_emulation_byte_offsets(payload)

    choices = ["insert", "flood"]
    if existing:
        choices.append("drop")
    choice = rng.choice(choices)

    if choice == "drop":
        # Remove a real emulation-prevention byte, exposing raw 0x00 0x00 0xXX.
        pos = rng.choice(existing)  # offset within payload of the 0x03
        new_payload = payload[:pos] + payload[pos + 1 :]
        exposed = payload[pos + 1] if pos + 1 < len(payload) else None
        detail = (
            f"dropped emulation-prevention byte at payload offset {pos} "
            f"(NAL #{idx}); exposes raw 0x0000"
            + (f"{exposed:02x}" if exposed is not None else "")
        )

    elif choice == "flood":
        # High-density emulation flood right after the header (CVE-2022-32939).
        count = rng.choice([64, 128, 256, 300])
        flood = b"\x00\x00\x03" * count
        new_payload = flood + payload
        detail = (
            f"injected {count} consecutive 0x000003 emulation triplets "
            f"({count * 3} bytes) at NAL #{idx} payload head "
            f"(CVE-2022-32939 high-density pattern)"
        )

    else:  # insert
        # Splice one phantom 0x00 0x00 0x03 at a payload byte boundary.
        pos = rng.randrange(0, len(payload) + 1)
        new_payload = payload[:pos] + b"\x00\x00\x03" + payload[pos:]
        detail = (
            f"inserted phantom 0x000003 emulation sequence at payload offset "
            f"{pos} (NAL #{idx})"
        )

    out[idx] = NalUnit(nal.start_code_len, nal.offset, header + new_payload)
    mutated_stream = assemble_nal_units(out)
    return MutationResult(
        nals=out,
        mutator="nal-emulation-bytes",
        bytes_changed=count_changed_bytes(original_stream, mutated_stream),
        detail=detail,
    )


def load_stream(data: bytes) -> list[NalUnit]:
    """Convenience: split a raw Annex-B stream into NAL units."""
    return split_nal_units(data)
