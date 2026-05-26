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
    parse_slice_header,
    parse_sps,
    splice_fixed_bits,
    splice_replace_region,
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


def load_stream(data: bytes) -> list[NalUnit]:
    """Convenience: split a raw Annex-B stream into NAL units."""
    return split_nal_units(data)
