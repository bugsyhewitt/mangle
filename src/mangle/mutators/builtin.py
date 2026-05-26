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
    parse_pps,
    parse_slice_header,
    parse_sps,
    splice_fixed_bits,
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


def load_stream(data: bytes) -> list[NalUnit]:
    """Convenience: split a raw Annex-B stream into NAL units."""
    return split_nal_units(data)
