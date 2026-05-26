"""HEVC parameter-set parsing, scoped to the fields mangle mutates.

We deliberately do *not* implement a full HEVC parser. mangle's job is
structured *parameter-level* mutation: locate a specific syntax element in the
RBSP, then splice a re-encoded value in its place. To do that we parse just far
enough to know (a) the value and (b) the exact bit span the element occupies.

The classes below return a parsed view *and* a list of ``FieldSpan`` records
describing where each interesting element lives, so a mutator can rewrite a
single field without disturbing the rest of the bitstream.

References: ITU-T H.265 section 7.3.2 (parameter sets), 7.3.6 (slice header).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .bitstream import BitReader, BitWriter


@dataclass
class FieldSpan:
    """Locates one syntax element within an RBSP, by bit offset and length."""

    name: str
    bit_offset: int
    bit_length: int
    value: int


def _parse_profile_tier_level(
    reader: BitReader, max_sub_layers_minus1: int
) -> None:
    """Skip profile_tier_level (H.265 7.3.3). We never mutate it, just advance."""
    # general profile/tier/level: 2 + 1 + 5 + 32 + 4 + 43 + 1 = 88 bits, then
    # general_level_idc (8 bits) = 96 bits total for the "general" block.
    reader.read_bits(8)  # general_profile_space(2)+tier(1)+profile_idc(5)
    reader.read_bits(32)  # general_profile_compatibility_flag[32]
    reader.read_bits(48)  # constraint flags(48) incl. progressive/interlaced...
    reader.read_bits(8)  # general_level_idc
    sub_layer_profile_present = []
    sub_layer_level_present = []
    for _ in range(max_sub_layers_minus1):
        sub_layer_profile_present.append(reader.read_bit())
        sub_layer_level_present.append(reader.read_bit())
    if max_sub_layers_minus1 > 0:
        for _ in range(8 - max_sub_layers_minus1):
            reader.read_bits(2)  # reserved_zero_2bits
    for i in range(max_sub_layers_minus1):
        if sub_layer_profile_present[i]:
            reader.read_bits(8)
            reader.read_bits(32)
            reader.read_bits(48)
        if sub_layer_level_present[i]:
            reader.read_bits(8)


@dataclass
class SeqParameterSet:
    """A minimally-parsed HEVC SPS exposing dimension field spans."""

    sps_video_parameter_set_id: int
    sps_max_sub_layers_minus1: int
    chroma_format_idc: int
    pic_width_in_luma_samples: int
    pic_height_in_luma_samples: int
    spans: list[FieldSpan] = field(default_factory=list)

    def span(self, name: str) -> FieldSpan:
        for s in self.spans:
            if s.name == name:
                return s
        raise KeyError(name)


def parse_sps(rbsp: bytes) -> SeqParameterSet:
    """Parse an SPS RBSP up to the picture dimensions.

    ``rbsp`` must be the SPS NAL payload *without* the 2-byte NAL header and
    *with* emulation-prevention bytes already removed.
    """
    reader = BitReader(rbsp)
    vps_id = reader.read_bits(4)  # sps_video_parameter_set_id
    max_sub_layers_minus1 = reader.read_bits(3)
    reader.read_bit()  # sps_temporal_id_nesting_flag
    _parse_profile_tier_level(reader, max_sub_layers_minus1)
    reader.read_ue()  # sps_seq_parameter_set_id

    chroma_off = reader.bit_position
    chroma_format_idc = reader.read_ue()
    chroma_span = FieldSpan(
        "chroma_format_idc", chroma_off, reader.bit_position - chroma_off, chroma_format_idc
    )
    if chroma_format_idc == 3:
        reader.read_bit()  # separate_colour_plane_flag

    width_off = reader.bit_position
    width = reader.read_ue()
    width_span = FieldSpan(
        "pic_width_in_luma_samples", width_off, reader.bit_position - width_off, width
    )

    height_off = reader.bit_position
    height = reader.read_ue()
    height_span = FieldSpan(
        "pic_height_in_luma_samples", height_off, reader.bit_position - height_off, height
    )

    return SeqParameterSet(
        sps_video_parameter_set_id=vps_id,
        sps_max_sub_layers_minus1=max_sub_layers_minus1,
        chroma_format_idc=chroma_format_idc,
        pic_width_in_luma_samples=width,
        pic_height_in_luma_samples=height,
        spans=[chroma_span, width_span, height_span],
    )


@dataclass
class PicParameterSet:
    """A minimally-parsed HEVC PPS exposing tile-config field spans."""

    pps_pic_parameter_set_id: int
    pps_seq_parameter_set_id: int
    tiles_enabled_flag: int
    entropy_coding_sync_enabled_flag: int
    spans: list[FieldSpan] = field(default_factory=list)

    def span(self, name: str) -> FieldSpan:
        for s in self.spans:
            if s.name == name:
                return s
        raise KeyError(name)


def parse_pps(rbsp: bytes) -> PicParameterSet:
    """Parse a PPS RBSP up to and including tiles_enabled_flag.

    ``rbsp`` is the PPS payload without the NAL header, emulation bytes removed.
    """
    reader = BitReader(rbsp)
    spans: list[FieldSpan] = []

    pps_id = reader.read_ue()  # pps_pic_parameter_set_id
    sps_id = reader.read_ue()  # pps_seq_parameter_set_id
    reader.read_bit()  # dependent_slice_segments_enabled_flag
    reader.read_bit()  # output_flag_present_flag
    reader.read_bits(3)  # num_extra_slice_header_bits
    reader.read_bit()  # sign_data_hiding_enabled_flag
    reader.read_bit()  # cabac_init_present_flag
    reader.read_ue()  # num_ref_idx_l0_default_active_minus1
    reader.read_ue()  # num_ref_idx_l1_default_active_minus1
    reader.read_se()  # init_qp_minus26
    reader.read_bit()  # constrained_intra_pred_flag
    reader.read_bit()  # transform_skip_enabled_flag
    cu_qp_delta = reader.read_bit()  # cu_qp_delta_enabled_flag
    if cu_qp_delta:
        reader.read_ue()  # diff_cu_qp_delta_depth
    reader.read_se()  # pps_cb_qp_offset
    reader.read_se()  # pps_cr_qp_offset
    reader.read_bit()  # pps_slice_chroma_qp_offsets_present_flag
    reader.read_bit()  # weighted_pred_flag
    reader.read_bit()  # weighted_bipred_flag
    reader.read_bit()  # transquant_bypass_enabled_flag

    tiles_off = reader.bit_position
    tiles_enabled = reader.read_bit()
    spans.append(FieldSpan("tiles_enabled_flag", tiles_off, 1, tiles_enabled))

    esync_off = reader.bit_position
    entropy_sync = reader.read_bit()
    spans.append(
        FieldSpan("entropy_coding_sync_enabled_flag", esync_off, 1, entropy_sync)
    )

    return PicParameterSet(
        pps_pic_parameter_set_id=pps_id,
        pps_seq_parameter_set_id=sps_id,
        tiles_enabled_flag=tiles_enabled,
        entropy_coding_sync_enabled_flag=entropy_sync,
        spans=spans,
    )


@dataclass
class SliceHeader:
    """Minimally-parsed slice segment header, exposing early field spans.

    For v0.1 the slice-header mutator targets the ``first_slice_segment_in_pic``
    and ``slice_pic_parameter_set_id`` region plus the slice type, which together
    drive reference-picture-list interpretation. We expose those spans.
    """

    first_slice_segment_in_pic_flag: int
    slice_pic_parameter_set_id: int
    spans: list[FieldSpan] = field(default_factory=list)

    def span(self, name: str) -> FieldSpan:
        for s in self.spans:
            if s.name == name:
                return s
        raise KeyError(name)


def parse_slice_header(rbsp: bytes, nal_unit_type: int) -> SliceHeader:
    """Parse the front of a slice segment header.

    ``rbsp`` is the slice payload without the NAL header, emulation bytes removed.
    We stop after ``slice_pic_parameter_set_id`` — deeper parsing requires SPS/PPS
    context we deliberately avoid for v0.1's structured-mutation scope.
    """
    reader = BitReader(rbsp)
    spans: list[FieldSpan] = []

    first_off = reader.bit_position
    first_slice = reader.read_bit()
    spans.append(FieldSpan("first_slice_segment_in_pic_flag", first_off, 1, first_slice))

    # no_output_of_prior_pics_flag present for IRAP NAL types [16, 23].
    if 16 <= nal_unit_type <= 23:
        reader.read_bit()

    ppsid_off = reader.bit_position
    pps_id = reader.read_ue()
    spans.append(
        FieldSpan(
            "slice_pic_parameter_set_id",
            ppsid_off,
            reader.bit_position - ppsid_off,
            pps_id,
        )
    )

    return SliceHeader(
        first_slice_segment_in_pic_flag=first_slice,
        slice_pic_parameter_set_id=pps_id,
        spans=spans,
    )


def splice_ue_field(rbsp: bytes, span: FieldSpan, new_value: int) -> bytes:
    """Return a new RBSP with the ue(v) field at ``span`` replaced by new_value.

    The surrounding bits are preserved exactly; only the field's bit span is
    re-encoded, so total length may change if the Exp-Golomb code length differs.
    """
    reader = BitReader(rbsp)
    writer = BitWriter()
    # Copy bits before the field verbatim.
    for _ in range(span.bit_offset):
        writer.write_bit(reader.read_bit())
    # Skip the old field (reader is now at the field start), write the new one.
    reader.read_bits(span.bit_length)
    writer.write_ue(new_value)
    # Copy the remaining bits verbatim.
    total_bits = len(rbsp) * 8
    while reader.bit_position < total_bits:
        writer.write_bit(reader.read_bit())
    return writer.to_bytes()


def splice_fixed_bits(rbsp: bytes, bit_offset: int, bit_length: int, new_value: int) -> bytes:
    """Return a new RBSP with ``bit_length`` bits at ``bit_offset`` replaced."""
    reader = BitReader(rbsp)
    writer = BitWriter()
    for _ in range(bit_offset):
        writer.write_bit(reader.read_bit())
    reader.read_bits(bit_length)  # discard old
    writer.write_bits(new_value, bit_length)
    total_bits = len(rbsp) * 8
    while reader.bit_position < total_bits:
        writer.write_bit(reader.read_bit())
    return writer.to_bytes()
