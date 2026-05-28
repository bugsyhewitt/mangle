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
class ShortTermRps:
    """One short-term reference-picture set, parsed from an ``st_ref_pic_set()``.

    Only the ``stRpsIdx == 0`` form (no inter-RPS prediction) is modelled, which
    is the form mangle's RPS mutator constructs and the most common in seeds.
    """

    num_negative_pics: int
    num_positive_pics: int
    delta_poc_s0_minus1: list[int] = field(default_factory=list)
    used_by_curr_pic_s0_flag: list[int] = field(default_factory=list)
    delta_poc_s1_minus1: list[int] = field(default_factory=list)
    used_by_curr_pic_s1_flag: list[int] = field(default_factory=list)


@dataclass
class LongTermRefPic:
    """One long-term reference picture entry from the SPS long-term RPS block."""

    poc_lsb_lt: int
    used_by_curr_pic_lt_sps_flag: int


@dataclass
class SeqParameterSet:
    """A minimally-parsed HEVC SPS exposing dimension and RPS field spans.

    In addition to the v0.1 dimension spans, the parser advances all the way to
    the reference-picture-set region (H.265 7.3.2.2.1) so RPS mutators can locate
    and rewrite it. The fields needed for RPS mutation are recorded:

      * ``sps_max_dec_pic_buffering_minus1`` — the DPB-size bound that
        ``num_negative_pics``/``num_positive_pics`` must exceed to overflow DPB
        index arrays.
      * ``log2_max_pic_order_cnt_lsb_minus4`` — sets the ``poc_lsb_lt`` field
        width, needed to encode long-term POC LSB entries.
      * ``num_short_term_ref_pic_sets`` and its bit offset / following tail bits,
        so a synthesised ``st_ref_pic_set()`` can be spliced in.
      * ``long_term_ref_pics_present_flag`` and its bit offset / following tail
        bits, so a synthesised long-term RPS block can be spliced in.
    """

    sps_video_parameter_set_id: int
    sps_max_sub_layers_minus1: int
    chroma_format_idc: int
    pic_width_in_luma_samples: int
    pic_height_in_luma_samples: int
    spans: list[FieldSpan] = field(default_factory=list)
    # separate_colour_plane_flag is present in the bitstream only when
    # chroma_format_idc == 3; None means "not present in this SPS".
    separate_colour_plane_flag: int | None = None
    # Bit-depth fields (None if the SPS could not be parsed that far).
    bit_depth_luma_minus8: int | None = None
    bit_depth_chroma_minus8: int | None = None
    # RPS-relevant fields (None if SPS could not be parsed that far).
    sps_max_dec_pic_buffering_minus1: list[int] = field(default_factory=list)
    log2_max_pic_order_cnt_lsb_minus4: int | None = None
    num_short_term_ref_pic_sets: int | None = None
    long_term_ref_pics_present_flag: int | None = None
    short_term_rps: list[ShortTermRps] = field(default_factory=list)
    long_term_ref_pics: list[LongTermRefPic] = field(default_factory=list)

    def span(self, name: str) -> FieldSpan:
        for s in self.spans:
            if s.name == name:
                return s
        raise KeyError(name)

    def has_span(self, name: str) -> bool:
        return any(s.name == name for s in self.spans)


def _parse_short_term_rps(reader: BitReader, st_rps_idx: int) -> ShortTermRps:
    """Parse one ``st_ref_pic_set()`` (H.265 7.3.7).

    Only the non-inter-predicted form is modelled. For ``st_rps_idx > 0`` an
    ``inter_ref_pic_set_prediction_flag`` precedes the block; we read it and bail
    to the explicit form when it is 0 (the inter-predicted form is not modelled).
    """
    if st_rps_idx != 0:
        inter_flag = reader.read_bit()
        if inter_flag:
            raise ValueError(
                "inter-predicted short-term RPS not modelled by mangle's parser"
            )
    num_negative = reader.read_ue()
    num_positive = reader.read_ue()
    rps = ShortTermRps(num_negative_pics=num_negative, num_positive_pics=num_positive)
    for _ in range(num_negative):
        rps.delta_poc_s0_minus1.append(reader.read_ue())
        rps.used_by_curr_pic_s0_flag.append(reader.read_bit())
    for _ in range(num_positive):
        rps.delta_poc_s1_minus1.append(reader.read_ue())
        rps.used_by_curr_pic_s1_flag.append(reader.read_bit())
    return rps


@dataclass
class VideoParameterSet:
    """A minimally-parsed HEVC VPS exposing layer/sublayer field spans.

    Parses the VPS RBSP (H.265 §7.3.2.1) through the first 16 bits of fixed-
    width fields that control per-layer loop bounds and temporal-nesting
    validation in both software and hardware decoders.
    """

    vps_id: int
    vps_max_layers_minus1: int
    vps_max_sub_layers_minus1: int
    vps_temporal_id_nesting_flag: int
    spans: list[FieldSpan] = field(default_factory=list)

    def span(self, name: str) -> FieldSpan:
        for s in self.spans:
            if s.name == name:
                return s
        raise KeyError(name)


def parse_vps(rbsp: bytes) -> VideoParameterSet:
    """Parse a VPS RBSP through the first 16 fixed-width bits.

    ``rbsp`` must be the VPS NAL payload *without* the 2-byte NAL header and
    *with* emulation-prevention bytes already removed.

    Fields parsed (H.265 §7.3.2.1):
      - vps_video_parameter_set_id  (4 bits)
      - vps_base_layer_internal_flag (1 bit)  — skipped, not mutated
      - vps_base_layer_available_flag (1 bit)  — skipped, not mutated
      - vps_max_layers_minus1        (6 bits, spec range 0..62)
      - vps_max_sub_layers_minus1    (3 bits, spec range 0..6)
      - vps_temporal_id_nesting_flag (1 bit)
    """
    reader = BitReader(rbsp)
    spans: list[FieldSpan] = []

    vps_id = reader.read_bits(4)  # vps_video_parameter_set_id
    reader.read_bit()             # vps_base_layer_internal_flag (skip)
    reader.read_bit()             # vps_base_layer_available_flag (skip)

    layers_off = reader.bit_position
    max_layers = reader.read_bits(6)  # vps_max_layers_minus1
    spans.append(FieldSpan("vps_max_layers_minus1", layers_off, 6, max_layers))

    sub_layers_off = reader.bit_position
    max_sub_layers = reader.read_bits(3)  # vps_max_sub_layers_minus1
    spans.append(
        FieldSpan("vps_max_sub_layers_minus1", sub_layers_off, 3, max_sub_layers)
    )

    nesting_off = reader.bit_position
    nesting_flag = reader.read_bit()  # vps_temporal_id_nesting_flag
    spans.append(
        FieldSpan("vps_temporal_id_nesting_flag", nesting_off, 1, nesting_flag)
    )

    return VideoParameterSet(
        vps_id=vps_id,
        vps_max_layers_minus1=max_layers,
        vps_max_sub_layers_minus1=max_sub_layers,
        vps_temporal_id_nesting_flag=nesting_flag,
        spans=spans,
    )


def parse_sps(rbsp: bytes) -> SeqParameterSet:
    """Parse an SPS RBSP through to the reference-picture-set region.

    ``rbsp`` must be the SPS NAL payload *without* the 2-byte NAL header and
    *with* emulation-prevention bytes already removed.

    Parsing proceeds in two stages. The first stage (always succeeds for a valid
    SPS) records the dimension spans v0.1 relies on. The second stage advances
    through the conformance window, bit-depths, DPB sizing and coding-block
    geometry to reach ``num_short_term_ref_pic_sets`` and the long-term-RPS flag.
    If the SPS is too truncated or uses syntax mangle does not model, the RPS
    fields are left as ``None`` and only the dimension view is returned.
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
    separate_colour_plane_flag: int | None = None
    if chroma_format_idc == 3:
        separate_colour_plane_flag = reader.read_bit()  # separate_colour_plane_flag

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

    sps = SeqParameterSet(
        sps_video_parameter_set_id=vps_id,
        sps_max_sub_layers_minus1=max_sub_layers_minus1,
        chroma_format_idc=chroma_format_idc,
        pic_width_in_luma_samples=width,
        pic_height_in_luma_samples=height,
        spans=[chroma_span, width_span, height_span],
        separate_colour_plane_flag=separate_colour_plane_flag,
    )

    # Second stage: advance to the RPS region. Any parse error here leaves the
    # RPS fields unset but keeps the dimension view intact.
    try:
        conformance_window_flag = reader.read_bit()
        if conformance_window_flag:
            reader.read_ue()  # conf_win_left_offset
            reader.read_ue()  # conf_win_right_offset
            reader.read_ue()  # conf_win_top_offset
            reader.read_ue()  # conf_win_bottom_offset
        bd_luma_off = reader.bit_position
        bd_luma = reader.read_ue()  # bit_depth_luma_minus8
        sps.bit_depth_luma_minus8 = bd_luma
        sps.spans.append(
            FieldSpan(
                "bit_depth_luma_minus8",
                bd_luma_off,
                reader.bit_position - bd_luma_off,
                bd_luma,
            )
        )

        bd_chroma_off = reader.bit_position
        bd_chroma = reader.read_ue()  # bit_depth_chroma_minus8
        sps.bit_depth_chroma_minus8 = bd_chroma
        sps.spans.append(
            FieldSpan(
                "bit_depth_chroma_minus8",
                bd_chroma_off,
                reader.bit_position - bd_chroma_off,
                bd_chroma,
            )
        )

        log2_max_poc_off = reader.bit_position
        log2_max_poc = reader.read_ue()  # log2_max_pic_order_cnt_lsb_minus4
        sps.log2_max_pic_order_cnt_lsb_minus4 = log2_max_poc
        sps.spans.append(
            FieldSpan(
                "log2_max_pic_order_cnt_lsb_minus4",
                log2_max_poc_off,
                reader.bit_position - log2_max_poc_off,
                log2_max_poc,
            )
        )

        sub_layer_ordering = reader.read_bit()  # sub_layer_ordering_info_present
        start = 0 if sub_layer_ordering else max_sub_layers_minus1
        dpb: list[int] = []
        for _ in range(start, max_sub_layers_minus1 + 1):
            dpb.append(reader.read_ue())  # sps_max_dec_pic_buffering_minus1[i]
            reader.read_ue()  # sps_max_num_reorder_pics[i]
            reader.read_ue()  # sps_max_latency_increase_plus1[i]
        sps.sps_max_dec_pic_buffering_minus1 = dpb

        reader.read_ue()  # log2_min_luma_coding_block_size_minus3
        reader.read_ue()  # log2_diff_max_min_luma_coding_block_size
        reader.read_ue()  # log2_min_luma_transform_block_size_minus2
        reader.read_ue()  # log2_diff_max_min_luma_transform_block_size
        reader.read_ue()  # max_transform_hierarchy_depth_inter
        reader.read_ue()  # max_transform_hierarchy_depth_intra
        scaling_list_enabled = reader.read_bit()
        if scaling_list_enabled:
            # sps_scaling_list_data_present_flag + optional scaling_list_data()
            # is variable-length and not modelled; bail out cleanly.
            raise ValueError("scaling_list_data present; RPS region not reached")
        reader.read_bit()  # amp_enabled_flag
        reader.read_bit()  # sample_adaptive_offset_enabled_flag
        pcm_enabled = reader.read_bit()
        if pcm_enabled:
            reader.read_bits(4)  # pcm_sample_bit_depth_luma_minus1
            reader.read_bits(4)  # pcm_sample_bit_depth_chroma_minus1
            reader.read_ue()  # log2_min_pcm_luma_coding_block_size_minus3
            reader.read_ue()  # log2_diff_max_min_pcm_luma_coding_block_size
            reader.read_bit()  # pcm_loop_filter_disabled_flag

        num_st_off = reader.bit_position
        num_st = reader.read_ue()  # num_short_term_ref_pic_sets
        sps.num_short_term_ref_pic_sets = num_st
        sps.spans.append(
            FieldSpan(
                "num_short_term_ref_pic_sets",
                num_st_off,
                reader.bit_position - num_st_off,
                num_st,
            )
        )
        for i in range(num_st):
            sps.short_term_rps.append(_parse_short_term_rps(reader, i))

        lt_off = reader.bit_position
        lt_present = reader.read_bit()  # long_term_ref_pics_present_flag
        sps.long_term_ref_pics_present_flag = lt_present
        sps.spans.append(
            FieldSpan("long_term_ref_pics_present_flag", lt_off, 1, lt_present)
        )
        if lt_present:
            num_lt = reader.read_ue()  # num_long_term_ref_pics_sps
            poc_bits = log2_max_poc + 4
            for _ in range(num_lt):
                poc_lsb = reader.read_bits(poc_bits)  # lt_ref_pic_poc_lsb_sps
                used = reader.read_bit()  # used_by_curr_pic_lt_sps_flag
                sps.long_term_ref_pics.append(LongTermRefPic(poc_lsb, used))
    except (EOFError, ValueError):
        # Leave whatever RPS fields we managed to fill; dimension view stands.
        pass

    return sps


@dataclass
class PicParameterSet:
    """A minimally-parsed HEVC PPS exposing tile-config and deblocking spans.

    In addition to the v0.1 tile-config spans, the parser advances past the
    (optional) tile-geometry block to the deblocking-filter control region
    (H.265 §7.3.2.3) so the deblocking mutator can locate and rewrite it. The
    fields needed for deblocking mutation are recorded when reached:

      * ``pps_loop_filter_across_slices_enabled_flag`` — u(1) loop-filter scope
        flag; flipping it changes cross-slice filtering behaviour.
      * ``deblocking_filter_control_present_flag`` — u(1) gate for the override /
        disable / beta-tc offset syntax that follows.
      * ``deblocking_filter_override_enabled_flag``,
        ``pps_deblocking_filter_disabled_flag`` — u(1) each, present only when the
        control flag is set.
      * ``pps_beta_offset_div2`` / ``pps_tc_offset_div2`` — se(v), valid range
        [-6, 6]; present only when control is set and disable is off.

    Any field not reached (e.g. tiles enabled → variable geometry, or a truncated
    PPS) is simply absent from ``spans`` and its attribute left ``None``.
    """

    pps_pic_parameter_set_id: int
    pps_seq_parameter_set_id: int
    tiles_enabled_flag: int
    entropy_coding_sync_enabled_flag: int
    spans: list[FieldSpan] = field(default_factory=list)
    # Deblocking-filter region (None if the parser did not reach it).
    pps_loop_filter_across_slices_enabled_flag: int | None = None
    deblocking_filter_control_present_flag: int | None = None
    deblocking_filter_override_enabled_flag: int | None = None
    pps_deblocking_filter_disabled_flag: int | None = None
    pps_beta_offset_div2: int | None = None
    pps_tc_offset_div2: int | None = None

    def span(self, name: str) -> FieldSpan:
        for s in self.spans:
            if s.name == name:
                return s
        raise KeyError(name)

    def has_span(self, name: str) -> bool:
        return any(s.name == name for s in self.spans)


def parse_pps(rbsp: bytes) -> PicParameterSet:
    """Parse a PPS RBSP through to the deblocking-filter control region.

    ``rbsp`` is the PPS payload without the NAL header, emulation bytes removed.

    The first stage (always succeeds for a valid PPS) records the tile-config
    spans v0.1 relies on. The second stage advances past the optional tile
    geometry to the deblocking-filter control fields (H.265 §7.3.2.3). If tiles
    are enabled — the geometry is variable and not modelled — or the PPS is
    truncated, the deblocking fields are left ``None`` and only the tile-config
    view is returned.
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

    pps = PicParameterSet(
        pps_pic_parameter_set_id=pps_id,
        pps_seq_parameter_set_id=sps_id,
        tiles_enabled_flag=tiles_enabled,
        entropy_coding_sync_enabled_flag=entropy_sync,
        spans=spans,
    )

    # Second stage: advance to the deblocking-filter control region. Any parse
    # error here leaves the deblocking fields unset but keeps the tile view.
    try:
        if tiles_enabled:
            # Tile geometry (num_tile_columns_minus1 etc.) is variable-length and
            # not modelled; bail cleanly, leaving deblocking fields unset.
            raise ValueError("tiles enabled; deblocking region not modelled")

        lf_off = reader.bit_position
        lf_across = reader.read_bit()  # pps_loop_filter_across_slices_enabled_flag
        pps.pps_loop_filter_across_slices_enabled_flag = lf_across
        pps.spans.append(
            FieldSpan("pps_loop_filter_across_slices_enabled_flag", lf_off, 1, lf_across)
        )

        ctl_off = reader.bit_position
        ctl_present = reader.read_bit()  # deblocking_filter_control_present_flag
        pps.deblocking_filter_control_present_flag = ctl_present
        pps.spans.append(
            FieldSpan("deblocking_filter_control_present_flag", ctl_off, 1, ctl_present)
        )

        if ctl_present:
            ovr_off = reader.bit_position
            override = reader.read_bit()  # deblocking_filter_override_enabled_flag
            pps.deblocking_filter_override_enabled_flag = override
            pps.spans.append(
                FieldSpan("deblocking_filter_override_enabled_flag", ovr_off, 1, override)
            )

            dis_off = reader.bit_position
            disabled = reader.read_bit()  # pps_deblocking_filter_disabled_flag
            pps.pps_deblocking_filter_disabled_flag = disabled
            pps.spans.append(
                FieldSpan("pps_deblocking_filter_disabled_flag", dis_off, 1, disabled)
            )

            if not disabled:
                beta_off = reader.bit_position
                beta = reader.read_se()  # pps_beta_offset_div2
                pps.pps_beta_offset_div2 = beta
                pps.spans.append(
                    FieldSpan(
                        "pps_beta_offset_div2",
                        beta_off,
                        reader.bit_position - beta_off,
                        beta,
                    )
                )

                tc_off = reader.bit_position
                tc = reader.read_se()  # pps_tc_offset_div2
                pps.pps_tc_offset_div2 = tc
                pps.spans.append(
                    FieldSpan(
                        "pps_tc_offset_div2",
                        tc_off,
                        reader.bit_position - tc_off,
                        tc,
                    )
                )
    except (EOFError, ValueError):
        # Leave whatever deblocking fields we filled; tile view stands.
        pass

    return pps


def splice_se_field(rbsp: bytes, span: FieldSpan, new_value: int) -> bytes:
    """Return a new RBSP with the se(v) field at ``span`` replaced by new_value.

    The surrounding bits are preserved exactly; only the field's bit span is
    re-encoded, so total length may change if the signed Exp-Golomb code length
    differs.
    """
    reader = BitReader(rbsp)
    writer = BitWriter()
    for _ in range(span.bit_offset):
        writer.write_bit(reader.read_bit())
    reader.read_bits(span.bit_length)  # discard the old field
    writer.write_se(new_value)
    total_bits = len(rbsp) * 8
    while reader.bit_position < total_bits:
        writer.write_bit(reader.read_bit())
    return writer.to_bytes()


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


@dataclass
class SeiMessage:
    """One SEI message located within a SEI NAL RBSP.

    Attributes:
        payload_type: SEI payloadType value (e.g. 0=buffering_period, 1=pic_timing, 6=recovery_point).
        payload_offset: byte offset where the payload data starts within the RBSP
            (i.e. after the payloadType and payloadSize length-prefix bytes).
        payload_size: number of bytes in the payload (as declared by the SEI message header).
    """

    payload_type: int
    payload_offset: int
    payload_size: int


def parse_sei(rbsp: bytes) -> list[SeiMessage]:
    """Parse a SEI NAL RBSP into a list of SEI messages.

    ``rbsp`` must be the SEI NAL payload *without* the 2-byte NAL header and
    *with* emulation-prevention bytes already removed.

    The SEI message framing (H.265 §7.3.2.4) uses a variable-length prefix for
    both payloadType and payloadSize: a sequence of 0xFF bytes accumulates 255
    each, and the final non-0xFF byte contributes its value to the total.

    Parsing stops at the RBSP trailing bits marker (the 0x80 alignment byte at
    the end of the RBSP), or when there are no more full messages to read.
    Returns a list of :class:`SeiMessage` in order of appearance.
    """
    messages: list[SeiMessage] = []
    pos = 0
    n = len(rbsp)

    while pos < n:
        # RBSP trailing bits: a 0x80 byte (stop bit + zero-padding) signals end.
        if rbsp[pos] == 0x80:
            break

        # Decode payloadType
        payload_type = 0
        while pos < n and rbsp[pos] == 0xFF:
            payload_type += 255
            pos += 1
        if pos >= n:
            break
        payload_type += rbsp[pos]
        pos += 1

        # Decode payloadSize
        payload_size = 0
        while pos < n and rbsp[pos] == 0xFF:
            payload_size += 255
            pos += 1
        if pos >= n:
            break
        payload_size += rbsp[pos]
        pos += 1

        # Record the payload start offset
        payload_offset = pos
        messages.append(SeiMessage(
            payload_type=payload_type,
            payload_offset=payload_offset,
            payload_size=payload_size,
        ))

        # Advance past the payload bytes
        pos += payload_size

    return messages


def splice_replace_region(
    rbsp: bytes,
    prefix_bits: int,
    old_region_bits: int,
    writer_fn,
) -> bytes:
    """Replace the ``old_region_bits`` bits after ``prefix_bits`` with new bits.

    The first ``prefix_bits`` bits of ``rbsp`` are copied verbatim, ``writer_fn``
    is invoked with a :class:`BitWriter` to emit the replacement region, the next
    ``old_region_bits`` bits of the original are discarded, and the remaining tail
    is copied verbatim. This lets a mutator splice in a variable-length syntax
    block (e.g. a synthesised ``st_ref_pic_set()``) without disturbing the rest of
    the parameter set.
    """
    reader = BitReader(rbsp)
    writer = BitWriter()
    for _ in range(prefix_bits):
        writer.write_bit(reader.read_bit())
    writer_fn(writer)
    reader.read_bits(old_region_bits)  # discard the region we are replacing
    total_bits = len(rbsp) * 8
    while reader.bit_position < total_bits:
        writer.write_bit(reader.read_bit())
    return writer.to_bytes()
