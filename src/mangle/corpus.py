"""Multi-seed corpus builder (POST_V01 item #4).

Coverage-guided and manual fuzzing campaigns benefit from a diverse, compact
seed corpus rather than a single point in the input space. mangle v0.1 shipped
only one seed (``tests/fixtures/clean.h265``); this module derives a spread of
distinct, still-well-framed seeds from one input file, covering:

  * distinct SPS dimension classes (a boundary set of widths × heights),
  * distinct chroma formats (where the seed's SPS permits the rewrite),
  * incomplete-parameter-set streams (VPS-only / SPS-only / PPS-only NALs),
  * a non-IRAP-first NAL ordering (a trailing slice moved before the IRAP).

The builder never hand-rolls a parameter set: it reuses the existing bitstream
assembly layer (:func:`assemble_nal_units`) and the SPS splice functions
(:func:`splice_ue_field`) so every emitted seed shares the seed file's valid
framing and only the targeted field differs. Seeds whose rewrite cannot be
applied to the given input (e.g. a chroma rewrite on an SPS that does not parse
to ``chroma_format_idc``) are skipped and recorded in the manifest, not faked.

References: ITU-T H.265 §7.3.2 (parameter sets). The boundary dimension set
follows the TWINFUZZ / FuzzWise observation that a few well-chosen boundary
seeds outperform thousands of random ones.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from .bitstream import (
    NalUnit,
    assemble_nal_units,
    ebsp_to_rbsp,
    rbsp_to_ebsp,
    split_nal_units,
)
from .hevc import parse_sps, splice_fixed_bits, splice_ue_field

# Boundary dimension set: 1 (degenerate), 2 (sub-CTB), 16 (one CTB row), 64
# (the seed's typical size), 256, 4096 (4K-ish), 65535 (ue(v) extreme). These
# exercise tiny, typical, large, and overflow-prone buffer-sizing paths.
DIMENSION_BOUNDARIES: tuple[int, ...] = (1, 2, 16, 64, 256, 4096, 65535)

# chroma_format_idc values worth covering: 0=monochrome, 1=4:2:0 (typical),
# 2=4:2:2, 3=4:4:4. We only rewrite when the seed SPS parses to the field and
# the rewrite does not require the variable separate_colour_plane_flag bit that
# follows chroma_format_idc == 3 (writing 3 over a non-3 value would desync the
# following bits; that inconsistency is the sps-chroma-format *mutator's* job,
# not the corpus builder's, which keeps seeds well-framed).
CHROMA_FORMATS: tuple[int, ...] = (0, 1, 2)


@dataclass
class CorpusEntry:
    """One corpus seed (emitted) or one skipped seed (not emitted).

    Attributes:
        index: zero-padded ordinal in filename order.
        descriptor: short slug describing the seed class (used in the filename).
        filename: the written file name, or ``None`` when ``skipped`` is set.
        strategy: which generation strategy produced (or would have produced) it.
        detail: human-readable note about the seed's distinguishing property.
        bytes: size of the written seed, or 0 when skipped.
        skipped: reason the seed could not be produced, or ``None`` if emitted.
    """

    index: int
    descriptor: str
    filename: str | None
    strategy: str
    detail: str
    bytes: int
    skipped: str | None = None


def _sps_index(nals: list[NalUnit]) -> int | None:
    for i, n in enumerate(nals):
        if n.nal_unit_type == 33:  # SPS_NUT
            return i
    return None


def _nals_of_type(nals: list[NalUnit], nal_type: int) -> list[NalUnit]:
    return [n for n in nals if n.nal_unit_type == nal_type]


def _rewrite_sps_payload(nal: NalUnit, new_rbsp: bytes) -> NalUnit:
    """Rebuild an SPS NAL from a new RBSP payload, keeping its 2-byte header."""
    header = nal.ebsp[:2]
    return NalUnit(nal.start_code_len, nal.offset, header + rbsp_to_ebsp(new_rbsp))


def _dimension_seeds(
    nals: list[NalUnit], sps_idx: int, start_index: int
) -> tuple[list[tuple[str, str, str, bytes]], list[CorpusEntry]]:
    """Build width×height boundary seeds. Returns (emitted, skipped)."""
    emitted: list[tuple[str, str, str, bytes]] = []
    skipped: list[CorpusEntry] = []

    rbsp = ebsp_to_rbsp(nals[sps_idx].ebsp[2:])
    sps = parse_sps(rbsp)
    try:
        width_span = sps.span("pic_width_in_luma_samples")
        height_span = sps.span("pic_height_in_luma_samples")
    except KeyError:
        skipped.append(
            CorpusEntry(
                index=start_index,
                descriptor="dims",
                filename=None,
                strategy="dimensions",
                detail="SPS did not parse to width/height spans",
                bytes=0,
                skipped="no_dimension_spans",
            )
        )
        return emitted, skipped

    for width in DIMENSION_BOUNDARIES:
        for height in DIMENSION_BOUNDARIES:
            # Re-parse per iteration: splicing width changes later bit offsets,
            # so we always splice height off the width-spliced RBSP using a fresh
            # parse to get the shifted height span.
            w_rbsp = splice_ue_field(rbsp, width_span, width)
            w_sps = parse_sps(w_rbsp)
            try:
                h_span = w_sps.span("pic_height_in_luma_samples")
            except KeyError:
                # Should not happen for a seed that parsed once, but be safe.
                continue
            seed_rbsp = splice_ue_field(w_rbsp, h_span, height)
            out = list(nals)
            out[sps_idx] = _rewrite_sps_payload(nals[sps_idx], seed_rbsp)
            data = assemble_nal_units(out)
            emitted.append(
                (
                    "dims",
                    "dimensions",
                    f"{width}x{height}",
                    data,
                )
            )
    return emitted, skipped


def _chroma_seeds(
    nals: list[NalUnit], sps_idx: int
) -> tuple[list[tuple[str, str, str, bytes]], list[CorpusEntry]]:
    """Build chroma-format seeds where the SPS permits a clean in-place rewrite."""
    emitted: list[tuple[str, str, str, bytes]] = []
    skipped: list[CorpusEntry] = []

    rbsp = ebsp_to_rbsp(nals[sps_idx].ebsp[2:])
    sps = parse_sps(rbsp)
    try:
        chroma_span = sps.span("chroma_format_idc")
    except KeyError:
        skipped.append(
            CorpusEntry(
                index=-1,
                descriptor="chroma",
                filename=None,
                strategy="chroma",
                detail="SPS did not parse to chroma_format_idc",
                bytes=0,
                skipped="no_chroma_span",
            )
        )
        return emitted, skipped

    for chroma in CHROMA_FORMATS:
        if chroma == chroma_span.value:
            continue  # identical to seed; no new coverage
        # chroma_format_idc is ue(v); rewriting among {0,1,2} never introduces or
        # removes the separate_colour_plane_flag bit (which is present only for
        # value 3), so the following bits stay aligned and the seed stays valid.
        seed_rbsp = splice_ue_field(rbsp, chroma_span, chroma)
        out = list(nals)
        out[sps_idx] = _rewrite_sps_payload(nals[sps_idx], seed_rbsp)
        data = assemble_nal_units(out)
        emitted.append(("chroma", "chroma", f"idc{chroma}", data))
    return emitted, skipped


def _incomplete_param_set_seeds(
    nals: list[NalUnit],
) -> tuple[list[tuple[str, str, str, bytes]], list[CorpusEntry]]:
    """VPS-only / SPS-only / PPS-only single-NAL streams."""
    emitted: list[tuple[str, str, str, bytes]] = []
    skipped: list[CorpusEntry] = []

    for nal_type, slug in ((32, "vps-only"), (33, "sps-only"), (34, "pps-only")):
        members = _nals_of_type(nals, nal_type)
        if not members:
            skipped.append(
                CorpusEntry(
                    index=-1,
                    descriptor=slug,
                    filename=None,
                    strategy="incomplete-param-set",
                    detail=f"seed has no NAL of type {nal_type}",
                    bytes=0,
                    skipped="nal_type_absent",
                )
            )
            continue
        data = assemble_nal_units([members[0]])
        emitted.append(("incomplete-param-set", "incomplete-param-set", slug, data))
    return emitted, skipped


def _nal_ordering_seed(
    nals: list[NalUnit],
) -> tuple[list[tuple[str, str, str, bytes]], list[CorpusEntry]]:
    """A seed with a non-IRAP VCL NAL placed before the first IRAP VCL NAL.

    IRAP NAL types are [16, 23] (BLA/IDR/CRA). A decoder expects an IRAP to lead
    a coded video sequence; presenting a trailing (non-IRAP) slice first
    exercises the "missing reference" / "no prior IRAP" paths.
    """
    emitted: list[tuple[str, str, str, bytes]] = []
    skipped: list[CorpusEntry] = []

    irap_pos = next(
        (i for i, n in enumerate(nals) if 16 <= n.nal_unit_type <= 23), None
    )
    non_irap_pos = next(
        (i for i, n in enumerate(nals) if n.is_vcl and not (16 <= n.nal_unit_type <= 23)),
        None,
    )
    if irap_pos is None or non_irap_pos is None or non_irap_pos < irap_pos:
        skipped.append(
            CorpusEntry(
                index=-1,
                descriptor="non-irap-first",
                filename=None,
                strategy="nal-ordering",
                detail="seed lacks both an IRAP and a later non-IRAP VCL NAL",
                bytes=0,
                skipped="no_reorderable_vcl_pair",
            )
        )
        return emitted, skipped

    reordered = list(nals)
    moved = reordered.pop(non_irap_pos)
    reordered.insert(irap_pos, moved)
    data = assemble_nal_units(reordered)
    emitted.append(("nal-ordering", "nal-ordering", "non-irap-first", data))
    return emitted, skipped


def build_corpus(seed_path: str | Path, output_dir: str | Path) -> list[CorpusEntry]:
    """Generate a diverse seed corpus from one seed file into ``output_dir``.

    Writes ``<index>-<descriptor>.h265`` files plus a ``manifest.json`` that
    records every emitted and skipped seed. Returns the list of all entries
    (emitted and skipped) in deterministic order.

    The corpus is fully deterministic for a given seed file — no RNG is used.
    """
    seed_bytes = Path(seed_path).read_bytes()
    nals = split_nal_units(seed_bytes)
    if not nals:
        raise ValueError(f"seed {seed_path} contains no NAL units")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    sps_idx = _sps_index(nals)

    produced: list[tuple[str, str, str, bytes]] = []
    skips: list[CorpusEntry] = []

    if sps_idx is not None:
        dim_emit, dim_skip = _dimension_seeds(nals, sps_idx, start_index=0)
        produced += dim_emit
        skips += dim_skip
        chroma_emit, chroma_skip = _chroma_seeds(nals, sps_idx)
        produced += chroma_emit
        skips += chroma_skip
    else:
        skips.append(
            CorpusEntry(
                index=-1,
                descriptor="dims",
                filename=None,
                strategy="dimensions",
                detail="seed has no SPS NAL",
                bytes=0,
                skipped="no_sps",
            )
        )
        skips.append(
            CorpusEntry(
                index=-1,
                descriptor="chroma",
                filename=None,
                strategy="chroma",
                detail="seed has no SPS NAL",
                bytes=0,
                skipped="no_sps",
            )
        )

    inc_emit, inc_skip = _incomplete_param_set_seeds(nals)
    produced += inc_emit
    skips += inc_skip

    ord_emit, ord_skip = _nal_ordering_seed(nals)
    produced += ord_emit
    skips += ord_skip

    entries: list[CorpusEntry] = []
    width = max(2, len(str(len(produced))))
    for i, (strategy, _strat2, descriptor, data) in enumerate(produced):
        filename = f"{i:0{width}d}-{descriptor}.h265"
        (out_dir / filename).write_bytes(data)
        entries.append(
            CorpusEntry(
                index=i,
                descriptor=descriptor,
                filename=filename,
                strategy=strategy,
                detail=descriptor,
                bytes=len(data),
            )
        )

    # Re-index skipped entries after the emitted ones for a stable manifest.
    for j, skip in enumerate(skips):
        skip.index = len(entries) + j
        entries.append(skip)

    manifest = {
        "seed": str(seed_path),
        "emitted": len(produced),
        "skipped": len(skips),
        "entries": [asdict(e) for e in entries],
    }
    (out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    return entries
