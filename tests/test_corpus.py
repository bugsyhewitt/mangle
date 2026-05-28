"""Tests for the multi-seed corpus builder (POST_V01 item #4)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mangle.bitstream import (
    NalUnit,
    assemble_nal_units,
    ebsp_to_rbsp,
    split_nal_units,
)
from mangle.cli import main
from mangle.corpus import (
    CHROMA_FORMATS,
    DIMENSION_BOUNDARIES,
    build_corpus,
)
from mangle.hevc import parse_sps

SEED = Path(__file__).parent / "fixtures" / "clean.h265"


def _seed_sps_value(field_name: str) -> int:
    nals = split_nal_units(SEED.read_bytes())
    sps_nal = next(n for n in nals if n.nal_unit_type == 33)
    sps = parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))
    return sps.span(field_name).value


class TestCorpusGeneration:
    def test_emits_files_and_manifest(self, tmp_path):
        entries = build_corpus(SEED, tmp_path)
        assert entries, "expected at least one corpus entry"
        manifest_path = tmp_path / "manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["seed"] == str(SEED)
        assert manifest["emitted"] >= 1
        # Every emitted entry has a real file on disk.
        for entry in entries:
            if entry.skipped is None:
                assert (tmp_path / entry.filename).exists()
            else:
                assert entry.filename is None

    def test_dimension_seeds_cover_full_boundary_grid(self, tmp_path):
        build_corpus(SEED, tmp_path)
        produced = {p.name.split("-", 1)[1] for p in tmp_path.glob("*-*x*.h265")}
        expected = {
            f"{w}x{h}.h265"
            for w in DIMENSION_BOUNDARIES
            for h in DIMENSION_BOUNDARIES
        }
        assert produced == expected

    def test_dimension_seed_parses_to_requested_dimensions(self, tmp_path):
        build_corpus(SEED, tmp_path)
        target = next(tmp_path.glob("*-256x4096.h265"))
        nals = split_nal_units(target.read_bytes())
        sps_nal = next(n for n in nals if n.nal_unit_type == 33)
        sps = parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))
        assert sps.pic_width_in_luma_samples == 256
        assert sps.pic_height_in_luma_samples == 4096

    def test_chroma_seeds_exclude_seed_value(self, tmp_path):
        seed_chroma = _seed_sps_value("chroma_format_idc")
        build_corpus(SEED, tmp_path)
        emitted_chroma = set()
        for p in tmp_path.glob("*-idc*.h265"):
            idc = int(p.name.split("idc")[1].split(".")[0])
            emitted_chroma.add(idc)
            nals = split_nal_units(p.read_bytes())
            sps_nal = next(n for n in nals if n.nal_unit_type == 33)
            sps = parse_sps(ebsp_to_rbsp(sps_nal.ebsp[2:]))
            assert sps.chroma_format_idc == idc
        # The builder skips the seed's own value (no redundant seed) and only
        # emits from the {0,1,2} set it can rewrite without realigning bits.
        assert seed_chroma not in emitted_chroma
        assert emitted_chroma <= set(CHROMA_FORMATS)

    def test_incomplete_parameter_set_seeds_are_single_nal(self, tmp_path):
        build_corpus(SEED, tmp_path)
        for slug, nal_type in (
            ("vps-only", 32),
            ("sps-only", 33),
            ("pps-only", 34),
        ):
            matches = list(tmp_path.glob(f"*-{slug}.h265"))
            # The clean seed contains a VPS, SPS, and PPS, so all three emit.
            assert len(matches) == 1, slug
            nals = split_nal_units(matches[0].read_bytes())
            assert len(nals) == 1
            assert nals[0].nal_unit_type == nal_type

    def test_all_emitted_seeds_are_valid_annex_b(self, tmp_path):
        """Every emitted seed re-splits into the same byte stream it was written
        as — i.e. start-code framing is intact and NALs are well-formed."""
        entries = build_corpus(SEED, tmp_path)
        for entry in entries:
            if entry.skipped is not None:
                continue
            data = (tmp_path / entry.filename).read_bytes()
            nals = split_nal_units(data)
            assert nals, entry.filename
            assert assemble_nal_units(nals) == data

    def test_deterministic_output(self, tmp_path):
        dir_a = tmp_path / "a"
        dir_b = tmp_path / "b"
        build_corpus(SEED, dir_a)
        build_corpus(SEED, dir_b)
        files_a = sorted(p.name for p in dir_a.glob("*.h265"))
        files_b = sorted(p.name for p in dir_b.glob("*.h265"))
        assert files_a == files_b
        for name in files_a:
            assert (dir_a / name).read_bytes() == (dir_b / name).read_bytes()

    def test_manifest_records_skips_with_reasons(self, tmp_path):
        """The single-IDR clean seed has no reorderable VCL pair, so the
        non-IRAP-first ordering seed is skipped — and that skip is recorded,
        not silently dropped."""
        build_corpus(SEED, tmp_path)
        manifest = json.loads((tmp_path / "manifest.json").read_text())
        skips = [e for e in manifest["entries"] if e["skipped"] is not None]
        assert any(e["strategy"] == "nal-ordering" for e in skips)
        for e in skips:
            assert e["skipped"]  # non-empty reason code
            assert e["filename"] is None


class TestCorpusEdgeCases:
    def test_empty_seed_raises(self, tmp_path):
        empty = tmp_path / "empty.h265"
        empty.write_bytes(b"")
        with pytest.raises(ValueError):
            build_corpus(empty, tmp_path / "out")

    def test_seed_without_sps_skips_sps_dependent_strategies(self, tmp_path):
        """A stream with only a PPS NAL still produces the PPS-only incomplete
        seed but records skips for the dimension and chroma strategies."""
        nals = split_nal_units(SEED.read_bytes())
        pps = next(n for n in nals if n.nal_unit_type == 34)
        only_pps = assemble_nal_units([pps])
        seed = tmp_path / "pps-only-seed.h265"
        seed.write_bytes(only_pps)

        entries = build_corpus(seed, tmp_path / "out")
        emitted = [e for e in entries if e.skipped is None]
        skipped = [e for e in entries if e.skipped is not None]
        # The PPS-only incomplete-param-set seed is the one emitted artifact.
        assert any(e.descriptor == "pps-only" for e in emitted)
        skip_strategies = {e.strategy for e in skipped}
        assert "dimensions" in skip_strategies
        assert "chroma" in skip_strategies

    def test_non_irap_first_ordering_when_seed_has_a_pair(self, tmp_path):
        """When the seed has an IRAP followed by a non-IRAP VCL NAL, the
        ordering seed is emitted with the non-IRAP slice moved ahead."""
        nals = split_nal_units(SEED.read_bytes())
        irap = next(n for n in nals if 16 <= n.nal_unit_type <= 23)
        # Synthesise a trailing (TRAIL_R, type 1) VCL NAL after the IRAP by
        # cloning the IRAP payload under a non-IRAP header.
        trail_header = bytes([(1 << 1) & 0x7E, irap.ebsp[1]])
        trail = NalUnit(irap.start_code_len, 0, trail_header + irap.ebsp[2:])
        augmented = tmp_path / "augmented.h265"
        augmented.write_bytes(assemble_nal_units([*nals, trail]))

        entries = build_corpus(augmented, tmp_path / "out")
        ordering = [e for e in entries if e.strategy == "nal-ordering"]
        assert len(ordering) == 1
        assert ordering[0].skipped is None
        data = (tmp_path / "out" / ordering[0].filename).read_bytes()
        reordered = split_nal_units(data)
        first_vcl = next(n for n in reordered if n.is_vcl)
        assert not (16 <= first_vcl.nal_unit_type <= 23)


class TestCorpusCli:
    def test_cli_corpus_subcommand(self, tmp_path, capsys):
        out_dir = tmp_path / "corpus-out"
        rc = main(["corpus", "--seed", str(SEED), "--output-dir", str(out_dir)])
        assert rc == 0
        assert (out_dir / "manifest.json").exists()
        assert list(out_dir.glob("*.h265"))
        captured = capsys.readouterr()
        assert "generated" in captured.out
        assert "manifest" in captured.out
