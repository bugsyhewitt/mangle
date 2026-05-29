"""Tests for the mutation heat-map reporter (POST_V01 heat-map leg)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mangle.cli import main
from mangle.heatmap import (
    OTHER_REGION,
    HeatmapReport,
    RegionHeat,
    heatmap_report,
    region_for_mutator,
    write_heatmap,
)
from mangle.mutators import list_mutators

# A realistic ASAN report so distinct-signature counting exercises the triage
# fingerprint path, not just the stderr fallback.
ASAN_STDERR_A = """\
==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000d54
    #0 0x55a3c0ffaa11 in ff_hevc_decode_short_term_rps /src/libavcodec/hevc_ps.c:401:9
    #1 0x55a3c0ffee21 in hevc_parse_sps /src/libavcodec/hevc_ps.c:1234:7
SUMMARY: AddressSanitizer: heap-buffer-overflow hevc_ps.c:401:9
"""

# Same bug (identical top frames), different incidental addresses/lines.
ASAN_STDERR_A2 = """\
==2==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000abc
    #0 0x7f0011223344 in ff_hevc_decode_short_term_rps /src/libavcodec/hevc_ps.c:402:9
    #1 0x7f0011225566 in hevc_parse_sps /src/libavcodec/hevc_ps.c:1240:7
SUMMARY: AddressSanitizer: heap-buffer-overflow hevc_ps.c:402:9
"""

# A genuinely different bug.
ASAN_STDERR_B = """\
==3==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x55a3c0ff0001 in pps_deblocking_derive /src/libavcodec/hevc_ps.c:700:3
    #1 0x55a3c0ff0002 in hevc_parse_pps /src/libavcodec/hevc_ps.c:1500:7
SUMMARY: AddressSanitizer: SEGV hevc_ps.c:700:3
"""


def _write_results(
    out_dir: Path,
    iterations: list[dict],
    crash_stderrs: dict[str, str] | None = None,
) -> None:
    """Write a synthetic fuzz output dir (same shape as the coverage tests)."""
    out_dir.mkdir(parents=True, exist_ok=True)
    crashes_dir = out_dir / "crashes"
    crash_stderrs = crash_stderrs or {}
    lines = []
    for i, it in enumerate(iterations):
        rec = {
            "iteration": it.get("iteration", i),
            "mutator": it["mutator"],
            "seed_rng": it.get("seed_rng", i),
            "outcome": it["outcome"],
            "returncode": it.get("returncode", 0),
            "bytes_changed": it.get("bytes_changed", 1),
            "detail": it.get("detail", "synthetic"),
            "crash_hash": it.get("crash_hash"),
        }
        if rec["crash_hash"] and rec["crash_hash"] in crash_stderrs:
            crashes_dir.mkdir(parents=True, exist_ok=True)
            (crashes_dir / f"{rec['crash_hash']}.txt").write_text(
                crash_stderrs[rec["crash_hash"]]
            )
            (crashes_dir / f"{rec['crash_hash']}.h265").write_bytes(b"\x00" * 16)
        lines.append(json.dumps(rec))
    (out_dir / "results.jsonl").write_text("\n".join(lines) + "\n")


class TestRegionMapping:
    def test_known_prefixes_map_to_regions(self):
        assert region_for_mutator("sps-dimensions") == "sps"
        assert region_for_mutator("vps-layer-count") == "vps"
        assert region_for_mutator("pps-deblocking") == "pps"
        assert region_for_mutator("rps-overflow") == "rps"
        assert region_for_mutator("slice-header-ref-pic-list") == "slice-header"
        assert region_for_mutator("sei-buffering-overflow") == "sei"
        assert region_for_mutator("nal-emulation-bytes") == "nal-framing"

    def test_pps_slice_gates_map_to_pps_by_prefix(self):
        # PPS->slice-header gate mutators carry the pps- prefix; they bucket under
        # pps deterministically (the rule is the prefix, not the bridge target).
        assert region_for_mutator("pps-slice-header-extension") == "pps"
        assert region_for_mutator("pps-lists-modification") == "pps"
        assert region_for_mutator("pps-slice-qp") == "pps"

    def test_unmapped_prefix_falls_to_other(self):
        assert region_for_mutator("ghost-mutator") == OTHER_REGION
        assert region_for_mutator("noprefix") == OTHER_REGION

    def test_every_registered_mutator_maps_to_a_known_region(self):
        # No live mutator should land in "other" — the region table must cover the
        # whole registry (a guard against an unmapped prefix slipping in).
        for name in list_mutators():
            assert region_for_mutator(name) != OTHER_REGION, name


class TestRegionAggregation:
    def test_aggregates_iterations_by_region(self):
        # Two sps mutators + one pps mutator collapse to two regions.
        report = _report(
            [
                {"mutator": "sps-bit-depth", "outcome": "clean"},
                {"mutator": "sps-dimensions", "outcome": "clean"},
                {"mutator": "pps-deblocking", "outcome": "clean"},
            ]
        )
        by_region = {r.region: r for r in report.regions}
        assert by_region["sps"].iterations == 2
        assert by_region["pps"].iterations == 1

    def test_counts_crash_aborts_per_region(self):
        report = _report(
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "h1"},
                {"mutator": "rps-lt-poc-ambiguity", "outcome": "abort",
                 "crash_hash": "h2"},
                {"mutator": "rps-overflow", "outcome": "clean"},
            ]
        )
        rps = next(r for r in report.regions if r.region == "rps")
        assert rps.iterations == 3
        assert rps.crash_aborts == 2
        assert rps.outcomes["crash"] == 1
        assert rps.outcomes["abort"] == 1
        assert rps.outcomes["clean"] == 1

    def test_sums_bytes_changed_per_region(self):
        report = _report(
            [
                {"mutator": "sps-bit-depth", "outcome": "clean", "bytes_changed": 4},
                {"mutator": "sps-dimensions", "outcome": "clean", "bytes_changed": 6},
            ]
        )
        sps = next(r for r in report.regions if r.region == "sps")
        assert sps.bytes_changed == 10

    def test_distinct_signatures_dedupe_within_region(self):
        # Two crashes share a signature, a third differs => 2 distinct bugs in rps.
        report = _report(
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "rps-lt-poc-ambiguity", "outcome": "crash",
                 "crash_hash": "a2"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "b1"},
            ],
            crash_stderrs={
                "a1": ASAN_STDERR_A,
                "a2": ASAN_STDERR_A2,
                "b1": ASAN_STDERR_B,
            },
        )
        rps = next(r for r in report.regions if r.region == "rps")
        assert rps.crash_aborts == 3
        assert rps.distinct_signatures == 2

    def test_region_lists_its_registry_mutators(self):
        report = _report([{"mutator": "rps-overflow", "outcome": "clean"}])
        rps = next(r for r in report.regions if r.region == "rps")
        # Both rps mutators are listed even though only one was exercised.
        assert "rps-overflow" in rps.mutators
        assert "rps-lt-poc-ambiguity" in rps.mutators
        assert rps.mutators == sorted(rps.mutators)


class TestShares:
    def test_iteration_share_sums_to_one(self):
        report = _report(
            [
                {"mutator": "sps-bit-depth", "outcome": "clean"},
                {"mutator": "pps-deblocking", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "clean"},
            ]
        )
        total = sum(r.iteration_share for r in report.regions)
        assert total == pytest.approx(1.0)
        rps = next(r for r in report.regions if r.region == "rps")
        assert rps.iteration_share == pytest.approx(0.5)

    def test_crash_share_reflects_reward_distribution(self):
        report = _report(
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "c1"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "c2"},
                {"mutator": "pps-deblocking", "outcome": "crash", "crash_hash": "c3"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            crash_stderrs={
                "c1": ASAN_STDERR_A,
                "c2": ASAN_STDERR_B,
                "c3": ASAN_STDERR_B,
            },
        )
        by_region = {r.region: r for r in report.regions}
        assert by_region["rps"].crash_share == pytest.approx(2 / 3)
        assert by_region["pps"].crash_share == pytest.approx(1 / 3)
        # sps had no crashes -> zero reward share despite spending an iteration.
        assert by_region["sps"].crash_share == pytest.approx(0.0)

    def test_crash_share_zero_when_no_crashes(self):
        report = _report([{"mutator": "sps-bit-depth", "outcome": "clean"}])
        sps = next(r for r in report.regions if r.region == "sps")
        assert sps.crash_share == 0.0
        assert report.total_crash_aborts == 0


class TestReportLevel:
    def test_hottest_region_is_highest_reward(self):
        # pps gets the most crashes; it must lead and be flagged hottest.
        report = _report(
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "r1"},
                {"mutator": "pps-deblocking", "outcome": "crash", "crash_hash": "p1"},
                {"mutator": "pps-deblocking", "outcome": "crash", "crash_hash": "p2"},
            ],
            crash_stderrs={
                "r1": ASAN_STDERR_A,
                "p1": ASAN_STDERR_B,
                "p2": ASAN_STDERR_A,
            },
        )
        assert report.hottest_region == "pps"
        assert report.regions[0].region == "pps"

    def test_regions_sorted_reward_then_pressure_then_name(self):
        # No crashes anywhere -> sort falls through to iterations desc, then name.
        report = _report(
            [
                {"mutator": "sps-bit-depth", "outcome": "clean"},
                {"mutator": "sps-dimensions", "outcome": "clean"},
                {"mutator": "pps-deblocking", "outcome": "clean"},
                {"mutator": "vps-layer-count", "outcome": "clean"},
            ]
        )
        order = [r.region for r in report.regions]
        # sps (2 iters) first, then pps & vps (1 each) by name.
        assert order == ["sps", "pps", "vps"]

    def test_totals(self):
        report = _report(
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        assert report.total_iterations == 2
        assert report.total_crash_aborts == 1
        assert report.region_count == 2

    def test_ignores_blank_lines(self, tmp_path):
        out = tmp_path
        out.mkdir(parents=True, exist_ok=True)
        (out / "results.jsonl").write_text(
            json.dumps(
                {
                    "iteration": 0,
                    "mutator": "rps-overflow",
                    "seed_rng": 0,
                    "outcome": "clean",
                    "returncode": 0,
                    "bytes_changed": 1,
                    "detail": "x",
                    "crash_hash": None,
                }
            )
            + "\n\n\n"
        )
        assert heatmap_report(out).total_iterations == 1

    def test_unknown_mutator_buckets_to_other(self):
        report = _report([{"mutator": "ghost-mutator", "outcome": "clean"}])
        regions = {r.region for r in report.regions}
        assert OTHER_REGION in regions

    def test_missing_results_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            heatmap_report(tmp_path / "nope")

    def test_deterministic(self):
        spec = (
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            {"a1": ASAN_STDERR_A},
        )

        def build(tmp):
            _write_results(tmp, spec[0], crash_stderrs=spec[1])
            return heatmap_report(tmp)

        import tempfile

        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            first = build(Path(d1))
            second = build(Path(d2))
        assert [r.region for r in first.regions] == [
            r.region for r in second.regions
        ]
        assert first.hottest_region == second.hottest_region


def _report(iterations, crash_stderrs=None):
    """Build a report against a throwaway dir (keeps the test bodies terse)."""
    import tempfile

    d = Path(tempfile.mkdtemp())
    _write_results(d, iterations, crash_stderrs=crash_stderrs)
    return heatmap_report(d)


class TestWriteHeatmap:
    def test_writes_heatmap_json(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        report = write_heatmap(tmp_path)
        path = tmp_path / "heatmap.json"
        assert path.exists()
        obj = json.loads(path.read_text())
        for key in (
            "total_iterations",
            "total_crash_aborts",
            "region_count",
            "hottest_region",
            "regions",
        ):
            assert key in obj
        assert isinstance(obj["regions"], list)
        assert obj["regions"][0]["region"] == report.regions[0].region

    def test_heatmap_json_region_schema(self, tmp_path):
        _write_results(
            tmp_path,
            [{"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"}],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        write_heatmap(tmp_path)
        obj = json.loads((tmp_path / "heatmap.json").read_text())
        r = obj["regions"][0]
        for key in (
            "region",
            "iterations",
            "outcomes",
            "crash_aborts",
            "distinct_signatures",
            "bytes_changed",
            "mutators",
            "iteration_share",
            "crash_share",
        ):
            assert key in r


class TestHeatmapCli:
    def test_cli_heatmap_runs(self, tmp_path, capsys):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        rc = main(["heatmap", "--output-dir", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "heat-map" in out.lower()
        assert "hottest region" in out.lower()
        assert (tmp_path / "heatmap.json").exists()

    def test_cli_missing_dir_errors(self, tmp_path, capsys):
        rc = main(["heatmap", "--output-dir", str(tmp_path / "nope")])
        assert rc == 1
        assert "error:" in capsys.readouterr().err

    def test_cli_frame_depth_option(self, tmp_path):
        # Two crashes share top frame #0 but differ at #1: depth 1 collapses them
        # within the rps region, depth 2 keeps them distinct.
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a2"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A, "a2": ASAN_STDERR_B},
        )
        rc = main(
            ["heatmap", "--output-dir", str(tmp_path), "--frame-depth", "1"]
        )
        assert rc == 0
        obj = json.loads((tmp_path / "heatmap.json").read_text())
        rps = next(r for r in obj["regions"] if r["region"] == "rps")
        # Depth 1: top frames differ (ff_hevc_... vs pps_deblocking_...) -> 2.
        assert rps["distinct_signatures"] == 2


def test_dataclasses_constructible():
    rh = RegionHeat(region="sps")
    assert rh.iterations == 0
    assert rh.outcomes == {}
    assert rh.mutators == []
    rep = HeatmapReport()
    assert rep.regions == []
    assert rep.hottest_region is None
