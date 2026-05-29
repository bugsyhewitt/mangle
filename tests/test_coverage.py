"""Tests for the mutation-coverage reporter (POST_V01 coverage-metrics leg)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mangle.cli import main
from mangle.coverage import (
    CoverageReport,
    MutatorCoverage,
    coverage_report,
    write_coverage,
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
    """Write a synthetic fuzz output dir.

    ``iterations`` is a list of partial result dicts; missing fields are filled
    with sensible defaults. When an iteration has a ``crash_hash`` and
    ``crash_stderrs`` supplies a matching stderr, the crashes/ artifact is
    written too so signature counting has something to read.
    """
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


class TestMutatorCoverage:
    def test_counts_iterations_and_outcomes_per_mutator(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "h1"},
                {"mutator": "rps-overflow", "outcome": "abort", "crash_hash": "h2"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
        )
        report = coverage_report(tmp_path)
        by_name = {m.mutator: m for m in report.mutators}
        rps = by_name["rps-overflow"]
        assert rps.iterations == 3
        assert rps.outcomes["clean"] == 1
        assert rps.outcomes["crash"] == 1
        assert rps.outcomes["abort"] == 1
        assert rps.crash_aborts == 2
        sps = by_name["sps-bit-depth"]
        assert sps.iterations == 1
        assert sps.crash_aborts == 0

    def test_sums_bytes_changed(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean", "bytes_changed": 4},
                {"mutator": "rps-overflow", "outcome": "clean", "bytes_changed": 6},
            ],
        )
        report = coverage_report(tmp_path)
        rps = next(m for m in report.mutators if m.mutator == "rps-overflow")
        assert rps.bytes_changed == 10

    def test_counts_distinct_crash_signatures(self, tmp_path):
        # Two crashes with the SAME signature + one distinct => 2 unique bugs.
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a2"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "b1"},
            ],
            crash_stderrs={
                "a1": ASAN_STDERR_A,
                "a2": ASAN_STDERR_A2,
                "b1": ASAN_STDERR_B,
            },
        )
        report = coverage_report(tmp_path)
        rps = next(m for m in report.mutators if m.mutator == "rps-overflow")
        assert rps.crash_aborts == 3
        assert rps.distinct_signatures == 2

    def test_distinct_signatures_zero_without_crashes(self, tmp_path):
        _write_results(
            tmp_path, [{"mutator": "rps-overflow", "outcome": "clean"}]
        )
        rps = next(
            m for m in coverage_report(tmp_path).mutators if m.mutator == "rps-overflow"
        )
        assert rps.distinct_signatures == 0


class TestCampaignCoverage:
    def test_exercised_vs_uncovered_split(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
        )
        report = coverage_report(tmp_path)
        assert set(report.exercised) == {"rps-overflow", "sps-bit-depth"}
        # Every other registered mutator is uncovered.
        registry = set(list_mutators())
        assert set(report.uncovered) == registry - {"rps-overflow", "sps-bit-depth"}
        assert report.registry_size == len(registry)

    def test_coverage_fractions(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "sps-bit-depth", "outcome": "crash", "crash_hash": "x"},
            ],
            crash_stderrs={"x": ASAN_STDERR_A},
        )
        report = coverage_report(tmp_path)
        n = report.registry_size
        # Two mutators exercised, one of them productive.
        assert report.exercised_count == 2
        assert report.productive_count == 1
        assert report.coverage_fraction == pytest.approx(2 / n)
        assert report.productive_fraction == pytest.approx(1 / n)

    def test_unknown_mutator_in_results_is_reported_not_crashed(self, tmp_path):
        # A results.jsonl from an older/newer registry may name a mutator we no
        # longer know. It must still be counted, and flagged.
        _write_results(
            tmp_path, [{"mutator": "ghost-mutator", "outcome": "clean"}]
        )
        report = coverage_report(tmp_path)
        assert "ghost-mutator" in report.exercised
        assert "ghost-mutator" in report.unknown_mutators

    def test_known_mutators_not_in_unknown(self, tmp_path):
        _write_results(
            tmp_path, [{"mutator": "rps-overflow", "outcome": "clean"}]
        )
        report = coverage_report(tmp_path)
        assert report.unknown_mutators == []

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
        report = coverage_report(out)
        assert report.total_iterations == 1

    def test_missing_results_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            coverage_report(tmp_path / "nope")

    def test_deterministic(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        first = coverage_report(tmp_path)
        second = coverage_report(tmp_path)
        assert [m.mutator for m in first.mutators] == [
            m.mutator for m in second.mutators
        ]
        assert first.uncovered == second.uncovered

    def test_mutators_sorted_by_name(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "sps-bit-depth", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "clean"},
            ],
        )
        names = [m.mutator for m in coverage_report(tmp_path).mutators]
        assert names == sorted(names)


class TestWriteCoverage:
    def test_writes_coverage_json(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        report = write_coverage(tmp_path)
        path = tmp_path / "coverage.json"
        assert path.exists()
        obj = json.loads(path.read_text())
        for key in (
            "registry_size",
            "exercised_count",
            "productive_count",
            "uncovered",
            "coverage_fraction",
            "productive_fraction",
            "total_iterations",
            "unknown_mutators",
            "mutators",
        ):
            assert key in obj
        assert isinstance(obj["mutators"], list)
        assert obj["mutators"][0]["mutator"] == report.mutators[0].mutator

    def test_coverage_json_mutator_schema(self, tmp_path):
        _write_results(
            tmp_path,
            [{"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"}],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        write_coverage(tmp_path)
        obj = json.loads((tmp_path / "coverage.json").read_text())
        m = obj["mutators"][0]
        for key in (
            "mutator",
            "iterations",
            "outcomes",
            "crash_aborts",
            "distinct_signatures",
            "bytes_changed",
            "known",
        ):
            assert key in m


class TestCoverageCli:
    def test_cli_coverage_runs(self, tmp_path, capsys):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A},
        )
        rc = main(["coverage", "--output-dir", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "mutator coverage" in out.lower()
        assert (tmp_path / "coverage.json").exists()

    def test_cli_coverage_lists_uncovered(self, tmp_path, capsys):
        _write_results(
            tmp_path, [{"mutator": "rps-overflow", "outcome": "clean"}]
        )
        rc = main(["coverage", "--output-dir", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        # At least one uncovered mutator should be surfaced.
        assert "uncovered" in out.lower()

    def test_cli_missing_dir_errors(self, tmp_path, capsys):
        rc = main(["coverage", "--output-dir", str(tmp_path / "nope")])
        assert rc == 1
        assert "error:" in capsys.readouterr().err

    def test_cli_frame_depth_option(self, tmp_path):
        # Two crashes that share top-frame #0 but differ at #1: depth 1 collapses
        # them to one signature, depth 2 keeps them distinct.
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a1"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a2"},
            ],
            crash_stderrs={"a1": ASAN_STDERR_A, "a2": ASAN_STDERR_B},
        )
        rc = main(
            ["coverage", "--output-dir", str(tmp_path), "--frame-depth", "1"]
        )
        assert rc == 0
        obj = json.loads((tmp_path / "coverage.json").read_text())
        rps = next(m for m in obj["mutators"] if m["mutator"] == "rps-overflow")
        # Depth 1: top frames differ (ff_hevc_... vs pps_deblocking_...) -> 2.
        assert rps["distinct_signatures"] == 2


def test_dataclasses_constructible():
    mc = MutatorCoverage(mutator="m", known=True)
    assert mc.iterations == 0
    assert mc.outcomes == {}
    rep = CoverageReport(registry_size=1)
    assert rep.mutators == []
    assert rep.uncovered == []
