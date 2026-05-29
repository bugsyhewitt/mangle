"""Tests for the mutate/fuzz engine. Decoder is mocked (criterion 8)."""

from __future__ import annotations

import json
import signal
from pathlib import Path

import mangle.engine as engine
from mangle.cli import main
from mangle.decoder import DecodeResult, DivergenceResult, Outcome

SEED = Path(__file__).parent / "fixtures" / "clean.h265"


class TestMutateFile:
    def test_writes_mutant_and_reports(self, tmp_path):
        out = tmp_path / "mutant.h265"
        result = engine.mutate_file(SEED, out, "sps-dimensions", seed_rng=42)
        assert out.exists()
        assert out.stat().st_size > 0
        assert result.mutator == "sps-dimensions"
        assert result.bytes_changed > 0

    def test_reproducible(self, tmp_path):
        # Criterion 7: identical output across runs for the same seed-rng.
        a = tmp_path / "a.h265"
        b = tmp_path / "b.h265"
        engine.mutate_file(SEED, a, "sps-dimensions", seed_rng=42)
        engine.mutate_file(SEED, b, "sps-dimensions", seed_rng=42)
        assert a.read_bytes() == b.read_bytes()


def _patch_decoder(monkeypatch, outcomes):
    """Replace run_decoder with a deterministic sequence-or-callable mock."""
    state = {"i": 0}

    def fake(decoder, path, timeout, runner=None):
        idx = state["i"]
        state["i"] += 1
        return outcomes(idx)

    monkeypatch.setattr(engine, "run_decoder", fake)


class TestFuzzFile:
    def test_records_results_jsonl(self, tmp_path, monkeypatch):
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CLEAN, 0, ""),
        )
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED, out_dir, iterations=20, decoder="ffmpeg", timeout=5.0, seed_rng=1
        )
        assert len(results) == 20
        results_file = out_dir / "results.jsonl"
        assert results_file.exists()
        lines = results_file.read_text().strip().splitlines()
        assert len(lines) == 20
        first = json.loads(lines[0])
        assert set(first) >= {"iteration", "mutator", "outcome", "bytes_changed"}

    def test_crash_writes_artifacts(self, tmp_path, monkeypatch):
        # Every 5th iteration "crashes".
        def outcomes(i):
            if i % 5 == 0:
                return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "segfault here")
            return DecodeResult(Outcome.CLEAN, 0, "")

        _patch_decoder(monkeypatch, outcomes)
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED, out_dir, iterations=20, decoder="ffmpeg", timeout=5.0, seed_rng=1
        )
        crashes_dir = out_dir / "crashes"
        assert crashes_dir.exists()
        h265_files = list(crashes_dir.glob("*.h265"))
        txt_files = list(crashes_dir.glob("*.txt"))
        assert len(h265_files) >= 1
        # Each crash mutant has a matching stderr file (criterion 6).
        for h in h265_files:
            assert (crashes_dir / f"{h.stem}.txt").exists()
        assert any("segfault" in t.read_text() for t in txt_files)
        crash_results = [r for r in results if r.crash_hash]
        assert len(crash_results) >= 1

    def test_results_have_all_outcomes_classified(self, tmp_path, monkeypatch):
        def outcomes(i):
            mapping = {
                0: DecodeResult(Outcome.CLEAN, 0, ""),
                1: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "x"),
                2: DecodeResult(Outcome.TIMEOUT, None, ""),
                3: DecodeResult(Outcome.ABORT, -signal.SIGABRT, "abort"),
            }
            return mapping[i % 4]

        _patch_decoder(monkeypatch, outcomes)
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED, out_dir, iterations=8, decoder="ffmpeg", timeout=5.0, seed_rng=2
        )
        seen = {r.outcome for r in results}
        assert {"clean", "crash", "timeout", "abort"} == seen


def _patch_pair(monkeypatch, pair_for):
    """Replace run_decoder_pair with a deterministic per-iteration mock."""
    state = {"i": 0}

    def fake(left, right, path, timeout):
        idx = state["i"]
        state["i"] += 1
        return pair_for(idx, left, right)

    monkeypatch.setattr(engine, "run_decoder_pair", fake)


def _agree(left, right):
    return DivergenceResult(
        diverged=False,
        kind="agree",
        left=DecodeResult(Outcome.CLEAN, 0, "", decoder=left),
        right=DecodeResult(Outcome.CLEAN, 0, "", decoder=right),
    )


def _crash_split(left, right):
    return DivergenceResult(
        diverged=True,
        kind="crash-split",
        left=DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "ffmpeg boom", decoder=left),
        right=DecodeResult(Outcome.CLEAN, 0, "", decoder=right),
    )


class TestDiffFile:
    def test_records_diff_jsonl(self, tmp_path, monkeypatch):
        _patch_pair(monkeypatch, lambda i, left, right: _agree(left, right))
        out_dir = tmp_path / "diff-out"
        results = engine.diff_file(
            SEED,
            out_dir,
            iterations=12,
            left_decoder="ffmpeg",
            right_decoder="libde265",
            timeout=5.0,
            seed_rng=1,
        )
        assert len(results) == 12
        diff_file = out_dir / "diff.jsonl"
        assert diff_file.exists()
        lines = diff_file.read_text().strip().splitlines()
        assert len(lines) == 12
        first = json.loads(lines[0])
        assert set(first) >= {
            "iteration",
            "mutator",
            "diverged",
            "kind",
            "left_decoder",
            "right_decoder",
            "left_outcome",
            "right_outcome",
        }
        assert all(r.diverged is False for r in results)

    def test_divergence_writes_artifacts(self, tmp_path, monkeypatch):
        # Every 4th iteration diverges (crash-split).
        def pair_for(i, left, right):
            if i % 4 == 0:
                return _crash_split(left, right)
            return _agree(left, right)

        _patch_pair(monkeypatch, pair_for)
        out_dir = tmp_path / "diff-out"
        results = engine.diff_file(
            SEED,
            out_dir,
            iterations=12,
            left_decoder="ffmpeg",
            right_decoder="libde265",
            timeout=5.0,
            seed_rng=1,
        )
        div_dir = out_dir / "divergences"
        assert div_dir.exists()
        h265 = list(div_dir.glob("*.h265"))
        txt = list(div_dir.glob("*.txt"))
        assert len(h265) >= 1
        # Each diverging mutant has a side-by-side stderr report.
        for h in h265:
            report = (div_dir / f"{h.stem}.txt").read_text()
            assert "crash-split" in report
            assert "ffmpeg" in report
            assert "libde265" in report
        diverged = [r for r in results if r.diverged]
        assert len(diverged) >= 1
        assert all(r.divergence_hash for r in diverged)

    def test_same_decoder_rejected(self, tmp_path):
        out_dir = tmp_path / "diff-out"
        try:
            engine.diff_file(
                SEED,
                out_dir,
                iterations=4,
                left_decoder="ffmpeg",
                right_decoder="ffmpeg",
                timeout=5.0,
                seed_rng=1,
            )
        except ValueError as exc:
            assert "different decoders" in str(exc)
        else:
            raise AssertionError("expected ValueError for identical decoders")

    def test_reproducible_mutator_selection(self, tmp_path, monkeypatch):
        # Same seed-rng picks the same mutator sequence (criterion 7).
        _patch_pair(monkeypatch, lambda i, left, right: _agree(left, right))
        a = engine.diff_file(
            SEED,
            tmp_path / "a",
            iterations=10,
            left_decoder="ffmpeg",
            right_decoder="libde265",
            timeout=5.0,
            seed_rng=7,
        )
        _patch_pair(monkeypatch, lambda i, left, right: _agree(left, right))
        b = engine.diff_file(
            SEED,
            tmp_path / "b",
            iterations=10,
            left_decoder="ffmpeg",
            right_decoder="libde265",
            timeout=5.0,
            seed_rng=7,
        )
        assert [r.mutator for r in a] == [r.mutator for r in b]
        assert [r.seed_rng for r in a] == [r.seed_rng for r in b]


class TestDiffCli:
    def test_diff_subcommand_runs(self, tmp_path, monkeypatch, capsys):
        def pair_for(i, left, right):
            return _crash_split(left, right) if i % 5 == 0 else _agree(left, right)

        _patch_pair(monkeypatch, pair_for)
        out_dir = tmp_path / "diff-out"
        rc = main(
            [
                "diff",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "10",
                "--left-decoder",
                "ffmpeg",
                "--right-decoder",
                "libde265",
                "--seed-rng",
                "3",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "ffmpeg vs libde265" in out
        assert "divergences:" in out
        assert (out_dir / "diff.jsonl").exists()
        assert (out_dir / "divergences").exists()

    def test_diff_same_decoder_errors(self, tmp_path, capsys):
        rc = main(
            [
                "diff",
                "--seed",
                str(SEED),
                "--output-dir",
                str(tmp_path / "out"),
                "--left-decoder",
                "ffmpeg",
                "--right-decoder",
                "ffmpeg",
            ]
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "different decoders" in err
