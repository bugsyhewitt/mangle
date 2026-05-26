"""Tests for the mutate/fuzz engine. Decoder is mocked (criterion 8)."""

from __future__ import annotations

import json
import signal
from pathlib import Path

import mangle.engine as engine
from mangle.decoder import DecodeResult, Outcome

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
