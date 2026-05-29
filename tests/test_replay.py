"""Tests for deterministic mutation replay (mangle replay).

Replay re-derives a fuzz iteration's mutant purely from the campaign's
results.jsonl metadata (the recorded mutator + per-iteration RNG seed) and the
original seed file. These tests run a real fuzz campaign with a mocked decoder
to produce a results.jsonl, then assert that replay reconstructs each iteration
byte-for-byte — crashing iterations against the saved crashes/ artifact, and
clean/non-crash iterations (which the campaign never saved) against the engine's
own re-derivation. No real decoder is required.
"""

from __future__ import annotations

import json
import signal
from pathlib import Path

import pytest

import mangle.engine as engine
from mangle.cli import main
from mangle.decoder import DecodeResult, Outcome
from mangle.replay import (
    ReplayRecord,
    find_record,
    load_results,
    replay_iteration,
    replay_record,
)

SEED = Path(__file__).parent / "fixtures" / "clean.h265"


def _patch_decoder(monkeypatch, outcomes):
    state = {"i": 0}

    def fake(decoder, path, timeout, runner=None):
        idx = state["i"]
        state["i"] += 1
        return outcomes(idx)

    monkeypatch.setattr(engine, "run_decoder", fake)


def _run_campaign(out_dir, monkeypatch, *, iterations=20, seed_rng=7, crashes=True):
    """Run a fuzz campaign producing results.jsonl (+ crashes/ if requested)."""

    def outcomes(i):
        if crashes and i % 5 == 0:
            return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "segfault here")
        return DecodeResult(Outcome.CLEAN, 0, "")

    _patch_decoder(monkeypatch, outcomes)
    return engine.fuzz_file(
        SEED,
        out_dir,
        iterations=iterations,
        decoder="ffmpeg",
        timeout=5.0,
        seed_rng=seed_rng,
    )


# ---------------------------------------------------------------------------
# load_results / find_record
# ---------------------------------------------------------------------------


class TestLoadResults:
    def test_loads_every_iteration(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch, iterations=12)
        records = load_results(out_dir)
        assert len(records) == 12
        assert [r.iteration for r in records] == list(range(12))
        assert all(isinstance(r, ReplayRecord) for r in records)

    def test_records_carry_reproduction_fields(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch)
        rec = load_results(out_dir)[0]
        assert rec.mutator
        assert isinstance(rec.seed_rng, int)
        assert rec.outcome in {"clean", "crash", "abort", "timeout", "hang"}

    def test_missing_results_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_results(tmp_path / "does-not-exist")

    def test_skips_blank_lines(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch, iterations=5)
        rp = out_dir / "results.jsonl"
        rp.write_text(rp.read_text() + "\n\n")
        assert len(load_results(out_dir)) == 5


class TestFindRecord:
    def test_finds_existing(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch, iterations=8)
        records = load_results(out_dir)
        rec = find_record(records, 3)
        assert rec.iteration == 3

    def test_missing_iteration_raises_with_range(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch, iterations=8)
        records = load_results(out_dir)
        with pytest.raises(KeyError) as exc:
            find_record(records, 99)
        assert "0..7" in str(exc.value)


# ---------------------------------------------------------------------------
# byte-exact reconstruction
# ---------------------------------------------------------------------------


class TestReplayReconstruction:
    def test_crash_iteration_matches_saved_artifact(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        results = _run_campaign(out_dir, monkeypatch)
        crash = next(r for r in results if r.crash_hash)
        out = tmp_path / "replayed.h265"
        res = replay_iteration(SEED, out_dir, crash.iteration, out)
        saved = out_dir / "crashes" / f"{crash.crash_hash}.h265"
        assert out.read_bytes() == saved.read_bytes()
        assert res.verified is True
        assert res.crash_hash == crash.crash_hash

    def test_clean_iteration_reconstructs_without_artifact(
        self, tmp_path, monkeypatch
    ):
        out_dir = tmp_path / "fuzz-out"
        results = _run_campaign(out_dir, monkeypatch)
        clean = next(r for r in results if not r.crash_hash)
        out = tmp_path / "replayed-clean.h265"
        res = replay_iteration(SEED, out_dir, clean.iteration, out)
        assert out.exists()
        assert res.outcome == "clean"
        # No saved artifact existed, so verification is not applicable.
        assert res.verified is None
        assert res.crash_hash is None

    def test_reconstruction_is_deterministic(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch)
        a = tmp_path / "a.h265"
        b = tmp_path / "b.h265"
        replay_iteration(SEED, out_dir, 4, a)
        replay_iteration(SEED, out_dir, 4, b)
        assert a.read_bytes() == b.read_bytes()

    def test_replay_record_pure_function(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch)
        rec = find_record(load_results(out_dir), 2)
        seed_data = SEED.read_bytes()
        assert replay_record(seed_data, rec) == replay_record(seed_data, rec)

    def test_every_iteration_reconstructs(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch, iterations=15)
        seed_data = SEED.read_bytes()
        for rec in load_results(out_dir):
            mutant = replay_record(seed_data, rec)
            assert isinstance(mutant, bytes)
            assert len(mutant) > 0

    def test_result_reports_sha256_and_size(self, tmp_path, monkeypatch):
        import hashlib

        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch)
        out = tmp_path / "m.h265"
        res = replay_iteration(SEED, out_dir, 1, out)
        assert res.bytes_written == out.stat().st_size
        assert res.mutant_sha256 == hashlib.sha256(out.read_bytes()).hexdigest()

    def test_creates_output_parent_dirs(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch)
        nested = tmp_path / "deep" / "nested" / "m.h265"
        replay_iteration(SEED, out_dir, 0, nested)
        assert nested.exists()


class TestVerificationGuard:
    def test_tampered_artifact_flags_mismatch(self, tmp_path, monkeypatch):
        out_dir = tmp_path / "fuzz-out"
        results = _run_campaign(out_dir, monkeypatch)
        crash = next(r for r in results if r.crash_hash)
        # Corrupt the saved artifact so it no longer matches the re-derivation.
        saved = out_dir / "crashes" / f"{crash.crash_hash}.h265"
        saved.write_bytes(saved.read_bytes() + b"\x00tampered")
        res = replay_iteration(
            SEED, out_dir, crash.iteration, tmp_path / "m.h265"
        )
        assert res.verified is False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestReplayCli:
    def test_cli_reconstructs_crash_and_verifies(
        self, tmp_path, monkeypatch, capsys
    ):
        out_dir = tmp_path / "fuzz-out"
        results = _run_campaign(out_dir, monkeypatch)
        crash = next(r for r in results if r.crash_hash)
        out = tmp_path / "cli.h265"
        rc = main(
            [
                "replay",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iteration",
                str(crash.iteration),
                "--output",
                str(out),
            ]
        )
        assert rc == 0
        captured = capsys.readouterr().out
        assert f"replayed iteration {crash.iteration}" in captured
        assert "verified" in captured
        saved = out_dir / "crashes" / f"{crash.crash_hash}.h265"
        assert out.read_bytes() == saved.read_bytes()

    def test_cli_missing_iteration_errors(self, tmp_path, monkeypatch, capsys):
        out_dir = tmp_path / "fuzz-out"
        _run_campaign(out_dir, monkeypatch, iterations=5)
        rc = main(
            [
                "replay",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iteration",
                "999",
                "--output",
                str(tmp_path / "x.h265"),
            ]
        )
        assert rc == 1
        assert "not found" in capsys.readouterr().err

    def test_cli_missing_results_errors(self, tmp_path, capsys):
        rc = main(
            [
                "replay",
                "--seed",
                str(SEED),
                "--output-dir",
                str(tmp_path / "nope"),
                "--iteration",
                "0",
                "--output",
                str(tmp_path / "x.h265"),
            ]
        )
        assert rc == 1
        assert "results.jsonl" in capsys.readouterr().err
