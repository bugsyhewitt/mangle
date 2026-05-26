"""Integration tests against a real ffmpeg, if available (criterion 8).

These tests are marked ``integration`` and skipped automatically when ffmpeg is
not on PATH, so the default smoke-test run never requires a decoder install.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

import mangle.engine as engine
from mangle.decoder import Outcome, run_decoder

SEED = Path(__file__).parent / "fixtures" / "clean.h265"

ffmpeg_available = shutil.which("ffmpeg") is not None


@pytest.mark.integration
@pytest.mark.skipif(not ffmpeg_available, reason="ffmpeg not installed")
class TestRealFfmpeg:
    def test_clean_seed_decodes_clean(self):
        result = run_decoder("ffmpeg", str(SEED), timeout=10.0)
        assert result.outcome == Outcome.CLEAN

    def test_fuzz_campaign_runs(self, tmp_path):
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=20,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=42,
            concurrency=4,
        )
        assert len(results) == 20
        assert (out_dir / "results.jsonl").exists()
        # All outcomes must be from the known taxonomy.
        valid = {"clean", "crash", "timeout", "abort", "hang"}
        assert all(r.outcome in valid for r in results)
