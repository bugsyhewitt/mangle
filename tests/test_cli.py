"""Comprehensive CLI tests for all mangle subcommands.

Each subcommand is tested through the main() entry point with mocked decoders
where real decoding would be needed.  Tests verify argument parsing, error
handling, exit codes, and expected output artefacts.
"""

from __future__ import annotations

import json
import signal
from pathlib import Path

import pytest

import mangle.engine as engine
from mangle.cli import main
from mangle.decoder import DecodeResult, DivergenceResult, Outcome
from mangle.mutators import list_mutators

SEED = Path(__file__).parent / "fixtures" / "clean.h265"


def _mock_decoder_all_clean(monkeypatch):
    """Patch run_decoder to always return CLEAN with no stderr."""
    monkeypatch.setattr(
        engine,
        "run_decoder",
        lambda decoder, path, timeout, runner=None: DecodeResult(Outcome.CLEAN, 0, ""),
    )


def _mock_decoder_with_crash(monkeypatch, every_nth: int = 3):
    """Patch run_decoder to crash every nth call."""
    state = {"i": 0}

    def fake(decoder, path, timeout, runner=None):
        idx = state["i"]
        state["i"] += 1
        if idx % every_nth == 0:
            return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "SIGSEGV: segfault")
        return DecodeResult(Outcome.CLEAN, 0, "")

    monkeypatch.setattr(engine, "run_decoder", fake)


def _mock_diff_decoder(monkeypatch):
    """Patch run_decoder_pair so the diff command gets clean results."""
    monkeypatch.setattr(
        engine,
        "run_decoder_pair",
        lambda ld, rd, path, timeout, compare_output=False: DivergenceResult(
            diverged=False,
            kind="",
            left=DecodeResult(Outcome.CLEAN, 0, ""),
            right=DecodeResult(Outcome.CLEAN, 0, ""),
        ),
    )


# ---------------------------------------------------------------------------
# --version
# ---------------------------------------------------------------------------

class TestVersionFlag:
    def test_version_flag_exits_zero(self, capsys):
        with pytest.raises(SystemExit) as exc:
            main(["--version"])
        assert exc.value.code == 0

    def test_version_flag_prints_mangle(self, capsys):
        with pytest.raises(SystemExit):
            main(["--version"])
        out, _ = capsys.readouterr()
        assert "mangle" in out


# ---------------------------------------------------------------------------
# No subcommand / unknown subcommand
# ---------------------------------------------------------------------------

class TestTopLevelParser:
    def test_no_subcommand_exits_nonzero(self):
        with pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code != 0

    def test_unknown_subcommand_exits_nonzero(self):
        with pytest.raises(SystemExit) as exc:
            main(["doesnotexist"])
        assert exc.value.code != 0

    def test_help_mentions_all_subcommands(self, capsys):
        with pytest.raises(SystemExit):
            main(["--help"])
        out, _ = capsys.readouterr()
        for cmd in ("mutate", "fuzz", "diff", "corpus", "triage", "replay",
                    "coverage", "heatmap", "mutation-score", "afl-mutate", "mutators"):
            assert cmd in out, f"subcommand {cmd!r} missing from --help"


# ---------------------------------------------------------------------------
# mutate
# ---------------------------------------------------------------------------

class TestMutateSubcommand:
    def test_mutate_writes_output_file(self, tmp_path):
        out = tmp_path / "mutant.h265"
        rc = main(["mutate", "--seed", str(SEED), "--output", str(out),
                   "--mutator", "sps-dimensions"])
        assert rc == 0
        assert out.exists()
        assert out.stat().st_size > 0

    def test_mutate_prints_summary(self, tmp_path, capsys):
        out = tmp_path / "m.h265"
        main(["mutate", "--seed", str(SEED), "--output", str(out),
              "--mutator", "sps-dimensions"])
        printed, _ = capsys.readouterr()
        assert "mutation applied" in printed
        assert "sps-dimensions" in printed
        assert "bytes changed" in printed

    def test_mutate_missing_seed_returns_1(self, tmp_path, capsys):
        out = tmp_path / "m.h265"
        rc = main(["mutate", "--seed", str(tmp_path / "absent.h265"),
                   "--output", str(out), "--mutator", "sps-dimensions"])
        assert rc == 1
        _, err = capsys.readouterr()
        assert "error" in err.lower()

    def test_mutate_seed_rng_flag_accepted(self, tmp_path):
        out = tmp_path / "m.h265"
        rc = main(["mutate", "--seed", str(SEED), "--output", str(out),
                   "--mutator", "sps-dimensions", "--seed-rng", "123"])
        assert rc == 0

    def test_mutate_unknown_mutator_rejected(self, tmp_path):
        out = tmp_path / "m.h265"
        with pytest.raises(SystemExit) as exc:
            main(["mutate", "--seed", str(SEED), "--output", str(out),
                  "--mutator", "not-a-real-mutator"])
        assert exc.value.code != 0

    def test_mutate_missing_required_flags_exits(self):
        with pytest.raises(SystemExit) as exc:
            main(["mutate", "--seed", str(SEED)])
        assert exc.value.code != 0


# ---------------------------------------------------------------------------
# mutators (list)
# ---------------------------------------------------------------------------

class TestMutatorsSubcommand:
    def test_mutators_exits_zero(self, capsys):
        rc = main(["mutators"])
        assert rc == 0

    def test_mutators_prints_all_registered(self, capsys):
        main(["mutators"])
        out, _ = capsys.readouterr()
        listed = set(out.strip().splitlines())
        assert listed == set(list_mutators()), (
            f"mutators CLI output differs from registry: {listed ^ set(list_mutators())}"
        )

    def test_mutators_one_per_line(self, capsys):
        main(["mutators"])
        out, _ = capsys.readouterr()
        lines = [l for l in out.splitlines() if l.strip()]
        assert len(lines) == len(list_mutators())


# ---------------------------------------------------------------------------
# fuzz
# ---------------------------------------------------------------------------

class TestFuzzSubcommand:
    def test_fuzz_basic_creates_results_jsonl(self, tmp_path, monkeypatch):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        rc = main([
            "fuzz", "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "5",
        ])
        assert rc == 0
        assert (out_dir / "results.jsonl").exists()

    def test_fuzz_prints_summary_line(self, tmp_path, monkeypatch, capsys):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        main(["fuzz", "--seed", str(SEED), "--output-dir", str(out_dir),
              "--iterations", "3"])
        out, _ = capsys.readouterr()
        assert "ran 3 iterations" in out
        assert "results written" in out

    def test_fuzz_crash_artifacts_written(self, tmp_path, monkeypatch):
        _mock_decoder_with_crash(monkeypatch, every_nth=2)
        out_dir = tmp_path / "fuzz-out"
        main(["fuzz", "--seed", str(SEED), "--output-dir", str(out_dir),
              "--iterations", "4"])
        crashes = list((out_dir / "crashes").glob("*.h265"))
        assert crashes

    def test_fuzz_seed_from_crashes_mutually_exclusive_with_seed(self, tmp_path):
        with pytest.raises(SystemExit) as exc:
            main([
                "fuzz",
                "--seed", str(SEED),
                "--seed-from-crashes", str(tmp_path),
                "--output-dir", str(tmp_path / "out"),
                "--iterations", "1",
            ])
        assert exc.value.code != 0

    def test_fuzz_max_crashes_requires_dedup(self, tmp_path, monkeypatch, capsys):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        rc = main([
            "fuzz", "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "2",
            "--max-crashes", "1",
        ])
        assert rc == 2
        _, err = capsys.readouterr()
        assert "--max-crashes requires --crash-dedup" in err

    def test_fuzz_max_time_without_crash_requires_dedup(
        self, tmp_path, monkeypatch, capsys
    ):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        rc = main([
            "fuzz", "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "2",
            "--max-time-without-crash", "60",
        ])
        assert rc == 2
        _, err = capsys.readouterr()
        assert "--crash-dedup" in err

    def test_fuzz_scheduler_state_requires_adaptive(
        self, tmp_path, monkeypatch, capsys
    ):
        _mock_decoder_all_clean(monkeypatch)
        state_file = tmp_path / "sched.json"
        state_file.write_text("{}")
        out_dir = tmp_path / "fuzz-out"
        rc = main([
            "fuzz", "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "2",
            "--strategy", "uniform",
            "--scheduler-state", str(state_file),
        ])
        assert rc == 2
        _, err = capsys.readouterr()
        assert "--strategy adaptive" in err

    def test_fuzz_adaptive_strategy_writes_scheduler_json(
        self, tmp_path, monkeypatch, capsys
    ):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        rc = main([
            "fuzz", "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "4",
            "--strategy", "adaptive",
        ])
        assert rc == 0
        assert (out_dir / "scheduler.json").exists()
        out, _ = capsys.readouterr()
        assert "scoreboard written" in out


# ---------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------

class TestCorpusSubcommand:
    def test_corpus_creates_manifest_and_seeds(self, tmp_path, capsys):
        out_dir = tmp_path / "corpus-out"
        rc = main(["corpus", "--seed", str(SEED), "--output-dir", str(out_dir)])
        assert rc == 0
        assert (out_dir / "manifest.json").exists()
        assert list(out_dir.glob("*.h265"))
        out, _ = capsys.readouterr()
        assert "generated" in out
        assert "manifest" in out

    def test_corpus_missing_seed_returns_1(self, tmp_path, capsys):
        rc = main(["corpus", "--seed", str(tmp_path / "absent.h265"),
                   "--output-dir", str(tmp_path / "out")])
        assert rc == 1

    def test_corpus_manifest_has_expected_keys(self, tmp_path):
        out_dir = tmp_path / "corpus-out"
        main(["corpus", "--seed", str(SEED), "--output-dir", str(out_dir)])
        manifest = json.loads((out_dir / "manifest.json").read_text())
        assert "emitted" in manifest
        assert "entries" in manifest


# ---------------------------------------------------------------------------
# coverage
# ---------------------------------------------------------------------------

class TestCoverageSubcommand:
    def _make_results_dir(self, tmp_path, monkeypatch):
        """Run a small fuzz campaign so coverage has results.jsonl to read."""
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        main(["fuzz", "--seed", str(SEED), "--output-dir", str(out_dir),
              "--iterations", "4"])
        return out_dir

    def test_coverage_writes_coverage_json(self, tmp_path, monkeypatch):
        out_dir = self._make_results_dir(tmp_path, monkeypatch)
        rc = main(["coverage", "--output-dir", str(out_dir)])
        assert rc == 0
        assert (out_dir / "coverage.json").exists()

    def test_coverage_prints_summary(self, tmp_path, monkeypatch, capsys):
        out_dir = self._make_results_dir(tmp_path, monkeypatch)
        main(["coverage", "--output-dir", str(out_dir)])
        out, _ = capsys.readouterr()
        assert "mutator coverage" in out
        assert "coverage report written" in out

    def test_coverage_missing_results_returns_1(self, tmp_path, capsys):
        rc = main(["coverage", "--output-dir", str(tmp_path / "empty")])
        assert rc == 1


# ---------------------------------------------------------------------------
# heatmap
# ---------------------------------------------------------------------------

class TestHeatmapSubcommand:
    def _make_results_dir(self, tmp_path, monkeypatch):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        main(["fuzz", "--seed", str(SEED), "--output-dir", str(out_dir),
              "--iterations", "4"])
        return out_dir

    def test_heatmap_writes_heatmap_json(self, tmp_path, monkeypatch):
        out_dir = self._make_results_dir(tmp_path, monkeypatch)
        rc = main(["heatmap", "--output-dir", str(out_dir)])
        assert rc == 0
        assert (out_dir / "heatmap.json").exists()

    def test_heatmap_prints_summary(self, tmp_path, monkeypatch, capsys):
        out_dir = self._make_results_dir(tmp_path, monkeypatch)
        main(["heatmap", "--output-dir", str(out_dir)])
        out, _ = capsys.readouterr()
        assert "heat-map" in out
        assert "heat-map written" in out


# ---------------------------------------------------------------------------
# mutation-score
# ---------------------------------------------------------------------------

class TestMutationScoreSubcommand:
    def _make_results_dir(self, tmp_path, monkeypatch):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        main(["fuzz", "--seed", str(SEED), "--output-dir", str(out_dir),
              "--iterations", "4"])
        return out_dir

    def test_mutation_score_writes_json(self, tmp_path, monkeypatch):
        out_dir = self._make_results_dir(tmp_path, monkeypatch)
        rc = main(["mutation-score", "--output-dir", str(out_dir)])
        assert rc == 0
        assert (out_dir / "mutation-score.json").exists()

    def test_mutation_score_prints_kill_ratio(self, tmp_path, monkeypatch, capsys):
        out_dir = self._make_results_dir(tmp_path, monkeypatch)
        main(["mutation-score", "--output-dir", str(out_dir)])
        out, _ = capsys.readouterr()
        assert "mutation score" in out
        assert "%" in out


# ---------------------------------------------------------------------------
# triage
# ---------------------------------------------------------------------------

class TestTriageSubcommand:
    def _make_crash_dir(self, tmp_path, monkeypatch):
        _mock_decoder_with_crash(monkeypatch, every_nth=2)
        out_dir = tmp_path / "fuzz-out"
        main(["fuzz", "--seed", str(SEED), "--output-dir", str(out_dir),
              "--iterations", "6"])
        return out_dir

    def test_triage_writes_triage_jsonl(self, tmp_path, monkeypatch):
        out_dir = self._make_crash_dir(tmp_path, monkeypatch)
        rc = main(["triage", "--output-dir", str(out_dir)])
        assert rc == 0
        assert (out_dir / "triage.jsonl").exists()

    def test_triage_missing_output_dir_returns_1(self, tmp_path, capsys):
        rc = main(["triage", "--output-dir", str(tmp_path / "doesnotexist")])
        assert rc == 1

    def test_triage_bucket_flag_writes_bucket_json(self, tmp_path, monkeypatch):
        out_dir = self._make_crash_dir(tmp_path, monkeypatch)
        rc = main(["triage", "--output-dir", str(out_dir), "--triage-bucket"])
        assert rc == 0
        assert (out_dir / "triage-buckets.json").exists()


# ---------------------------------------------------------------------------
# replay
# ---------------------------------------------------------------------------

class TestReplaySubcommand:
    def _make_campaign(self, tmp_path, monkeypatch):
        _mock_decoder_all_clean(monkeypatch)
        out_dir = tmp_path / "fuzz-out"
        main(["fuzz", "--seed", str(SEED), "--output-dir", str(out_dir),
              "--iterations", "3"])
        return out_dir

    def test_replay_writes_mutant(self, tmp_path, monkeypatch):
        out_dir = self._make_campaign(tmp_path, monkeypatch)
        out_mutant = tmp_path / "replayed.h265"
        rc = main([
            "replay",
            "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iteration", "0",
            "--output", str(out_mutant),
        ])
        assert rc == 0
        assert out_mutant.exists()
        assert out_mutant.stat().st_size > 0

    def test_replay_prints_iteration_info(self, tmp_path, monkeypatch, capsys):
        out_dir = self._make_campaign(tmp_path, monkeypatch)
        out_mutant = tmp_path / "r.h265"
        main([
            "replay",
            "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iteration", "1",
            "--output", str(out_mutant),
        ])
        out, _ = capsys.readouterr()
        assert "replayed iteration 1" in out
        assert "reconstructed" in out

    def test_replay_out_of_range_iteration_returns_1(self, tmp_path, monkeypatch, capsys):
        out_dir = self._make_campaign(tmp_path, monkeypatch)
        out_mutant = tmp_path / "r.h265"
        rc = main([
            "replay",
            "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iteration", "9999",
            "--output", str(out_mutant),
        ])
        assert rc == 1


# ---------------------------------------------------------------------------
# diff
# ---------------------------------------------------------------------------

class TestDiffSubcommand:
    def test_diff_same_decoder_rejected_by_engine(self, tmp_path, monkeypatch, capsys):
        """The engine raises when left == right decoder."""
        _mock_diff_decoder(monkeypatch)
        out_dir = tmp_path / "diff-out"
        rc = main([
            "diff",
            "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "2",
            "--left-decoder", "ffmpeg",
            "--right-decoder", "ffmpeg",
        ])
        assert rc == 1
        _, err = capsys.readouterr()
        assert "error" in err.lower()

    def test_diff_basic_creates_diff_jsonl(self, tmp_path, monkeypatch):
        _mock_diff_decoder(monkeypatch)
        out_dir = tmp_path / "diff-out"
        rc = main([
            "diff",
            "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "3",
            "--left-decoder", "ffmpeg",
            "--right-decoder", "libde265",
        ])
        assert rc == 0
        assert (out_dir / "diff.jsonl").exists()
