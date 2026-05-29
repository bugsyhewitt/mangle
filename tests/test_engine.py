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


class _FakeClock:
    """A deterministic monotonic clock that advances a fixed step per read.

    Lets the time-limit dispatch logic be exercised without real wall-clock
    sleeps: the campaign's deadline is compared against successive reads, so a
    known number of reads (one per round's budget check) crosses it.
    """

    def __init__(self, start: float = 1000.0, step: float = 1.0):
        self.t = start
        self.step = step

    def __call__(self) -> float:
        now = self.t
        self.t += self.step
        return now


class TestTimeLimit:
    def test_budget_halts_dispatch_before_iteration_cap(
        self, tmp_path, monkeypatch
    ):
        # Clock starts at 1000 and advances 1s per read. Deadline = start + 3s.
        # Read 1 (deadline compute) -> 1000, deadline = 1003.
        # Round checks read 1001, 1002, 1003 -> the 3rd check (>=1003) breaks.
        # With concurrency=1 that dispatches 2 rounds (iterations 0 and 1).
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "fuzz-out"
        clock = _FakeClock(start=1000.0, step=1.0)
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=1000,  # high cap; the budget must stop us well short
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            concurrency=1,
            time_limit=3.0,
            clock=clock,
        )
        # Far fewer than the 1000 cap — the wall-clock budget truncated dispatch.
        assert 0 < len(results) < 1000
        # results.jsonl carries exactly the iterations that ran (no phantom rows).
        lines = (out_dir / "results.jsonl").read_text().strip().splitlines()
        assert len(lines) == len(results)
        # Iteration indices are contiguous from 0 (sorted, no gaps).
        assert [r.iteration for r in results] == list(range(len(results)))

    def test_iteration_cap_still_caps_under_generous_budget(
        self, tmp_path, monkeypatch
    ):
        # A budget that never expires (clock never advances) must let the full
        # iteration cap run — --iterations is the other limit.
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "fuzz-out"
        frozen = lambda: 0.0  # noqa: E731 — never reaches the deadline
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=8,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            concurrency=4,
            time_limit=10.0,
            clock=frozen,
        )
        assert len(results) == 8

    def test_no_time_limit_runs_all_iterations(self, tmp_path, monkeypatch):
        # Default (time_limit=None) must run the full requested iteration count.
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED, out_dir, iterations=20, decoder="ffmpeg", timeout=5.0, seed_rng=1
        )
        assert len(results) == 20

    def test_no_time_limit_rng_stream_byte_identical(self, tmp_path, monkeypatch):
        # Criterion 7 guard: adding the time-limit plumbing must NOT perturb the
        # v0.1 mutator/seed_rng stream of a plain --iterations campaign. The
        # single-shot uniform path is only taken when time_limit is None.
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        a = engine.fuzz_file(
            SEED, tmp_path / "a", iterations=15, decoder="ffmpeg",
            timeout=5.0, seed_rng=77,
        )
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        b = engine.fuzz_file(
            SEED, tmp_path / "b", iterations=15, decoder="ffmpeg",
            timeout=5.0, seed_rng=77,
        )
        assert [(r.mutator, r.seed_rng) for r in a] == [
            (r.mutator, r.seed_rng) for r in b
        ]

    def test_rejects_non_positive_budget(self, tmp_path):
        import pytest

        with pytest.raises(ValueError, match="positive number of seconds"):
            engine.fuzz_file(
                SEED,
                tmp_path / "out",
                iterations=4,
                decoder="ffmpeg",
                timeout=5.0,
                time_limit=0.0,
            )

    def test_time_limited_iterations_are_replayable(self, tmp_path, monkeypatch):
        # Even though COUNT is wall-clock dependent, each row that ran records the
        # mutator + seed_rng that fully reproduce its mutant (replay contract).
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=1000,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            concurrency=2,
            time_limit=5.0,
            clock=_FakeClock(start=0.0, step=1.0),
        )
        for r in results:
            assert isinstance(r.mutator, str) and r.mutator
            assert isinstance(r.seed_rng, int)


class TestAdaptiveFuzz:
    def test_adaptive_records_results_and_scoreboard(self, tmp_path, monkeypatch):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=16,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            strategy="adaptive",
            concurrency=4,
        )
        assert len(results) == 16
        # Every iteration index appears exactly once and they are sorted.
        assert [r.iteration for r in results] == list(range(16))
        assert (out_dir / "results.jsonl").exists()
        # Adaptive mode emits a learned-scoreboard artifact.
        scoreboard = json.loads((out_dir / "scheduler.json").read_text())
        assert scoreboard["strategy"] == "adaptive"
        assert scoreboard["iterations"] == 16
        total_trials = sum(a["trials"] for a in scoreboard["arms"].values())
        assert total_trials == 16

    def test_uniform_writes_no_scoreboard(self, tmp_path, monkeypatch):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "fuzz-out"
        engine.fuzz_file(
            SEED, out_dir, iterations=8, decoder="ffmpeg", timeout=5.0, seed_rng=1
        )
        assert not (out_dir / "scheduler.json").exists()

    def test_adaptive_is_reproducible(self, tmp_path, monkeypatch):
        # Criterion 7: same seed-rng -> identical mutator/outcome stream. The mock
        # keys its verdict off the decoded file content (stable per input), NOT
        # off call order, so it is immune to within-round gather scheduling.
        def content_outcome(decoder, path, timeout, runner=None):
            data = Path(path).read_bytes()
            if sum(data) % 3 == 0:
                return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "boom")
            return DecodeResult(Outcome.CLEAN, 0, "")

        monkeypatch.setattr(engine, "run_decoder", content_outcome)
        a = engine.fuzz_file(
            SEED, tmp_path / "a", iterations=24, decoder="ffmpeg",
            timeout=5.0, seed_rng=5, strategy="adaptive",
        )
        b = engine.fuzz_file(
            SEED, tmp_path / "b", iterations=24, decoder="ffmpeg",
            timeout=5.0, seed_rng=5, strategy="adaptive",
        )
        assert [r.mutator for r in a] == [r.mutator for r in b]
        assert [r.outcome for r in a] == [r.outcome for r in b]

    def test_adaptive_biases_toward_crashing_mutator(self, tmp_path, monkeypatch):
        # One specific mutator always crashes; all others stay clean. Over a long
        # campaign the adaptive scheduler should spend more trials on the crasher
        # than its uniform 1/N share would allow.
        seed_data = SEED.read_bytes()
        from mangle.engine import mutate_bytes
        import random as _random

        # Discover which mutator a given iter-rng maps to is not stable across the
        # bandit, so instead key the "always crash" on the mutator NAME by
        # intercepting at the result level via a name-aware decoder mock.
        crash_mutator = "sps-dimensions"

        # Map temp file content -> mutator by re-deriving is impossible here, so
        # we drive the decision off the IterationResult through a custom runner:
        # patch _run_iteration to crash only when the chosen mutator matches.
        real_run_iteration = engine._run_iteration

        async def fake_run_iteration(
            i, sd, mutator_name, iter_rng_seed, decoder, timeout, crashes_dir, sem,
            base_seed=None,
        ):
            from mangle.engine import IterationResult

            mutated, result = mutate_bytes(
                sd, mutator_name, _random.Random(iter_rng_seed)
            )
            crashed = mutator_name == crash_mutator
            return IterationResult(
                iteration=i,
                mutator=mutator_name,
                seed_rng=iter_rng_seed,
                outcome=(Outcome.CRASH.value if crashed else Outcome.CLEAN.value),
                returncode=(-signal.SIGSEGV if crashed else 0),
                bytes_changed=result.bytes_changed,
                detail=result.detail,
                crash_hash=("deadbeef" if crashed else None),
                base_seed=base_seed,
            )

        monkeypatch.setattr(engine, "_run_iteration", fake_run_iteration)

        adaptive = engine.fuzz_file(
            SEED, tmp_path / "ad", iterations=400, decoder="ffmpeg",
            timeout=5.0, seed_rng=11, strategy="adaptive", concurrency=4,
        )
        uniform = engine.fuzz_file(
            SEED, tmp_path / "un", iterations=400, decoder="ffmpeg",
            timeout=5.0, seed_rng=11, strategy="uniform", concurrency=4,
        )
        engine._run_iteration = real_run_iteration

        ad_share = sum(1 for r in adaptive if r.mutator == crash_mutator) / 400
        un_share = sum(1 for r in uniform if r.mutator == crash_mutator) / 400
        # Adaptive must over-select the crasher relative to uniform.
        assert ad_share > un_share


class TestSeedFromCrashes:
    def test_rejects_seed_and_crashes_together(self, tmp_path):
        import pytest

        with pytest.raises(ValueError, match="exactly one base-input source"):
            engine.fuzz_file(
                SEED,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
                seed_from_crashes=str(tmp_path / "crashes"),
            )

    def test_rejects_no_seed_source(self, tmp_path):
        import pytest

        with pytest.raises(ValueError, match="requires --seed or"):
            engine.fuzz_file(
                None,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
            )

    def test_missing_crash_dir(self, tmp_path):
        import pytest

        with pytest.raises(FileNotFoundError, match="no such crash directory"):
            engine.fuzz_file(
                None,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
                seed_from_crashes=str(tmp_path / "nope"),
            )

    def test_empty_crash_dir(self, tmp_path):
        import pytest

        crashes = tmp_path / "crashes"
        crashes.mkdir()
        with pytest.raises(ValueError, match="no .* crash artifacts"):
            engine.fuzz_file(
                None,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
                seed_from_crashes=str(crashes),
            )

    def _make_crash_pool(self, tmp_path, n=3):
        """Write n valid H.265 crash-artifact seeds from the fixture seed."""
        crashes = tmp_path / "prior-crashes"
        crashes.mkdir()
        base = SEED.read_bytes()
        names = []
        for k in range(n):
            # Each "crash seed" is a distinct deterministic mutant of the fixture
            # so the pool has varied (but valid-framed) base inputs.
            from mangle.engine import mutate_bytes
            import random as _random

            mutated, _ = mutate_bytes(base, "sps-dimensions", _random.Random(k))
            name = f"{k:016x}.h265"
            (crashes / name).write_bytes(mutated)
            names.append(name)
        # A non-h265 file must be ignored by the pool collector.
        (crashes / "deadbeef.txt").write_text("stderr noise")
        return crashes, sorted(names)

    def test_records_base_seed_round_robin(self, tmp_path, monkeypatch):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        crashes, names = self._make_crash_pool(tmp_path, n=3)
        out_dir = tmp_path / "out"
        results = engine.fuzz_file(
            None,
            out_dir,
            iterations=9,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            seed_from_crashes=str(crashes),
        )
        # Every iteration records a base seed drawn from the pool, round-robin by
        # iteration index (deterministic, independent of completion order).
        base_seeds = [r.base_seed for r in results]
        assert all(b in names for b in base_seeds)
        assert base_seeds == [names[i % 3] for i in range(9)]
        # results.jsonl carries base_seed for replayability.
        first = json.loads(
            (out_dir / "results.jsonl").read_text().strip().splitlines()[0]
        )
        assert first["base_seed"] in names

    def test_single_seed_base_seed_is_none(self, tmp_path, monkeypatch):
        # The v0.1 single-seed path records base_seed=None (backward compatible).
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "out"
        results = engine.fuzz_file(
            SEED, out_dir, iterations=5, decoder="ffmpeg", timeout=5.0, seed_rng=1
        )
        assert all(r.base_seed is None for r in results)

    def test_single_seed_rng_stream_unchanged(self, tmp_path, monkeypatch):
        # Criterion 7 guard: introducing the seed pool must NOT perturb the v0.1
        # mutator/seed_rng stream for a single-seed campaign.
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        results = engine.fuzz_file(
            SEED, tmp_path / "a", iterations=12, decoder="ffmpeg",
            timeout=5.0, seed_rng=99,
        )
        # Re-run independently; identical mutator + seed_rng per iteration.
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        again = engine.fuzz_file(
            SEED, tmp_path / "b", iterations=12, decoder="ffmpeg",
            timeout=5.0, seed_rng=99,
        )
        assert [(r.mutator, r.seed_rng) for r in results] == [
            (r.mutator, r.seed_rng) for r in again
        ]

    def test_crash_fed_campaign_is_reproducible(self, tmp_path, monkeypatch):
        crashes, _ = self._make_crash_pool(tmp_path, n=2)

        def content_outcome(decoder, path, timeout, runner=None):
            data = Path(path).read_bytes()
            if sum(data) % 3 == 0:
                return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "boom")
            return DecodeResult(Outcome.CLEAN, 0, "")

        monkeypatch.setattr(engine, "run_decoder", content_outcome)
        a = engine.fuzz_file(
            None, tmp_path / "a", iterations=16, decoder="ffmpeg",
            timeout=5.0, seed_rng=5, seed_from_crashes=str(crashes),
        )
        b = engine.fuzz_file(
            None, tmp_path / "b", iterations=16, decoder="ffmpeg",
            timeout=5.0, seed_rng=5, seed_from_crashes=str(crashes),
        )
        assert [(r.mutator, r.seed_rng, r.base_seed) for r in a] == [
            (r.mutator, r.seed_rng, r.base_seed) for r in b
        ]


class TestSeedFromCrashesCli:
    def test_cli_rejects_both_sources(self, tmp_path):
        import pytest

        with pytest.raises(SystemExit):
            main(
                [
                    "fuzz",
                    "--seed",
                    str(SEED),
                    "--seed-from-crashes",
                    str(tmp_path),
                    "--output-dir",
                    str(tmp_path / "out"),
                ]
            )

    def test_cli_requires_a_source(self, tmp_path):
        import pytest

        with pytest.raises(SystemExit):
            main(["fuzz", "--output-dir", str(tmp_path / "out")])

    def test_cli_runs_from_crashes(self, tmp_path, monkeypatch, capsys):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        crashes = tmp_path / "crashes"
        crashes.mkdir()
        (crashes / "aa.h265").write_bytes(SEED.read_bytes())
        (crashes / "bb.h265").write_bytes(SEED.read_bytes())
        out_dir = tmp_path / "out"
        rc = main(
            [
                "fuzz",
                "--seed-from-crashes",
                str(crashes),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "6",
                "--seed-rng",
                "3",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "crash seed(s)" in out
        assert (out_dir / "results.jsonl").exists()


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

    def test_fuzz_adaptive_strategy_cli(self, tmp_path, monkeypatch, capsys):
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(
                Outcome.CRASH if i % 4 == 0 else Outcome.CLEAN,
                -signal.SIGSEGV if i % 4 == 0 else 0,
                "x" if i % 4 == 0 else "",
            ),
        )
        out_dir = tmp_path / "fuzz-out"
        rc = main(
            [
                "fuzz",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "12",
                "--decoder",
                "ffmpeg",
                "--strategy",
                "adaptive",
                "--seed-rng",
                "3",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "adaptive scheduler" in out
        assert "scoreboard written" in out
        assert (out_dir / "scheduler.json").exists()

    def test_fuzz_time_limit_cli(self, tmp_path, monkeypatch, capsys):
        _patch_decoder(
            monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, "")
        )
        # Patch the engine's time source so the budget expires deterministically
        # after a handful of reads — no real wall-clock wait, no flakiness.
        monkeypatch.setattr(engine.time, "monotonic", _FakeClock(0.0, 1.0))
        out_dir = tmp_path / "fuzz-out"
        rc = main(
            [
                "fuzz",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "100000",  # cap far above what the budget can reach
                "--time-limit",
                "2",
                "--decoder",
                "ffmpeg",
                "--seed-rng",
                "3",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "time-limited to 2s" in out
        assert "iteration cap" in out
        # The reported run is well under the cap (the budget truncated it).
        lines = (out_dir / "results.jsonl").read_text().strip().splitlines()
        assert 0 < len(lines) < 100000

    def test_fuzz_rejects_non_positive_time_limit_cli(self, tmp_path, capsys):
        rc = main(
            [
                "fuzz",
                "--seed",
                str(SEED),
                "--output-dir",
                str(tmp_path / "out"),
                "--time-limit",
                "0",
            ]
        )
        assert rc == 1
        err = capsys.readouterr().err
        assert "positive number of seconds" in err

    def test_fuzz_rejects_bad_strategy(self, tmp_path):
        # argparse 'choices' rejects an unknown strategy at parse time.
        import pytest

        with pytest.raises(SystemExit):
            main(
                [
                    "fuzz",
                    "--seed",
                    str(SEED),
                    "--output-dir",
                    str(tmp_path / "out"),
                    "--strategy",
                    "nope",
                ]
            )

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
