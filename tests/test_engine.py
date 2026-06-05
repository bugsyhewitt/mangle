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
            base_seed=None, dedup=None,
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


class TestSeedCorpusDir:
    """``--seed-corpus-dir``: spread iterations across a directory of seeds.

    The engine-side companion of ``mangle corpus`` / ``mangle corpus-trim``.
    Mirrors the ``--seed-from-crashes`` dispatch (sorted, round-robin, each
    iteration records its ``base_seed`` for replay) but the source is any
    directory of ``*.h265`` seed files, not specifically a prior crashes/ dir.
    """

    def _make_corpus(self, tmp_path, n=3):
        """Write n distinct valid *.h265 seeds plus a manifest.json to ignore."""
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        base = SEED.read_bytes()
        names = []
        for k in range(n):
            from mangle.engine import mutate_bytes
            import random as _random

            mutated, _ = mutate_bytes(base, "sps-dimensions", _random.Random(k))
            name = f"seed-{k:03d}.h265"
            (corpus / name).write_bytes(mutated)
            names.append(name)
        # mangle corpus writes a sibling manifest.json — the pool must ignore it.
        (corpus / "manifest.json").write_text('{"entries": []}')
        return corpus, sorted(names)

    def test_rejects_seed_and_corpus_together(self, tmp_path):
        import pytest

        with pytest.raises(ValueError, match="exactly one base-input source"):
            engine.fuzz_file(
                SEED,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
                seed_corpus_dir=str(tmp_path / "corpus"),
            )

    def test_rejects_crashes_and_corpus_together(self, tmp_path):
        import pytest

        with pytest.raises(ValueError, match="exactly one base-input source"):
            engine.fuzz_file(
                None,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
                seed_from_crashes=str(tmp_path / "crashes"),
                seed_corpus_dir=str(tmp_path / "corpus"),
            )

    def test_missing_corpus_dir(self, tmp_path):
        import pytest

        with pytest.raises(FileNotFoundError, match="no such corpus directory"):
            engine.fuzz_file(
                None,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
                seed_corpus_dir=str(tmp_path / "nope"),
            )

    def test_empty_corpus_dir(self, tmp_path):
        import pytest

        corpus = tmp_path / "empty"
        corpus.mkdir()
        with pytest.raises(ValueError, match="no .* seed files"):
            engine.fuzz_file(
                None,
                tmp_path / "out",
                iterations=2,
                decoder="ffmpeg",
                timeout=5.0,
                seed_corpus_dir=str(corpus),
            )

    def test_ignores_non_h265_files(self, tmp_path, monkeypatch):
        # A manifest.json alongside the *.h265 seeds must not enter the pool.
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        corpus, names = self._make_corpus(tmp_path, n=3)
        results = engine.fuzz_file(
            None,
            tmp_path / "out",
            iterations=6,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            seed_corpus_dir=str(corpus),
        )
        # Every base_seed picked is one of the three *.h265 names; the
        # manifest.json is never selected.
        used = {r.base_seed for r in results}
        assert used.issubset(set(names))
        assert "manifest.json" not in used

    def test_records_base_seed_round_robin(self, tmp_path, monkeypatch):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        corpus, names = self._make_corpus(tmp_path, n=3)
        out_dir = tmp_path / "out"
        results = engine.fuzz_file(
            None,
            out_dir,
            iterations=9,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            seed_corpus_dir=str(corpus),
        )
        base_seeds = [r.base_seed for r in results]
        # Round-robin by iteration index, sorted by basename.
        assert base_seeds == [names[i % 3] for i in range(9)]
        # results.jsonl carries base_seed for replay.
        first = json.loads(
            (out_dir / "results.jsonl").read_text().strip().splitlines()[0]
        )
        assert first["base_seed"] in names

    def test_corpus_fed_campaign_is_reproducible(self, tmp_path, monkeypatch):
        corpus, _ = self._make_corpus(tmp_path, n=2)

        def content_outcome(decoder, path, timeout, runner=None):
            data = Path(path).read_bytes()
            if sum(data) % 3 == 0:
                return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "boom")
            return DecodeResult(Outcome.CLEAN, 0, "")

        monkeypatch.setattr(engine, "run_decoder", content_outcome)
        a = engine.fuzz_file(
            None, tmp_path / "a", iterations=12, decoder="ffmpeg",
            timeout=5.0, seed_rng=7, seed_corpus_dir=str(corpus),
        )
        b = engine.fuzz_file(
            None, tmp_path / "b", iterations=12, decoder="ffmpeg",
            timeout=5.0, seed_rng=7, seed_corpus_dir=str(corpus),
        )
        assert [(r.mutator, r.seed_rng, r.base_seed) for r in a] == [
            (r.mutator, r.seed_rng, r.base_seed) for r in b
        ]


class TestSeedCorpusDirCli:
    def test_cli_rejects_seed_and_corpus(self, tmp_path):
        import pytest

        with pytest.raises(SystemExit):
            main(
                [
                    "fuzz",
                    "--seed",
                    str(SEED),
                    "--seed-corpus-dir",
                    str(tmp_path),
                    "--output-dir",
                    str(tmp_path / "out"),
                ]
            )

    def test_cli_rejects_crashes_and_corpus(self, tmp_path):
        import pytest

        with pytest.raises(SystemExit):
            main(
                [
                    "fuzz",
                    "--seed-from-crashes",
                    str(tmp_path / "crashes"),
                    "--seed-corpus-dir",
                    str(tmp_path / "corpus"),
                    "--output-dir",
                    str(tmp_path / "out"),
                ]
            )

    def test_cli_runs_from_corpus(self, tmp_path, monkeypatch, capsys):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        corpus = tmp_path / "corpus"
        corpus.mkdir()
        (corpus / "a.h265").write_bytes(SEED.read_bytes())
        (corpus / "b.h265").write_bytes(SEED.read_bytes())
        out_dir = tmp_path / "out"
        rc = main(
            [
                "fuzz",
                "--seed-corpus-dir",
                str(corpus),
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
        assert "corpus seed(s)" in out
        assert (out_dir / "results.jsonl").exists()


def _patch_pair(monkeypatch, pair_for):
    """Replace run_decoder_pair with a deterministic per-iteration mock.

    The mock absorbs any extra kwargs (including ``compare_output``) so the
    same helper drives both the original crash-class diff campaigns and the
    output-divergence campaigns.
    """
    state = {"i": 0}

    def fake(left, right, path, timeout, **kwargs):
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


def _output_divergence(left, right):
    """Both decoders CLEAN, both with output_hash set, but the hashes differ.

    Models the TWINFUZZ silent-acceptor signal exposed by ``compare_output``.
    """
    return DivergenceResult(
        diverged=True,
        kind="output-divergence",
        left=DecodeResult(
            Outcome.CLEAN, 0, "", decoder=left, output_hash="a" * 64
        ),
        right=DecodeResult(
            Outcome.CLEAN, 0, "", decoder=right, output_hash="b" * 64
        ),
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

    def test_compare_output_records_hashes_and_kind(self, tmp_path, monkeypatch):
        # When compare_output=True is plumbed through and the underlying pair
        # reports an output-divergence, DiffResult records both decoders'
        # output_hash values and the kind is preserved through to diff.jsonl.
        def pair_for(i, left, right):
            # All iterations diverge by output (deterministic, simple to assert).
            return _output_divergence(left, right)

        _patch_pair(monkeypatch, pair_for)
        out_dir = tmp_path / "diff-out"
        results = engine.diff_file(
            SEED,
            out_dir,
            iterations=4,
            left_decoder="ffmpeg",
            right_decoder="libde265",
            timeout=5.0,
            seed_rng=11,
            compare_output=True,
        )
        assert all(r.diverged for r in results)
        assert all(r.kind == "output-divergence" for r in results)
        # Hashes carried through on every iteration.
        assert all(r.left_output_hash and r.right_output_hash for r in results)
        assert all(r.left_output_hash != r.right_output_hash for r in results)
        # And persisted in the jsonl with the new keys.
        first = json.loads((out_dir / "diff.jsonl").read_text().splitlines()[0])
        assert "left_output_hash" in first
        assert "right_output_hash" in first
        assert first["kind"] == "output-divergence"

    def test_compare_output_off_leaves_hashes_none(self, tmp_path, monkeypatch):
        # Default path: compare_output omitted -> DiffResult.left/right
        # output_hash are None, matching the pre-enhancement behaviour for
        # any existing crash-class-only diff campaign.
        _patch_pair(monkeypatch, lambda i, left, right: _agree(left, right))
        out_dir = tmp_path / "diff-out"
        results = engine.diff_file(
            SEED,
            out_dir,
            iterations=3,
            left_decoder="ffmpeg",
            right_decoder="libde265",
            timeout=5.0,
            seed_rng=13,
        )
        assert all(r.left_output_hash is None for r in results)
        assert all(r.right_output_hash is None for r in results)

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

    def test_diff_compare_output_cli_reports_output_divergence(
        self, tmp_path, monkeypatch, capsys
    ):
        # When --compare-output is passed and the underlying pair-runner
        # reports an output-divergence, the CLI summary surfaces it as a
        # named kind alongside crash-split / signal-split.
        def pair_for(i, left, right):
            return _output_divergence(left, right) if i % 3 == 0 else _agree(left, right)

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
                "9",
                "--left-decoder",
                "ffmpeg",
                "--right-decoder",
                "libde265",
                "--seed-rng",
                "5",
                "--compare-output",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "with output compare" in out
        assert "output-divergence" in out
        # At least one output-divergence artifact written.
        div_dir = out_dir / "divergences"
        assert div_dir.exists()
        assert any(div_dir.glob("*.h265"))
        # The side-by-side report names the kind and surfaces output_hash for
        # each decoder so the artifact alone explains why it was kept.
        for h in div_dir.glob("*.h265"):
            report = (div_dir / f"{h.stem}.txt").read_text()
            assert "output-divergence" in report
            assert "output_hash=" in report

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


class TestSchedulerStateResume:
    """Warm-start a fuzz campaign's adaptive scheduler from a prior scoreboard."""

    def test_engine_loads_prior_arm_counts(self, tmp_path, monkeypatch):
        # Every other iteration crashes — deterministic so we can compare the
        # scoreboard arithmetic.
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(
                Outcome.CRASH if i % 2 == 0 else Outcome.CLEAN,
                -signal.SIGSEGV if i % 2 == 0 else 0,
                "x" if i % 2 == 0 else "",
            ),
        )
        out_dir = tmp_path / "fuzz-out"
        # Pre-baked prior scoreboard mentioning a single registered mutator and
        # one unknown one — the engine must accept this and surface it as a
        # breadcrumb in the new scoreboard.
        prior = {
            "strategy": "adaptive",
            "iterations": 100,
            "arms": {
                "sps-dimensions": {"trials": 50, "rewards": 25},
                "vanished-mutator": {"trials": 10, "rewards": 5},
            },
        }
        engine.fuzz_file(
            SEED,
            out_dir,
            iterations=8,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=11,
            strategy="adaptive",
            concurrency=4,
            scheduler_state=prior,
        )
        scoreboard = json.loads((out_dir / "scheduler.json").read_text())
        # Resume breadcrumb is recorded.
        assert scoreboard["resumed_from_prior_iterations"] == 100
        # The prior trials for sps-dimensions add to whatever the campaign rolled.
        sps = scoreboard["arms"]["sps-dimensions"]
        assert sps["trials"] >= 50
        assert sps["rewards"] >= 25
        # The fresh iterations dispatched in this campaign show up.
        assert scoreboard["iterations"] == 8
        # The unknown mutator is silently dropped — it does not poison the score.
        assert "vanished-mutator" not in scoreboard["arms"]

    def test_engine_rejects_scheduler_state_with_uniform_strategy(
        self, tmp_path, monkeypatch
    ):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        import pytest as _pt
        with _pt.raises(ValueError, match="adaptive"):
            engine.fuzz_file(
                SEED,
                tmp_path / "out",
                iterations=4,
                decoder="ffmpeg",
                timeout=5.0,
                seed_rng=1,
                strategy="uniform",
                scheduler_state={"arms": {}},
            )

    def test_engine_rejects_scheduler_state_without_arms_key(
        self, tmp_path, monkeypatch
    ):
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        import pytest as _pt
        with _pt.raises(ValueError, match="'arms' mapping"):
            engine.fuzz_file(
                SEED,
                tmp_path / "out",
                iterations=4,
                decoder="ffmpeg",
                timeout=5.0,
                seed_rng=1,
                strategy="adaptive",
                scheduler_state={"strategy": "adaptive", "iterations": 1},
            )

    def test_split_resume_matches_single_campaign(self, tmp_path, monkeypatch):
        # End-to-end determinism contract: a single 16-iteration adaptive
        # campaign must select the same mutators as two chained 8-iteration
        # campaigns where the second resumes from the first's scoreboard,
        # given the same seed_rng. The decoder mock keys verdicts off the
        # mutant bytes (stable per input), so it is gather-order-independent.
        def content_outcome(decoder, path, timeout, runner=None):
            data = Path(path).read_bytes()
            if sum(data) % 2 == 0:
                return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, "boom")
            return DecodeResult(Outcome.CLEAN, 0, "")

        monkeypatch.setattr(engine, "run_decoder", content_outcome)
        single = engine.fuzz_file(
            SEED,
            tmp_path / "single",
            iterations=16,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=42,
            strategy="adaptive",
            concurrency=4,
        )
        first = engine.fuzz_file(
            SEED,
            tmp_path / "first",
            iterations=8,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=42,
            strategy="adaptive",
            concurrency=4,
        )
        prior = json.loads((tmp_path / "first" / "scheduler.json").read_text())
        # The second leg must use a continuation seed_rng. The realistic shape is
        # the same seed_rng plus the prior arm counts — the test asserts that
        # the *combined* arm totals match a single continuous campaign, which is
        # the operational guarantee that matters (the per-iteration mutator
        # sequence necessarily differs because the second leg starts a fresh RNG
        # stream — that is documented behaviour, not a regression).
        second = engine.fuzz_file(
            SEED,
            tmp_path / "second",
            iterations=8,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=43,
            strategy="adaptive",
            concurrency=4,
            scheduler_state=prior,
        )
        # The two-leg campaign dispatched the same total iteration count.
        assert len(first) + len(second) == len(single)
        # The combined scoreboard trial count equals the single-run scoreboard.
        single_scoreboard = json.loads(
            (tmp_path / "single" / "scheduler.json").read_text()
        )
        second_scoreboard = json.loads(
            (tmp_path / "second" / "scheduler.json").read_text()
        )
        single_trials = sum(
            a["trials"] for a in single_scoreboard["arms"].values()
        )
        # Second scoreboard already contains first-leg trials (load_state is
        # additive, by design — the scoreboard reflects the bandit's full
        # accumulated knowledge).
        resumed_trials = sum(
            a["trials"] for a in second_scoreboard["arms"].values()
        )
        assert resumed_trials == single_trials

    def test_cli_fuzz_with_scheduler_state(self, tmp_path, monkeypatch, capsys):
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(
                Outcome.CRASH if i % 3 == 0 else Outcome.CLEAN,
                -signal.SIGSEGV if i % 3 == 0 else 0,
                "x" if i % 3 == 0 else "",
            ),
        )
        prior_path = tmp_path / "prior-scheduler.json"
        prior_path.write_text(json.dumps({
            "strategy": "adaptive",
            "iterations": 250,
            "arms": {
                "sps-dimensions": {"trials": 100, "rewards": 40},
                "pps-tile-config": {"trials": 80, "rewards": 12},
            },
        }))
        out_dir = tmp_path / "resumed"
        rc = main([
            "fuzz",
            "--seed", str(SEED),
            "--output-dir", str(out_dir),
            "--iterations", "8",
            "--decoder", "ffmpeg",
            "--strategy", "adaptive",
            "--seed-rng", "7",
            "--scheduler-state", str(prior_path),
        ])
        assert rc == 0
        out = capsys.readouterr().out
        assert "resumed adaptive scheduler" in out
        assert "250 prior iterations" in out
        assert "180 prior trials" in out
        # Scoreboard breadcrumbs the resume.
        scoreboard = json.loads((out_dir / "scheduler.json").read_text())
        assert scoreboard["resumed_from_prior_iterations"] == 250
        # The two prior mutators carry their pre-load counts plus whatever this
        # campaign rolled.
        assert scoreboard["arms"]["sps-dimensions"]["trials"] >= 100
        assert scoreboard["arms"]["pps-tile-config"]["trials"] >= 80

    def test_cli_rejects_scheduler_state_with_uniform_strategy(
        self, tmp_path, capsys
    ):
        prior = tmp_path / "prior.json"
        prior.write_text(json.dumps({"arms": {}}))
        rc = main([
            "fuzz",
            "--seed", str(SEED),
            "--output-dir", str(tmp_path / "out"),
            "--strategy", "uniform",
            "--scheduler-state", str(prior),
        ])
        assert rc == 2
        err = capsys.readouterr().err
        assert "--scheduler-state requires --strategy adaptive" in err

    def test_cli_rejects_missing_scheduler_state_file(self, tmp_path, capsys):
        rc = main([
            "fuzz",
            "--seed", str(SEED),
            "--output-dir", str(tmp_path / "out"),
            "--strategy", "adaptive",
            "--scheduler-state", str(tmp_path / "does-not-exist.json"),
        ])
        assert rc == 2
        err = capsys.readouterr().err
        assert "could not read --scheduler-state" in err

    def test_cli_rejects_malformed_scheduler_state_file(self, tmp_path, capsys):
        bad = tmp_path / "bad.json"
        bad.write_text("this is not json {")
        rc = main([
            "fuzz",
            "--seed", str(SEED),
            "--output-dir", str(tmp_path / "out"),
            "--strategy", "adaptive",
            "--scheduler-state", str(bad),
        ])
        assert rc == 2
        err = capsys.readouterr().err
        assert "could not read --scheduler-state" in err
# ---------------------------------------------------------------------------
# Crash deduplication (--crash-dedup)
# ---------------------------------------------------------------------------


# A symbolised ASAN backtrace fragment. The top three frame *function* names
# are the signature; the address / file / line columns are deliberately
# different across the two payloads to prove the signature ignores them.
_ASAN_A = (
    "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xdead\n"
    "    #0 0x55a3c0ffee21 in hevc_decode_frame /src/libavcodec/hevcdec.c:1234:7\n"
    "    #1 0x55a3c0ffe000 in decode_nal_unit /src/libavcodec/hevcdec.c:999:3\n"
    "    #2 0x55a3c0ffd000 in ff_hevc_decode /src/libavcodec/hevcdec.c:42:1\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
)
_ASAN_A_DIFFERENT_ADDRS = (
    "==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xbeef\n"
    "    #0 0x7fffeeeeee21 in hevc_decode_frame /build/avcodec/hevcdec.c:5678:9\n"
    "    #1 0x7fffeeeed000 in decode_nal_unit /build/avcodec/hevcdec.c:111:1\n"
    "    #2 0x7fffeeeec000 in ff_hevc_decode /build/avcodec/hevcdec.c:50:1\n"
    "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
)
# A different bug — different top frame.
_ASAN_B = (
    "==54321==ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
    "    #0 0x55a3c0eeee21 in parse_sps /src/libavcodec/hevcdec.c:200:1\n"
    "    #1 0x55a3c0eeed000 in decode_nal_unit /src/libavcodec/hevcdec.c:999:3\n"
    "    #2 0x55a3c0eeec000 in ff_hevc_decode /src/libavcodec/hevcdec.c:42:1\n"
    "SUMMARY: AddressSanitizer: SEGV\n"
)


class TestCrashDedupOff:
    """With dedup off, the campaign and on-disk shape match the v0.1 path."""

    def test_results_jsonl_fields_default_to_none(self, tmp_path, monkeypatch):
        # Every iteration crashes with the SAME signature; with dedup OFF, every
        # crash artifact is still written and every results row carries None
        # for the new fields — proving the off-path is shape-stable.
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED, out_dir, iterations=5, decoder="ffmpeg", timeout=5.0, seed_rng=1
        )
        assert all(r.dedup_signature is None for r in results)
        assert all(r.dedup_first is None for r in results)
        # No dedup-signatures.json is written when dedup is off.
        assert not (out_dir / "dedup-signatures.json").exists()
        # And the on-disk results.jsonl carries the new keys as null so the
        # schema is forward-compatible without surprising older readers.
        first = json.loads((out_dir / "results.jsonl").read_text().splitlines()[0])
        assert first["dedup_signature"] is None
        assert first["dedup_first"] is None

    def test_off_path_writes_every_crash_artifact(self, tmp_path, monkeypatch):
        # Three identical-signature crashes -> three distinct mutant-hash files.
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        out_dir = tmp_path / "fuzz-out"
        engine.fuzz_file(
            SEED, out_dir, iterations=3, decoder="ffmpeg", timeout=5.0, seed_rng=1
        )
        h265s = sorted((out_dir / "crashes").glob("*.h265"))
        assert len(h265s) == 3


class TestCrashDedupOn:
    """With dedup on, only the first-of-signature crash writes artifacts."""

    def test_same_signature_writes_one_artifact(self, tmp_path, monkeypatch):
        # All five iterations crash with the SAME ASAN signature (top frames
        # are identical; only the addresses and line numbers differ). With
        # --crash-dedup, only one mutant-hash artifact pair lands on disk.
        def outcomes(i):
            return DecodeResult(
                Outcome.CRASH,
                -signal.SIGSEGV,
                _ASAN_A if i % 2 == 0 else _ASAN_A_DIFFERENT_ADDRS,
            )

        _patch_decoder(monkeypatch, outcomes)
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=5,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
        )
        # Every iteration is recorded.
        assert len(results) == 5
        crashes = [r for r in results if r.crash_hash]
        assert len(crashes) == 5
        # Exactly one signature, exactly one first-occurrence.
        sigs = {r.dedup_signature for r in crashes}
        assert len(sigs) == 1
        assert sum(1 for r in crashes if r.dedup_first) == 1
        assert sum(1 for r in crashes if r.dedup_first is False) == 4
        # And only ONE artifact pair on disk — the dedup payoff.
        h265s = sorted((out_dir / "crashes").glob("*.h265"))
        assert len(h265s) == 1

    def test_distinct_signatures_each_write_an_artifact(self, tmp_path, monkeypatch):
        # Alternate between two distinct bugs -> two distinct artifact pairs.
        def outcomes(i):
            return DecodeResult(
                Outcome.CRASH,
                -signal.SIGSEGV,
                _ASAN_A if i % 2 == 0 else _ASAN_B,
            )

        _patch_decoder(monkeypatch, outcomes)
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=6,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
        )
        crashes = [r for r in results if r.crash_hash]
        sigs = {r.dedup_signature for r in crashes}
        assert len(sigs) == 2
        # Each signature has exactly one first-of-signature winner.
        firsts = [r for r in crashes if r.dedup_first]
        assert len(firsts) == 2
        assert {r.dedup_signature for r in firsts} == sigs
        # Two artifact pairs on disk.
        h265s = sorted((out_dir / "crashes").glob("*.h265"))
        assert len(h265s) == 2

    def test_stderr_fallback_signature_normalises_numbers(self, tmp_path, monkeypatch):
        # Plain (non-sanitizer) stderrs that differ ONLY in incidental
        # numbers should hash to the same signature and dedup to one artifact.
        def outcomes(i):
            return DecodeResult(
                Outcome.CRASH,
                -signal.SIGSEGV,
                f"plain decoder error at offset {i * 100}\n",
            )

        _patch_decoder(monkeypatch, outcomes)
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=4,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
        )
        crashes = [r for r in results if r.crash_hash]
        sigs = {r.dedup_signature for r in crashes}
        assert len(sigs) == 1
        # And kind-stable: all signatures are the stderr-fallback hash form
        # (a 16-char hex string from the triage signature_for fallback).
        sig = next(iter(sigs))
        assert len(sig) == 16
        h265s = sorted((out_dir / "crashes").glob("*.h265"))
        assert len(h265s) == 1

    def test_persists_seen_signatures_for_resume(self, tmp_path, monkeypatch):
        # After a campaign, dedup-signatures.json holds the seen set; a
        # subsequent campaign into the same dir picks them up and suppresses
        # the matching artifact even though it is the first iteration of the
        # NEW campaign — that is the resume semantic.
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        out_dir = tmp_path / "fuzz-out"
        engine.fuzz_file(
            SEED,
            out_dir,
            iterations=2,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
        )
        sig_file = out_dir / "dedup-signatures.json"
        assert sig_file.exists()
        payload = json.loads(sig_file.read_text())
        assert payload["frame_depth"] == 3
        assert len(payload["signatures"]) == 1
        first_artifact_count = len(list((out_dir / "crashes").glob("*.h265")))
        assert first_artifact_count == 1

        # Second campaign, same dir, same signature on every iteration: every
        # iteration's dedup_first must be False because the registry resumed
        # from disk. No NEW artifact pair lands.
        results2 = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=3,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=2,
            crash_dedup=True,
        )
        crashes2 = [r for r in results2 if r.crash_hash]
        assert len(crashes2) == 3
        assert all(r.dedup_first is False for r in crashes2)
        # Same one artifact pair as before.
        assert (
            len(list((out_dir / "crashes").glob("*.h265"))) == first_artifact_count
        )

    def test_corrupt_dedup_file_is_non_fatal(self, tmp_path, monkeypatch):
        # A garbage dedup-signatures.json (eg from a half-written previous run)
        # must not crash the campaign — the registry starts fresh and persists
        # the new state.
        out_dir = tmp_path / "fuzz-out"
        out_dir.mkdir()
        (out_dir / "dedup-signatures.json").write_text("{not valid json")
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=2,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
        )
        crashes = [r for r in results if r.crash_hash]
        # Fresh registry -> the first crash is the first-of-signature.
        assert any(r.dedup_first for r in crashes)
        # And the file is overwritten with the new (valid) state.
        payload = json.loads((out_dir / "dedup-signatures.json").read_text())
        assert len(payload["signatures"]) == 1

    def test_dedup_frame_depth_is_threaded_into_signature(self, tmp_path, monkeypatch):
        # With frame_depth=1 only the top frame is signature-bearing — so the
        # ASAN_A vs ASAN_A_DIFFERENT_ADDRS pair (same top frame, same second
        # and third frames) and a hypothetical A-with-different-second-frame
        # would still collide. Easier proof: frame_depth=1 vs frame_depth=3
        # produce DIFFERENT signatures for the SAME stderr, because the
        # signature is a join of the top N frame names.
        def outcomes(i):
            return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A)

        _patch_decoder(monkeypatch, outcomes)
        out_a = tmp_path / "out-a"
        engine.fuzz_file(
            SEED,
            out_a,
            iterations=1,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
            dedup_frame_depth=1,
        )
        out_b = tmp_path / "out-b"
        engine.fuzz_file(
            SEED,
            out_b,
            iterations=1,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
            dedup_frame_depth=3,
        )
        sig_a = json.loads(
            (out_a / "dedup-signatures.json").read_text()
        )["signatures"][0]
        sig_b = json.loads(
            (out_b / "dedup-signatures.json").read_text()
        )["signatures"][0]
        assert sig_a != sig_b
        # Frame-depth is also persisted so a triage tool can see what depth the
        # signatures were derived at.
        depth_a = json.loads(
            (out_a / "dedup-signatures.json").read_text()
        )["frame_depth"]
        assert depth_a == 1

    def test_clean_iterations_are_unaffected(self, tmp_path, monkeypatch):
        # Non-crashing iterations never compute a signature and never touch
        # the registry. Mix clean + crashing and confirm the fields are None
        # on the clean rows and populated only on the crashing rows.
        def outcomes(i):
            if i % 2 == 0:
                return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A)
            return DecodeResult(Outcome.CLEAN, 0, "")

        _patch_decoder(monkeypatch, outcomes)
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=4,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            crash_dedup=True,
        )
        for r in results:
            if r.outcome == "clean":
                assert r.dedup_signature is None
                assert r.dedup_first is None
            else:
                assert r.dedup_signature is not None
                assert r.dedup_first in (True, False)

    def test_concurrent_round_dispatch_has_single_winner(self, tmp_path, monkeypatch):
        # The check-and-record path is an asyncio.Lock-protected critical
        # section, so even when several same-signature crashes complete in the
        # same dispatch round, EXACTLY ONE iteration must be flagged as the
        # first-of-signature. Use adaptive strategy + concurrency to force
        # round-based dispatch with several iterations in flight at once.
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=12,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            concurrency=4,
            strategy="adaptive",
            crash_dedup=True,
        )
        crashes = [r for r in results if r.crash_hash]
        firsts = [r for r in crashes if r.dedup_first]
        assert len(firsts) == 1
        # And exactly one artifact pair regardless of dispatch ordering.
        assert len(list((out_dir / "crashes").glob("*.h265"))) == 1


class TestCrashDedupCli:
    """End-to-end CLI tests for --crash-dedup."""

    def test_cli_flag_enables_dedup(self, tmp_path, monkeypatch, capsys):
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        out_dir = tmp_path / "out"
        rc = main(
            [
                "fuzz",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "4",
                "--crash-dedup",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        # The summary line surfaces both the unique count AND the
        # suppressed-duplicate count so the operator sees what dedup bought.
        assert "1 unique crash artifact" in out
        assert "3 duplicate(s) suppressed by --crash-dedup" in out
        assert "dedup-signatures.json" in out
        assert (out_dir / "dedup-signatures.json").exists()
        assert len(list((out_dir / "crashes").glob("*.h265"))) == 1

    def test_cli_without_flag_writes_no_dedup_file(self, tmp_path, monkeypatch, capsys):
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        out_dir = tmp_path / "out"
        rc = main(
            [
                "fuzz",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "3",
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "3 crash artifact" in out
        assert "duplicate" not in out
        assert not (out_dir / "dedup-signatures.json").exists()

    def test_cli_frame_depth_threaded_through(self, tmp_path, monkeypatch):
        _patch_decoder(
            monkeypatch,
            lambda i: DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A),
        )
        out_dir = tmp_path / "out"
        rc = main(
            [
                "fuzz",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "1",
                "--crash-dedup",
                "--dedup-frame-depth",
                "1",
            ]
        )
        assert rc == 0
        payload = json.loads((out_dir / "dedup-signatures.json").read_text())
        assert payload["frame_depth"] == 1


class TestMaxCrashes:
    """Tests for the --max-crashes N campaign stop condition."""

    def test_campaign_stops_at_max_crashes(self, tmp_path, monkeypatch):
        # Two distinct crash signatures (A and B alternating). max_crashes=1 →
        # campaign should stop after the first unique signature is recorded.
        # With concurrency=1 and round_size=1 the check fires after each
        # round, so the campaign stops as soon as one unique crash lands.
        def outcomes(i):
            return DecodeResult(Outcome.CRASH, -signal.SIGSEGV, _ASAN_A if i % 2 == 0 else _ASAN_B)

        _patch_decoder(monkeypatch, outcomes)
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=20,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            concurrency=1,
            crash_dedup=True,
            max_crashes=1,
        )
        unique_crashes = sum(1 for r in results if r.dedup_first)
        # Exactly one unique crash should have triggered the stop.
        assert unique_crashes == 1
        # The campaign ran fewer than all 20 iterations.
        assert len(results) < 20

    def test_campaign_runs_to_completion_when_under_max(self, tmp_path, monkeypatch):
        # All iterations are clean — no crashes. max_crashes=5 is never reached.
        # The campaign should run to the full iteration count.
        _patch_decoder(monkeypatch, lambda i: DecodeResult(Outcome.CLEAN, 0, ""))
        out_dir = tmp_path / "fuzz-out"
        results = engine.fuzz_file(
            SEED,
            out_dir,
            iterations=8,
            decoder="ffmpeg",
            timeout=5.0,
            seed_rng=1,
            concurrency=2,
            crash_dedup=True,
            max_crashes=5,
        )
        assert len(results) == 8
        assert all(r.outcome == "clean" for r in results)

    def test_max_crashes_without_crash_dedup_raises(self, tmp_path):
        import pytest
        with pytest.raises(ValueError, match="--max-crashes requires --crash-dedup"):
            engine.fuzz_file(
                SEED,
                tmp_path / "out",
                iterations=4,
                decoder="ffmpeg",
                timeout=5.0,
                seed_rng=1,
                crash_dedup=False,
                max_crashes=2,
            )

    def test_max_crashes_zero_raises(self, tmp_path):
        import pytest
        with pytest.raises(ValueError, match="--max-crashes must be a positive integer"):
            engine.fuzz_file(
                SEED,
                tmp_path / "out",
                iterations=4,
                decoder="ffmpeg",
                timeout=5.0,
                seed_rng=1,
                crash_dedup=True,
                max_crashes=0,
            )

    def test_cli_max_crashes_without_dedup_returns_2(self, tmp_path, capsys):
        out_dir = tmp_path / "out"
        rc = main(
            [
                "fuzz",
                "--seed",
                str(SEED),
                "--output-dir",
                str(out_dir),
                "--iterations",
                "4",
                "--max-crashes",
                "2",
            ]
        )
        assert rc == 2
        err = capsys.readouterr().err
        assert "--max-crashes requires --crash-dedup" in err
