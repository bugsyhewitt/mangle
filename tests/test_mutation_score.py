"""Tests for the mutation-score reporter (POST_V01 mutation-testing leg)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mangle.cli import main
from mangle.mutation_score import (
    MutationScoreReport,
    MutatorScore,
    SeedScore,
    mutation_score,
    write_mutation_score,
)


def _write_results(
    out_dir: Path,
    iterations: list[dict],
) -> None:
    """Write a synthetic fuzz output dir with a results.jsonl.

    ``iterations`` is a list of partial result dicts; missing fields are filled
    with sensible defaults. Mirrors ``tests/test_coverage.py::_write_results``
    but kept local so the mutation-score tests stay self-contained.
    """
    out_dir.mkdir(parents=True, exist_ok=True)
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
            "base_seed": it.get("base_seed"),
        }
        lines.append(json.dumps(rec))
    (out_dir / "results.jsonl").write_text("\n".join(lines) + "\n")


class TestCampaignMutationScore:
    def test_score_is_killed_over_total(self, tmp_path):
        # 1 clean + 1 crash + 1 abort + 1 timeout = 3 killed / 4 total = 0.75
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "rps-overflow", "outcome": "abort", "crash_hash": "b"},
                {"mutator": "rps-overflow", "outcome": "timeout"},
            ],
        )
        report = mutation_score(tmp_path)
        assert report.total_iterations == 4
        assert report.killed_count == 3
        assert report.survived_count == 1
        assert report.score == pytest.approx(0.75)

    def test_hangs_count_as_killed(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "hang"},
            ],
        )
        report = mutation_score(tmp_path)
        assert report.killed_count == 1
        assert report.survived_count == 1
        assert report.score == pytest.approx(0.5)

    def test_zero_iterations_zero_score(self, tmp_path):
        (tmp_path / "results.jsonl").write_text("")
        report = mutation_score(tmp_path)
        assert report.total_iterations == 0
        assert report.killed_count == 0
        assert report.survived_count == 0
        assert report.score == 0.0

    def test_all_clean_score_is_zero(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
        )
        report = mutation_score(tmp_path)
        assert report.killed_count == 0
        assert report.score == 0.0

    def test_all_killed_score_is_one(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "rps-overflow", "outcome": "abort", "crash_hash": "b"},
            ],
        )
        report = mutation_score(tmp_path)
        assert report.killed_count == 2
        assert report.score == pytest.approx(1.0)

    def test_outcome_breakdown_counted(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "rps-overflow", "outcome": "timeout"},
                {"mutator": "rps-overflow", "outcome": "hang"},
            ],
        )
        report = mutation_score(tmp_path)
        assert report.outcomes["clean"] == 2
        assert report.outcomes["crash"] == 1
        assert report.outcomes["timeout"] == 1
        assert report.outcomes["hang"] == 1


class TestPerMutatorScore:
    def test_per_mutator_kill_ratio(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "b"},
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
        )
        report = mutation_score(tmp_path)
        by_name = {m.mutator: m for m in report.mutators}
        rps = by_name["rps-overflow"]
        assert rps.iterations == 3
        assert rps.killed == 2
        assert rps.survived == 1
        assert rps.score == pytest.approx(2 / 3)
        sps = by_name["sps-bit-depth"]
        assert sps.iterations == 2
        assert sps.killed == 0
        assert sps.score == 0.0

    def test_mutators_sorted_by_score_descending_then_name(self, tmp_path):
        _write_results(
            tmp_path,
            [
                # alpha: 0 killed / 1 = 0.0
                {"mutator": "alpha", "outcome": "clean"},
                # beta: 1 killed / 2 = 0.5
                {"mutator": "beta", "outcome": "clean"},
                {"mutator": "beta", "outcome": "crash", "crash_hash": "b"},
                # gamma: 1 killed / 1 = 1.0
                {"mutator": "gamma", "outcome": "crash", "crash_hash": "g"},
                # delta: same score as gamma (1.0) — name tiebreak
                {"mutator": "delta", "outcome": "abort", "crash_hash": "d"},
            ],
        )
        names = [m.mutator for m in mutation_score(tmp_path).mutators]
        # gamma=1.0, delta=1.0 (name tiebreak: delta < gamma), beta=0.5, alpha=0.0
        assert names == ["delta", "gamma", "beta", "alpha"]

    def test_mutator_outcomes_breakdown(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "rps-overflow", "outcome": "abort", "crash_hash": "b"},
            ],
        )
        rps = next(
            m for m in mutation_score(tmp_path).mutators if m.mutator == "rps-overflow"
        )
        assert rps.outcomes["clean"] == 1
        assert rps.outcomes["crash"] == 1
        assert rps.outcomes["abort"] == 1


class TestPerSeedScore:
    def test_per_base_seed_grouping(self, tmp_path):
        # Three base seeds with different yields. base_seed=None bucket aggregates
        # the single-seed (--seed) campaigns.
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "x",
                 "base_seed": "clean.h265"},
                {"mutator": "rps-overflow", "outcome": "clean",
                 "base_seed": "clean.h265"},
                {"mutator": "rps-overflow", "outcome": "clean",
                 "base_seed": "sei.h265"},
                {"mutator": "rps-overflow", "outcome": "clean",
                 "base_seed": "sei.h265"},
            ],
        )
        report = mutation_score(tmp_path)
        by_seed = {s.base_seed: s for s in report.seeds}
        assert by_seed["clean.h265"].iterations == 2
        assert by_seed["clean.h265"].killed == 1
        assert by_seed["clean.h265"].score == pytest.approx(0.5)
        assert by_seed["sei.h265"].iterations == 2
        assert by_seed["sei.h265"].killed == 0

    def test_single_seed_campaign_emits_none_bucket(self, tmp_path):
        # A v0.1-shape --seed campaign records base_seed=None on every row. The
        # per-seed list still has one entry (the implicit-seed bucket) so the
        # report shape is stable.
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "x"},
                {"mutator": "rps-overflow", "outcome": "clean"},
            ],
        )
        report = mutation_score(tmp_path)
        assert len(report.seeds) == 1
        assert report.seeds[0].base_seed is None
        assert report.seeds[0].iterations == 2
        assert report.seeds[0].killed == 1


class TestEdges:
    def test_ignores_blank_lines(self, tmp_path):
        (tmp_path / "results.jsonl").write_text(
            json.dumps(
                {
                    "iteration": 0,
                    "mutator": "rps-overflow",
                    "seed_rng": 0,
                    "outcome": "crash",
                    "returncode": -11,
                    "bytes_changed": 1,
                    "detail": "x",
                    "crash_hash": "a",
                }
            )
            + "\n\n\n"
        )
        report = mutation_score(tmp_path)
        assert report.total_iterations == 1
        assert report.killed_count == 1

    def test_missing_results_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            mutation_score(tmp_path / "nope")

    def test_deterministic(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
        )
        first = mutation_score(tmp_path)
        second = mutation_score(tmp_path)
        assert [m.mutator for m in first.mutators] == [
            m.mutator for m in second.mutators
        ]
        assert first.score == second.score
        assert [s.base_seed for s in first.seeds] == [
            s.base_seed for s in second.seeds
        ]

    def test_unknown_outcome_preserved_in_breakdown_but_not_killed(self, tmp_path):
        # An out-of-spec outcome string is not a known kill or survive — count it
        # in the breakdown but exclude it from killed/survived so the score stays
        # honest. Belt-and-braces against a future engine outcome we don't know
        # about yet.
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "clean"},
                {"mutator": "rps-overflow", "outcome": "weird-new-state"},
            ],
        )
        report = mutation_score(tmp_path)
        assert report.outcomes["weird-new-state"] == 1
        assert report.killed_count == 0
        assert report.survived_count == 1
        assert report.total_iterations == 2


class TestWriteMutationScore:
    def test_writes_json(self, tmp_path):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
        )
        report = write_mutation_score(tmp_path)
        path = tmp_path / "mutation-score.json"
        assert path.exists()
        obj = json.loads(path.read_text())
        for key in (
            "total_iterations",
            "killed_count",
            "survived_count",
            "score",
            "outcomes",
            "mutators",
            "seeds",
        ):
            assert key in obj
        assert isinstance(obj["mutators"], list)
        assert obj["score"] == pytest.approx(report.score)

    def test_mutator_schema_in_json(self, tmp_path):
        _write_results(
            tmp_path,
            [{"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"}],
        )
        write_mutation_score(tmp_path)
        obj = json.loads((tmp_path / "mutation-score.json").read_text())
        m = obj["mutators"][0]
        for key in ("mutator", "iterations", "killed", "survived", "score", "outcomes"):
            assert key in m


class TestMutationScoreCli:
    def test_cli_runs(self, tmp_path, capsys):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "sps-bit-depth", "outcome": "clean"},
            ],
        )
        rc = main(["mutation-score", "--output-dir", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "mutation score" in out.lower()
        assert (tmp_path / "mutation-score.json").exists()

    def test_cli_missing_dir_errors(self, tmp_path, capsys):
        rc = main(["mutation-score", "--output-dir", str(tmp_path / "nope")])
        assert rc == 1
        assert "error:" in capsys.readouterr().err

    def test_cli_prints_per_mutator_breakdown(self, tmp_path, capsys):
        _write_results(
            tmp_path,
            [
                {"mutator": "rps-overflow", "outcome": "crash", "crash_hash": "a"},
                {"mutator": "rps-overflow", "outcome": "clean"},
            ],
        )
        rc = main(["mutation-score", "--output-dir", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "rps-overflow" in out


def test_dataclasses_constructible():
    ms = MutatorScore(mutator="m")
    assert ms.iterations == 0
    assert ms.killed == 0
    assert ms.score == 0.0
    ss = SeedScore(base_seed=None)
    assert ss.iterations == 0
    rep = MutationScoreReport()
    assert rep.total_iterations == 0
    assert rep.score == 0.0
    assert rep.mutators == []
    assert rep.seeds == []
