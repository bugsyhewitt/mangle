"""Tests for the corpus minimiser (mangle corpus-trim).

The trimmer's decode probe is injected, so these tests drive the full corpus
minimisation without ffmpeg/libde265 installed. The fake probes encode a
*behaviour-by-content* policy: a seed's behaviour is decided by its bytes, so we
can assert that the trimmer keeps exactly one representative per distinct
behaviour and that the representative is the smallest file (tie-broken by name).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mangle.corpus_trim import (
    BehaviourProbe,
    make_decoder_probe,
    trim_corpus,
    trim_corpus_dir,
)


# ---------------------------------------------------------------------------
# Behaviour-probe fakes
# ---------------------------------------------------------------------------


def _probe_by_first_byte(seed: bytes) -> BehaviourProbe:
    """Behaviour is decided by the seed's first byte.

    0x00 -> clean; 0xAA -> crash with signature "BUG-A"; 0xBB -> crash "BUG-B";
    0xCC -> timeout. Empty seeds are treated as clean.
    """
    if not seed:
        return BehaviourProbe(outcome="clean")
    tag = seed[0]
    if tag == 0xAA:
        return BehaviourProbe(outcome="crash", signature="BUG-A")
    if tag == 0xBB:
        return BehaviourProbe(outcome="crash", signature="BUG-B")
    if tag == 0xCC:
        return BehaviourProbe(outcome="timeout")
    return BehaviourProbe(outcome="clean")


class TestBehaviourProbe:
    def test_crash_key_includes_signature(self):
        p = BehaviourProbe(outcome="crash", signature="BUG-A")
        assert p.behaviour_key() == "crash:BUG-A"

    def test_abort_distinct_from_crash_same_signature(self):
        crash = BehaviourProbe(outcome="crash", signature="X")
        abort = BehaviourProbe(outcome="abort", signature="X")
        assert crash.behaviour_key() != abort.behaviour_key()

    def test_clean_key_is_outcome_only(self):
        assert BehaviourProbe(outcome="clean").behaviour_key() == "clean"

    def test_timeout_key_is_outcome_only(self):
        assert BehaviourProbe(outcome="timeout").behaviour_key() == "timeout"


class TestTrimCorpus:
    def test_collapses_identical_behaviour_to_one(self):
        # Three clean seeds -> one kept.
        seeds = [
            ("a.h265", b"\x00\x01"),
            ("b.h265", b"\x00\x02\x03"),
            ("c.h265", b"\x00\x04"),
        ]
        result = trim_corpus(seeds, _probe_by_first_byte)
        assert result.input_count == 3
        assert result.kept_count == 1
        assert result.dropped_count == 2
        assert result.behaviour_count == 1

    def test_keeps_smallest_representative(self):
        # All clean; smallest file (a, 2 bytes) must be the kept representative.
        seeds = [
            ("z.h265", b"\x00\x01\x02\x03"),
            ("a.h265", b"\x00\x01"),
            ("m.h265", b"\x00\x01\x02"),
        ]
        result = trim_corpus(seeds, _probe_by_first_byte)
        kept = [v.name for v in result.verdicts if v.kept]
        assert kept == ["a.h265"]
        # The dropped seeds point at the representative.
        for v in result.verdicts:
            if not v.kept:
                assert v.subsumed_by == "a.h265"

    def test_tie_broken_by_name(self):
        # Two clean seeds, same size -> the lexicographically-first name wins.
        seeds = [
            ("b.h265", b"\x00\x09"),
            ("a.h265", b"\x00\x09"),
        ]
        result = trim_corpus(seeds, _probe_by_first_byte)
        kept = [v.name for v in result.verdicts if v.kept]
        assert kept == ["a.h265"]

    def test_distinct_behaviours_all_kept(self):
        # One clean, one BUG-A crash, one BUG-B crash, one timeout -> 4 buckets.
        seeds = [
            ("clean.h265", b"\x00\x01"),
            ("a.h265", b"\xaa\x01"),
            ("b.h265", b"\xbb\x01"),
            ("t.h265", b"\xcc\x01"),
        ]
        result = trim_corpus(seeds, _probe_by_first_byte)
        assert result.behaviour_count == 4
        assert result.kept_count == 4
        assert result.dropped_count == 0

    def test_same_outcome_different_signature_kept_separately(self):
        # Both crash, but BUG-A vs BUG-B are different bugs -> both kept.
        seeds = [
            ("a1.h265", b"\xaa\x00"),
            ("a2.h265", b"\xaa\x00\x00"),  # redundant with a1 (BUG-A)
            ("b1.h265", b"\xbb\x00"),
        ]
        result = trim_corpus(seeds, _probe_by_first_byte)
        kept = sorted(v.name for v in result.verdicts if v.kept)
        assert kept == ["a1.h265", "b1.h265"]
        assert result.behaviour_count == 2

    def test_verdicts_in_sorted_name_order(self):
        seeds = [
            ("c.h265", b"\x00"),
            ("a.h265", b"\x00"),
            ("b.h265", b"\x00"),
        ]
        result = trim_corpus(seeds, _probe_by_first_byte)
        assert [v.name for v in result.verdicts] == ["a.h265", "b.h265", "c.h265"]

    def test_probe_count_one_per_seed(self):
        seeds = [(f"{i}.h265", b"\x00" + bytes([i])) for i in range(5)]
        result = trim_corpus(seeds, _probe_by_first_byte)
        assert result.probes == 5

    def test_empty_corpus(self):
        result = trim_corpus([], _probe_by_first_byte)
        assert result.input_count == 0
        assert result.kept_count == 0
        assert result.dropped_count == 0
        assert result.behaviour_count == 0
        assert result.verdicts == []

    def test_deterministic(self):
        seeds = [
            ("z.h265", b"\x00\x01\x02"),
            ("a.h265", b"\xaa\x00"),
            ("m.h265", b"\x00\x01"),
            ("q.h265", b"\xaa\x00\x00"),
        ]
        r1 = trim_corpus(list(seeds), _probe_by_first_byte)
        r2 = trim_corpus(list(reversed(seeds)), _probe_by_first_byte)
        assert [v.name for v in r1.verdicts] == [v.name for v in r2.verdicts]
        assert [v.kept for v in r1.verdicts] == [v.kept for v in r2.verdicts]


class TestTrimCorpusDir:
    def _write(self, d: Path, name: str, data: bytes) -> None:
        (d / name).write_bytes(data)

    def test_copies_only_kept_seeds(self, tmp_path):
        in_dir = tmp_path / "in"
        in_dir.mkdir()
        self._write(in_dir, "a.h265", b"\x00\x01")  # clean (kept, smallest)
        self._write(in_dir, "b.h265", b"\x00\x01\x02")  # clean (dropped)
        self._write(in_dir, "c.h265", b"\xaa\x01")  # BUG-A (kept)
        out_dir = tmp_path / "out"

        result = trim_corpus_dir(
            in_dir, out_dir, probe_fn=_probe_by_first_byte
        )
        assert result.kept_count == 2
        assert (out_dir / "a.h265").exists()
        assert (out_dir / "c.h265").exists()
        assert not (out_dir / "b.h265").exists()
        assert result.output_dir == str(out_dir)

    def test_writes_manifest(self, tmp_path):
        in_dir = tmp_path / "in"
        in_dir.mkdir()
        self._write(in_dir, "a.h265", b"\x00\x01")
        self._write(in_dir, "b.h265", b"\x00\x01\x02")
        out_dir = tmp_path / "out"

        trim_corpus_dir(in_dir, out_dir, probe_fn=_probe_by_first_byte)
        manifest_path = out_dir / "trim-manifest.json"
        assert manifest_path.exists()
        manifest = json.loads(manifest_path.read_text())
        assert manifest["input_count"] == 2
        assert manifest["kept_count"] == 1
        assert manifest["dropped_count"] == 1
        names = [v["name"] for v in manifest["verdicts"]]
        assert names == ["a.h265", "b.h265"]
        dropped = next(v for v in manifest["verdicts"] if not v["kept"])
        assert dropped["subsumed_by"] == "a.h265"

    def test_missing_dir_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError, match="corpus directory not found"):
            trim_corpus_dir(tmp_path / "nope", tmp_path / "out",
                            probe_fn=_probe_by_first_byte)

    def test_empty_dir_raises(self, tmp_path):
        in_dir = tmp_path / "in"
        in_dir.mkdir()
        with pytest.raises(ValueError, match="no seeds matching"):
            trim_corpus_dir(in_dir, tmp_path / "out",
                            probe_fn=_probe_by_first_byte)

    def test_pattern_filters_inputs(self, tmp_path):
        in_dir = tmp_path / "in"
        in_dir.mkdir()
        self._write(in_dir, "a.hevc", b"\x00\x01")
        self._write(in_dir, "b.hevc", b"\x00\x01\x02")
        self._write(in_dir, "ignore.txt", b"\x00")
        out_dir = tmp_path / "out"

        result = trim_corpus_dir(
            in_dir, out_dir, pattern="*.hevc", probe_fn=_probe_by_first_byte
        )
        # Only the two .hevc files are considered.
        assert result.input_count == 2
        assert result.kept_count == 1


class TestDecoderProbe:
    """The real-decoder probe, exercised with an injected subprocess runner."""

    def test_probe_reports_crash_signature(self):
        import signal as _signal

        class FakeProc:
            def __init__(self, returncode, stderr):
                self.returncode = returncode
                self.stderr = stderr

        asan = (
            b"==1==ERROR: AddressSanitizer: heap-buffer-overflow\n"
            b"    #0 0xdead in boom_fn /src/a.c:1:1\n"
            b"    #1 0xbeef in caller_fn /src/a.c:2:2\n"
        )

        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=-_signal.SIGSEGV, stderr=asan)

        probe = make_decoder_probe("ffmpeg", 5.0, runner=fake_run)
        b = probe(b"\x00\x00\x00\x01\x42\x01\x00")
        assert b.outcome == "crash"
        assert "boom_fn" in b.signature

    def test_probe_reports_clean(self):
        class FakeProc:
            returncode = 0
            stderr = b""

        def fake_run(cmd, **kwargs):
            return FakeProc()

        probe = make_decoder_probe("ffmpeg", 5.0, runner=fake_run)
        b = probe(b"\x00\x00\x00\x01\x42\x01\x00")
        assert b.outcome == "clean"
        assert b.signature == ""
        assert b.behaviour_key() == "clean"


class TestCorpusTrimCli:
    def test_cli_corpus_trim_runs(self, tmp_path, capsys, monkeypatch):
        import mangle.cli as cli_mod

        in_dir = tmp_path / "in"
        in_dir.mkdir()
        (in_dir / "a.h265").write_bytes(b"\x00\x01")
        (in_dir / "b.h265").write_bytes(b"\x00\x01\x02")
        (in_dir / "c.h265").write_bytes(b"\xaa\x01")
        out_dir = tmp_path / "out"

        monkeypatch.setattr(
            cli_mod, "trim_corpus_dir", _patched_trim(_probe_by_first_byte)
        )
        rc = cli_mod.main(
            [
                "corpus-trim",
                "--input-dir",
                str(in_dir),
                "--output-dir",
                str(out_dir),
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "redundant dropped" in out
        assert "trim manifest written to" in out
        assert (out_dir / "trim-manifest.json").exists()

    def test_cli_corpus_trim_empty_errors(self, tmp_path, capsys, monkeypatch):
        import mangle.cli as cli_mod

        in_dir = tmp_path / "in"
        in_dir.mkdir()
        out_dir = tmp_path / "out"

        monkeypatch.setattr(
            cli_mod, "trim_corpus_dir", _patched_trim(_probe_by_first_byte)
        )
        rc = cli_mod.main(
            [
                "corpus-trim",
                "--input-dir",
                str(in_dir),
                "--output-dir",
                str(out_dir),
            ]
        )
        assert rc == 1
        assert "error:" in capsys.readouterr().err


def _patched_trim(probe):
    """Return a trim_corpus_dir shim that forces the injected probe."""
    from mangle.corpus_trim import trim_corpus_dir as real

    def shim(*, input_dir, output_dir, decoder, timeout, frame_depth, pattern):
        return real(
            input_dir,
            output_dir,
            decoder=decoder,
            timeout=timeout,
            frame_depth=frame_depth,
            pattern=pattern,
            probe_fn=probe,
        )

    return shim
