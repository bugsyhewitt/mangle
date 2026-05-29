"""Tests for the NAL-aware crash test-case minimiser (mangle reduce).

The reducer's "does it still crash?" oracle is injected, so these tests drive
the full ddmin reduction without ffmpeg/libde265 installed. The fake oracles
encode a *load-bearing NAL* policy: a candidate "crashes" only when it still
contains some required NAL unit(s), letting us assert that ddmin converges on the
minimal load-bearing subset and that it refuses to swap the bug for a different
signature.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from mangle.bitstream import (
    NalUnit,
    assemble_nal_units,
    split_nal_units,
)
from mangle.cli import main
from mangle.reduce import (
    ProbeResult,
    ddmin_nals,
    make_decoder_oracle,
    reduce_crash,
    reduce_file,
)

SEED = Path(__file__).parent / "fixtures" / "clean.h265"


# ---------------------------------------------------------------------------
# Synthetic NAL stream builders
# ---------------------------------------------------------------------------


def _nal(nal_type: int, body: bytes = b"\x00\x00") -> NalUnit:
    """Build a minimal NalUnit with the given nal_unit_type.

    The 2-byte NAL header encodes nal_unit_type in bits 1..6 of the first byte;
    ``body`` is appended so distinct NALs have distinct bytes/sizes.
    """
    header0 = (nal_type & 0x3F) << 1
    ebsp = bytes([header0, 0x01]) + body
    return NalUnit(start_code_len=4, offset=0, ebsp=ebsp)


def _stream(nals: list[NalUnit]) -> bytes:
    return assemble_nal_units(nals)


# An oracle factory: "crashes" iff the candidate still contains a NAL of each
# required type. Signature is fixed so a reproducing candidate matches baseline.
def _oracle_requiring(required_types: set[int], signature: str = "BUG-A"):
    def oracle(candidate: bytes):
        types = {n.nal_unit_type for n in split_nal_units(candidate)}
        if required_types.issubset(types):
            return ProbeResult(is_crash=True, signature=signature)
        return ProbeResult(is_crash=False, signature="")

    return oracle


class TestProbeResult:
    def test_defaults(self):
        p = ProbeResult(is_crash=True, signature="x")
        assert p.is_crash is True
        assert p.signature == "x"


class TestDdminNals:
    def test_keeps_single_load_bearing_nal(self):
        # 6 NALs; only the SPS (type 33) is load-bearing for the crash.
        nals = [
            _nal(32),  # VPS
            _nal(33, b"\xaa\xbb"),  # SPS  (the load-bearing one)
            _nal(34),  # PPS
            _nal(39),  # SEI
            _nal(1),  # slice
            _nal(1, b"\x11"),  # slice
        ]
        oracle = _oracle_requiring({33})
        minimal, probes = ddmin_nals(nals, "BUG-A", oracle)
        types = [n.nal_unit_type for n in minimal]
        assert types == [33]
        assert probes > 0

    def test_keeps_two_load_bearing_nals(self):
        # The crash needs BOTH the SPS (33) and one slice (1) present.
        nals = [_nal(32), _nal(33), _nal(34), _nal(39), _nal(1), _nal(1, b"\x22")]
        oracle = _oracle_requiring({33, 1})
        minimal, _probes = ddmin_nals(nals, "BUG-A", oracle)
        types = {n.nal_unit_type for n in minimal}
        assert 33 in types
        assert 1 in types
        # Nothing extraneous: VPS/PPS/SEI all dropped.
        assert types == {33, 1}

    def test_one_minimal_no_further_removal_possible(self):
        # Every NAL is required -> ddmin cannot remove anything.
        nals = [_nal(32), _nal(33), _nal(34)]
        oracle = _oracle_requiring({32, 33, 34})
        minimal, _probes = ddmin_nals(nals, "BUG-A", oracle)
        assert [n.nal_unit_type for n in minimal] == [32, 33, 34]

    def test_deterministic(self):
        nals = [_nal(t) for t in (32, 33, 34, 39, 1, 1, 1, 1)]
        oracle = _oracle_requiring({33})
        a, _ = ddmin_nals(nals, "BUG-A", _oracle_requiring({33}))
        b, _ = ddmin_nals(nals, "BUG-A", oracle)
        assert [n.ebsp for n in a] == [n.ebsp for n in b]


class TestReduceCrash:
    def test_reduces_to_load_bearing_nal(self):
        nals = [_nal(32), _nal(33, b"\xaa"), _nal(34), _nal(1), _nal(1, b"\x33")]
        crash = _stream(nals)
        oracle = _oracle_requiring({33})
        minimal_bytes, result = reduce_crash(crash, oracle)
        assert result.original_nals == 5
        assert result.minimal_nals == 1
        assert result.minimal_bytes < result.original_bytes
        assert result.signature == "BUG-A"
        # The minimal reproducer still contains the load-bearing SPS.
        assert {n.nal_unit_type for n in split_nal_units(minimal_bytes)} == {33}

    def test_probe_count_includes_baseline(self):
        nals = [_nal(33), _nal(1)]
        oracle = _oracle_requiring({33})
        _bytes, result = reduce_crash(_stream(nals), oracle)
        # At minimum the baseline decode is counted.
        assert result.probes >= 1

    def test_signature_must_match_baseline(self):
        # Oracle: removing the SPS yields a *different* signature crash. The
        # reducer must NOT accept that — it would be a different bug.
        nals = [_nal(32), _nal(33), _nal(34), _nal(1)]

        def oracle(candidate: bytes):
            types = {n.nal_unit_type for n in split_nal_units(candidate)}
            if 33 in types:
                return ProbeResult(is_crash=True, signature="BUG-A")
            # Still "crashes" but with a DIFFERENT signature.
            return ProbeResult(is_crash=True, signature="BUG-B")

        minimal_bytes, result = reduce_crash(_stream(nals), oracle)
        assert result.signature == "BUG-A"
        # Every accepted candidate kept BUG-A, so the SPS must remain.
        assert 33 in {n.nal_unit_type for n in split_nal_units(minimal_bytes)}

    def test_non_crashing_input_raises(self):
        nals = [_nal(33), _nal(1)]

        def never_crashes(candidate: bytes):
            return ProbeResult(is_crash=False, signature="")

        with pytest.raises(ValueError, match="does not crash"):
            reduce_crash(_stream(nals), never_crashes)

    def test_empty_input_raises(self):
        with pytest.raises(ValueError, match="no NAL units"):
            reduce_crash(b"", _oracle_requiring({33}))

    def test_already_minimal_unchanged(self):
        nals = [_nal(33, b"\x99")]
        crash = _stream(nals)
        oracle = _oracle_requiring({33})
        minimal_bytes, result = reduce_crash(crash, oracle)
        assert result.original_nals == result.minimal_nals == 1
        assert minimal_bytes == crash


class TestReduceFile:
    def test_writes_minimal_reproducer(self, tmp_path):
        nals = [_nal(32), _nal(33, b"\xab"), _nal(34), _nal(39), _nal(1)]
        crash_path = tmp_path / "crash.h265"
        crash_path.write_bytes(_stream(nals))
        out_path = tmp_path / "min.h265"
        result = reduce_file(
            crash_path,
            out_path,
            decode_fn=_oracle_requiring({33}),
        )
        assert out_path.exists()
        assert result.output_path == str(out_path)
        assert result.minimal_nals == 1
        written = out_path.read_bytes()
        assert {n.nal_unit_type for n in split_nal_units(written)} == {33}

    def test_written_reproducer_still_reproduces(self, tmp_path):
        nals = [_nal(32), _nal(33), _nal(34), _nal(1), _nal(1, b"\x44")]
        crash_path = tmp_path / "crash.h265"
        crash_path.write_bytes(_stream(nals))
        out_path = tmp_path / "min.h265"
        oracle = _oracle_requiring({33, 1})
        reduce_file(crash_path, out_path, decode_fn=oracle)
        # Re-run the oracle on the written file: it must still crash with BUG-A.
        probe = oracle(out_path.read_bytes())
        assert probe.is_crash is True
        assert probe.signature == "BUG-A"


class TestDecoderOracle:
    """The real-decoder oracle, exercised with an injected subprocess runner."""

    def test_oracle_reports_crash_with_asan_signature(self):
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

        oracle = make_decoder_oracle("ffmpeg", 5.0, runner=fake_run)
        probe = oracle(b"\x00\x00\x00\x01\x42\x01\x00")
        assert probe.is_crash is True
        assert "boom_fn" in probe.signature

    def test_oracle_reports_clean(self):
        class FakeProc:
            returncode = 0
            stderr = b""

        def fake_run(cmd, **kwargs):
            return FakeProc()

        oracle = make_decoder_oracle("ffmpeg", 5.0, runner=fake_run)
        probe = oracle(b"\x00\x00\x00\x01\x42\x01\x00")
        assert probe.is_crash is False
        assert probe.signature == ""


class TestReduceCli:
    def test_cli_reduce_runs(self, tmp_path, capsys, monkeypatch):
        import mangle.cli as cli_mod

        nals = [_nal(32), _nal(33, b"\xcd"), _nal(34), _nal(1)]
        crash_path = tmp_path / "crash.h265"
        crash_path.write_bytes(_stream(nals))
        out_path = tmp_path / "min.h265"

        # Patch reduce_file's oracle by patching the underlying decoder oracle
        # builder to our synthetic one (no ffmpeg needed).
        oracle = _oracle_requiring({33})
        monkeypatch.setattr(
            cli_mod, "reduce_file", _patched_reduce_file(oracle)
        )

        rc = main(
            [
                "reduce",
                "--crash",
                str(crash_path),
                "--output",
                str(out_path),
            ]
        )
        assert rc == 0
        out = capsys.readouterr().out
        assert "minimal reproducer written to" in out
        assert "NAL unit(s)" in out
        assert out_path.exists()

    def test_cli_reduce_non_crash_errors(self, tmp_path, capsys, monkeypatch):
        import mangle.cli as cli_mod

        nals = [_nal(33), _nal(1)]
        crash_path = tmp_path / "crash.h265"
        crash_path.write_bytes(_stream(nals))
        out_path = tmp_path / "min.h265"

        def never(candidate: bytes):
            return ProbeResult(is_crash=False, signature="")

        monkeypatch.setattr(cli_mod, "reduce_file", _patched_reduce_file(never))
        rc = main(
            ["reduce", "--crash", str(crash_path), "--output", str(out_path)]
        )
        assert rc == 1
        assert "error:" in capsys.readouterr().err


def _patched_reduce_file(oracle):
    """Return a reduce_file shim that forces the injected oracle."""
    from mangle.reduce import reduce_file as real_reduce_file

    def shim(*, crash_path, output_path, decoder, timeout, frame_depth):
        return real_reduce_file(
            crash_path,
            output_path,
            decoder=decoder,
            timeout=timeout,
            frame_depth=frame_depth,
            decode_fn=oracle,
        )

    return shim


class TestReduceRealSeedShape:
    """Sanity check ddmin over the framing of the real bundled seed."""

    def test_seed_splits_into_multiple_nals(self):
        nals = split_nal_units(SEED.read_bytes())
        assert len(nals) >= 2  # the reducer needs >=2 NALs to do anything

    def test_reduce_seed_preserving_all_nals_is_noop(self):
        crash = SEED.read_bytes()
        all_types = {n.nal_unit_type for n in split_nal_units(crash)}
        # Oracle requires every NAL type present -> nothing removable.
        minimal_bytes, result = reduce_crash(crash, _oracle_requiring(all_types))
        assert result.minimal_nals == result.original_nals
        assert split_nal_units(minimal_bytes)
