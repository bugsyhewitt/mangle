"""Unit tests for the decoder harness, with ffmpeg shell-out mocked.

Criterion 8: ffmpeg is mocked so these smoke tests run without ffmpeg installed.
"""

from __future__ import annotations

import signal
import subprocess
from dataclasses import dataclass

from mangle.decoder import (
    DecodeResult,
    DivergenceResult,
    Outcome,
    classify,
    decoder_command,
    decoder_output_command,
    run_decoder,
    run_decoder_pair,
)


@dataclass
class FakeProc:
    returncode: int
    stderr: bytes = b""
    stdout: bytes = b""


class TestClassify:
    def test_clean(self):
        assert classify(0) == Outcome.CLEAN

    def test_segfault(self):
        assert classify(-signal.SIGSEGV) == Outcome.CRASH

    def test_abort(self):
        assert classify(-signal.SIGABRT) == Outcome.ABORT

    def test_nonzero_exit_is_crash(self):
        assert classify(1) == Outcome.CRASH
        assert classify(187) == Outcome.CRASH


class TestDecoderCommand:
    def test_ffmpeg_command(self):
        cmd = decoder_command("ffmpeg", "/tmp/x.h265")
        assert cmd[0] == "ffmpeg"
        assert "/tmp/x.h265" in cmd

    def test_libde265_command(self):
        cmd = decoder_command("libde265", "/tmp/x.h265")
        assert cmd[0] == "dec265"

    def test_unknown_decoder_raises(self):
        try:
            decoder_command("vlc", "/tmp/x.h265")
        except ValueError as exc:
            assert "unsupported decoder" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestRunDecoderMocked:
    def test_clean_run(self):
        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=0, stderr=b"")

        result = run_decoder("ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run)
        assert result.outcome == Outcome.CLEAN
        assert result.returncode == 0

    def test_crash_run_captures_stderr(self):
        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=-signal.SIGSEGV, stderr=b"boom\n")

        result = run_decoder("ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run)
        assert result.outcome == Outcome.CRASH
        assert "boom" in result.stderr

    def test_nonzero_exit_is_crash(self):
        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=69, stderr=b"bad nal\n")

        result = run_decoder("ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run)
        assert result.outcome == Outcome.CRASH
        assert result.returncode == 69

    def test_timeout(self):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, timeout=5.0, stderr=b"slow")

        result = run_decoder("ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run)
        assert result.outcome == Outcome.TIMEOUT
        assert result.returncode is None

    def test_missing_decoder_raises_runtimeerror(self):
        def fake_run(cmd, **kwargs):
            raise FileNotFoundError(cmd[0])

        try:
            run_decoder("ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run)
        except RuntimeError as exc:
            assert "not found" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")

    def test_result_labels_decoder(self):
        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=0, stderr=b"")

        result = run_decoder("ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run)
        assert result.decoder == "ffmpeg"

    def test_timeout_result_labels_decoder(self):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, timeout=5.0, stderr=b"slow")

        result = run_decoder("libde265", "/tmp/x.h265", 5.0, runner=fake_run)
        assert result.decoder == "libde265"


def _pair_runner(by_program):
    """Build a fake subprocess runner that keys outcome on cmd[0] (program)."""

    def fake_run(cmd, **kwargs):
        return by_program[cmd[0]]

    return fake_run


class TestRunDecoderPair:
    def test_agree_clean(self):
        # ffmpeg, dec265 both clean -> no divergence.
        runner = _pair_runner(
            {"ffmpeg": FakeProc(0, b""), "dec265": FakeProc(0, b"")}
        )
        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=runner)
        assert isinstance(d, DivergenceResult)
        assert d.diverged is False
        assert d.kind == "agree"

    def test_agree_both_crash_same_signal(self):
        # Both SIGSEGV crashes -> agree (same outcome class).
        runner = _pair_runner(
            {
                "ffmpeg": FakeProc(-signal.SIGSEGV, b"a"),
                "dec265": FakeProc(-signal.SIGSEGV, b"b"),
            }
        )
        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=runner)
        assert d.diverged is False
        assert d.kind == "agree"

    def test_crash_split_one_crashes(self):
        # ffmpeg crashes, dec265 clean -> the high-value crash-split.
        runner = _pair_runner(
            {"ffmpeg": FakeProc(-signal.SIGSEGV, b"boom"), "dec265": FakeProc(0, b"")}
        )
        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=runner)
        assert d.diverged is True
        assert d.kind == "crash-split"
        assert d.left.decoder == "ffmpeg"
        assert d.right.decoder == "libde265"

    def test_crash_split_other_crashes(self):
        # dec265 crashes, ffmpeg clean -> still a crash-split.
        runner = _pair_runner(
            {"ffmpeg": FakeProc(0, b""), "dec265": FakeProc(1, b"bad nal")}
        )
        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=runner)
        assert d.diverged is True
        assert d.kind == "crash-split"

    def test_signal_split_crash_vs_abort(self):
        # ffmpeg SIGSEGV, dec265 SIGABRT -> both failed, different outcome.
        runner = _pair_runner(
            {
                "ffmpeg": FakeProc(-signal.SIGSEGV, b"seg"),
                "dec265": FakeProc(-signal.SIGABRT, b"abrt"),
            }
        )
        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=runner)
        assert d.diverged is True
        assert d.kind == "signal-split"

    def test_timeout_vs_clean_is_not_divergence(self):
        # Timeout is not a failure outcome; clean vs timeout does not diverge.
        runner = _pair_runner(
            {"ffmpeg": FakeProc(0, b""), "dec265": FakeProc(0, b"")}
        )

        # Force a timeout from one side via a runner that raises for dec265.
        def mixed(cmd, **kwargs):
            if cmd[0] == "dec265":
                raise subprocess.TimeoutExpired(cmd, timeout=5.0, stderr=b"")
            return FakeProc(0, b"")

        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=mixed)
        assert d.left.outcome == Outcome.CLEAN
        assert d.right.outcome == Outcome.TIMEOUT
        assert d.diverged is False
        assert d.kind == "agree"

    def test_timeout_vs_crash_is_divergence(self):
        # One crashes, the other times out -> crash-split (one failed, one didn't).
        def mixed(cmd, **kwargs):
            if cmd[0] == "dec265":
                raise subprocess.TimeoutExpired(cmd, timeout=5.0, stderr=b"")
            return FakeProc(-signal.SIGSEGV, b"seg")

        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=mixed)
        assert d.diverged is True
        assert d.kind == "crash-split"


class TestDecoderOutputCommand:
    def test_ffmpeg_writes_raw_yuv_to_stdout(self):
        cmd = decoder_output_command("ffmpeg", "/tmp/x.h265")
        assert cmd[0] == "ffmpeg"
        # Normalised output format: rawvideo YUV 4:2:0 to stdout (`-`).
        assert "rawvideo" in cmd
        assert "yuv420p" in cmd
        assert cmd[-1] == "-"
        assert "/tmp/x.h265" in cmd

    def test_dec265_writes_to_stdout(self):
        cmd = decoder_output_command("libde265", "/tmp/x.h265")
        assert cmd[0] == "dec265"
        # `-q` silences progress to keep stdout to YUV only; `-o /dev/stdout`
        # routes decoded frames to stdout for hashing.
        assert "-q" in cmd
        assert "/dev/stdout" in cmd
        assert "/tmp/x.h265" in cmd

    def test_unknown_decoder_raises(self):
        try:
            decoder_output_command("vlc", "/tmp/x.h265")
        except ValueError as exc:
            assert "unsupported decoder" in str(exc)
        else:
            raise AssertionError("expected ValueError")


class TestRunDecoderCaptureOutput:
    def test_capture_output_off_leaves_hash_none(self):
        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=0, stderr=b"", stdout=b"YYYUV")

        # Default: capture_output=False -> stdout untouched, hash None.
        result = run_decoder("ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run)
        assert result.output_hash is None

    def test_capture_output_on_hashes_stdout(self):
        captured = {}

        def fake_run(cmd, **kwargs):
            # Record the command actually used — must be the output variant.
            captured["cmd"] = cmd
            captured["stdout_pipe"] = kwargs.get("stdout")
            return FakeProc(returncode=0, stderr=b"", stdout=b"frame-bytes")

        result = run_decoder(
            "ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run, capture_output=True
        )
        assert result.outcome == Outcome.CLEAN
        # Hash is sha256 of b"frame-bytes".
        import hashlib

        assert result.output_hash == hashlib.sha256(b"frame-bytes").hexdigest()
        # The command must be the raw-YUV variant, not the discard variant.
        assert "rawvideo" in captured["cmd"]
        # And stdout must be captured (not discarded).
        assert captured["stdout_pipe"] == subprocess.PIPE

    def test_capture_output_different_inputs_different_hashes(self):
        def factory(payload):
            def fake_run(cmd, **kwargs):
                return FakeProc(returncode=0, stderr=b"", stdout=payload)
            return fake_run

        a = run_decoder(
            "ffmpeg", "/tmp/x.h265", 5.0, runner=factory(b"AAAA"), capture_output=True
        )
        b = run_decoder(
            "ffmpeg", "/tmp/x.h265", 5.0, runner=factory(b"BBBB"), capture_output=True
        )
        assert a.output_hash is not None
        assert b.output_hash is not None
        assert a.output_hash != b.output_hash

    def test_capture_output_timeout_leaves_hash_none(self):
        def fake_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, timeout=5.0, stderr=b"")

        result = run_decoder(
            "ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run, capture_output=True
        )
        assert result.outcome == Outcome.TIMEOUT
        assert result.output_hash is None

    def test_capture_output_crash_still_hashes_partial_stdout(self):
        # A crashed decoder may have flushed partial pixel data before dying;
        # hashing it lets us still spot divergence vs. a clean decoder's run.
        # The hash is populated for any non-timeout completion.
        def fake_run(cmd, **kwargs):
            return FakeProc(returncode=-signal.SIGSEGV, stderr=b"boom", stdout=b"half")

        result = run_decoder(
            "ffmpeg", "/tmp/x.h265", 5.0, runner=fake_run, capture_output=True
        )
        assert result.outcome == Outcome.CRASH
        assert result.output_hash is not None
        import hashlib

        assert result.output_hash == hashlib.sha256(b"half").hexdigest()


class TestRunDecoderPairOutputDivergence:
    def test_clean_clean_same_hash_is_agree(self):
        # Both decoders return CLEAN and produce identical stdout -> agree.
        runner = _pair_runner(
            {
                "ffmpeg": FakeProc(0, b"", stdout=b"identical-frames"),
                "dec265": FakeProc(0, b"", stdout=b"identical-frames"),
            }
        )
        d = run_decoder_pair(
            "ffmpeg", "libde265", "/tmp/x.h265", 5.0,
            runner=runner, compare_output=True,
        )
        assert d.diverged is False
        assert d.kind == "agree"
        # Both hashes populated and equal.
        assert d.left.output_hash is not None
        assert d.right.output_hash is not None
        assert d.left.output_hash == d.right.output_hash

    def test_clean_clean_different_hash_is_output_divergence(self):
        # The TWINFUZZ silent-acceptor signal: both say CLEAN, output differs.
        runner = _pair_runner(
            {
                "ffmpeg": FakeProc(0, b"", stdout=b"pixels-A"),
                "dec265": FakeProc(0, b"", stdout=b"pixels-B"),
            }
        )
        d = run_decoder_pair(
            "ffmpeg", "libde265", "/tmp/x.h265", 5.0,
            runner=runner, compare_output=True,
        )
        assert d.diverged is True
        assert d.kind == "output-divergence"
        assert d.left.outcome == Outcome.CLEAN
        assert d.right.outcome == Outcome.CLEAN
        assert d.left.output_hash != d.right.output_hash

    def test_crash_split_takes_priority_over_output(self):
        # If one crashes, it's a crash-split regardless of any partial stdout.
        runner = _pair_runner(
            {
                "ffmpeg": FakeProc(-signal.SIGSEGV, b"boom", stdout=b"partial"),
                "dec265": FakeProc(0, b"", stdout=b"full"),
            }
        )
        d = run_decoder_pair(
            "ffmpeg", "libde265", "/tmp/x.h265", 5.0,
            runner=runner, compare_output=True,
        )
        assert d.diverged is True
        assert d.kind == "crash-split"

    def test_compare_output_off_clean_clean_is_agree_regardless(self):
        # Without compare_output, hashes are not collected so a clean/clean
        # pair always agrees — preserving the original 2-mode behaviour.
        runner = _pair_runner(
            {
                "ffmpeg": FakeProc(0, b"", stdout=b"pixels-A"),
                "dec265": FakeProc(0, b"", stdout=b"pixels-B"),
            }
        )
        d = run_decoder_pair("ffmpeg", "libde265", "/tmp/x.h265", 5.0, runner=runner)
        assert d.diverged is False
        assert d.kind == "agree"
        # Hashes are None when compare_output is off.
        assert d.left.output_hash is None
        assert d.right.output_hash is None

    def test_compare_output_uses_output_command(self):
        # When compare_output=True the *output* command variant is invoked
        # (raw-YUV stdout), not the null-discard variant.
        seen = []

        def runner(cmd, **kwargs):
            seen.append(cmd)
            if cmd[0] == "ffmpeg":
                return FakeProc(0, b"", stdout=b"X")
            return FakeProc(0, b"", stdout=b"X")

        run_decoder_pair(
            "ffmpeg", "libde265", "/tmp/x.h265", 5.0,
            runner=runner, compare_output=True,
        )
        ffmpeg_cmd = next(c for c in seen if c[0] == "ffmpeg")
        dec265_cmd = next(c for c in seen if c[0] == "dec265")
        assert "rawvideo" in ffmpeg_cmd
        assert "/dev/stdout" in dec265_cmd
