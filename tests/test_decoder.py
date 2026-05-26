"""Unit tests for the decoder harness, with ffmpeg shell-out mocked.

Criterion 8: ffmpeg is mocked so these smoke tests run without ffmpeg installed.
"""

from __future__ import annotations

import signal
import subprocess
from dataclasses import dataclass

from mangle.decoder import (
    DecodeResult,
    Outcome,
    classify,
    decoder_command,
    run_decoder,
)


@dataclass
class FakeProc:
    returncode: int
    stderr: bytes = b""


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
