"""Tests for the crash triage and deduplication engine (POST_V01 item #8)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mangle.cli import main
from mangle.triage import (
    CrashSignature,
    cluster_crashes,
    extract_frames,
    signature_for,
    triage,
)

# A realistic ASAN heap-write report (top frames are the stable fingerprint).
ASAN_STDERR_A = """\
==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000d54
WRITE of size 4 at 0x602000000d54 thread T0
    #0 0x55a3c0ffaa11 in ff_hevc_decode_short_term_rps /src/libavcodec/hevc_ps.c:401:9
    #1 0x55a3c0ffee21 in hevc_parse_sps /src/libavcodec/hevc_ps.c:1234:7
    #2 0x55a3c1001000 in decode_nal_unit /src/libavcodec/hevcdec.c:2900:5
    #3 0x55a3c1002000 in hevc_decode_frame /src/libavcodec/hevcdec.c:3400:9
SUMMARY: AddressSanitizer: heap-buffer-overflow hevc_ps.c:401:9
"""

# Same bug, *different input*: identical top frames, different addresses/lines.
ASAN_STDERR_A2 = """\
==99999==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000abc
WRITE of size 4 at 0x602000000abc thread T0
    #0 0x7f0011223344 in ff_hevc_decode_short_term_rps /src/libavcodec/hevc_ps.c:402:9
    #1 0x7f0011225566 in hevc_parse_sps /src/libavcodec/hevc_ps.c:1240:7
    #2 0x7f0011227788 in decode_nal_unit /src/libavcodec/hevcdec.c:2905:5
    #3 0x7f0011229900 in hevc_decode_frame /src/libavcodec/hevcdec.c:3402:9
SUMMARY: AddressSanitizer: heap-buffer-overflow hevc_ps.c:402:9
"""

# A genuinely different bug: different top frames.
ASAN_STDERR_B = """\
==54321==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000
    #0 0x55a3c0ff0001 in pps_deblocking_derive /src/libavcodec/hevc_ps.c:700:3
    #1 0x55a3c0ff0002 in hevc_parse_pps /src/libavcodec/hevc_ps.c:1500:7
    #2 0x55a3c0ff0003 in decode_nal_unit /src/libavcodec/hevcdec.c:2900:5
SUMMARY: AddressSanitizer: SEGV hevc_ps.c:700:3
"""

# Plain (no-sanitizer) ffmpeg errors that differ only in incidental numbers.
PLAIN_STDERR_A = "[hevc @ 0x5570abcd] Could not find ref with POC 7\n"
PLAIN_STDERR_A2 = "[hevc @ 0x9999ffff] Could not find ref with POC 42\n"
PLAIN_STDERR_B = "[hevc @ 0x5570abcd] Invalid NAL unit size (123 > 45)\n"


def _write_run(
    out_dir: Path, crashes: list[tuple[str, str, str, int, bytes]]
) -> None:
    """Write a synthetic fuzz output dir.

    Each crash tuple is (crash_hash, mutator, stderr, iteration, mutant_bytes).
    """
    crashes_dir = out_dir / "crashes"
    crashes_dir.mkdir(parents=True, exist_ok=True)
    lines = []
    for h, mutator, stderr, iteration, data in crashes:
        (crashes_dir / f"{h}.h265").write_bytes(data)
        (crashes_dir / f"{h}.txt").write_text(stderr)
        lines.append(
            json.dumps(
                {
                    "iteration": iteration,
                    "mutator": mutator,
                    "seed_rng": iteration,
                    "outcome": "crash",
                    "returncode": -11,
                    "bytes_changed": 1,
                    "detail": "synthetic",
                    "crash_hash": h,
                }
            )
        )
    # Add some clean (non-crash) iterations that triage must ignore.
    lines.insert(
        0,
        json.dumps(
            {
                "iteration": -1,
                "mutator": "sps-dimensions",
                "seed_rng": 0,
                "outcome": "clean",
                "returncode": 0,
                "bytes_changed": 1,
                "detail": "ok",
                "crash_hash": None,
            }
        ),
    )
    (out_dir / "results.jsonl").write_text("\n".join(lines) + "\n")


class TestFrameExtraction:
    def test_extracts_top_frames_in_order(self):
        frames = extract_frames(ASAN_STDERR_A, frame_depth=3)
        assert frames == [
            "ff_hevc_decode_short_term_rps",
            "hevc_parse_sps",
            "decode_nal_unit",
        ]

    def test_respects_frame_depth(self):
        assert extract_frames(ASAN_STDERR_A, frame_depth=1) == [
            "ff_hevc_decode_short_term_rps"
        ]

    def test_no_frames_for_plain_stderr(self):
        assert extract_frames(PLAIN_STDERR_A) == []


class TestSignature:
    def test_asan_signature_kind_and_value(self):
        sig = signature_for(ASAN_STDERR_A, frame_depth=3)
        assert sig.kind == "asan"
        assert sig.signature == (
            "ff_hevc_decode_short_term_rps|hevc_parse_sps|decode_nal_unit"
        )
        assert sig.frames[0] == "ff_hevc_decode_short_term_rps"

    def test_same_bug_different_input_same_signature(self):
        a = signature_for(ASAN_STDERR_A)
        a2 = signature_for(ASAN_STDERR_A2)
        assert a.signature == a2.signature
        assert a.kind == a2.kind == "asan"

    def test_different_bug_different_signature(self):
        a = signature_for(ASAN_STDERR_A)
        b = signature_for(ASAN_STDERR_B)
        assert a.signature != b.signature

    def test_plain_stderr_fallback_kind(self):
        sig = signature_for(PLAIN_STDERR_A)
        assert sig.kind == "stderr"
        assert sig.frames == []
        # 16-hex-char digest
        assert len(sig.signature) == 16
        int(sig.signature, 16)  # parses as hex

    def test_plain_stderr_normalisation_clusters_numbers(self):
        # Differ only by POC number and address -> same normalised signature.
        assert signature_for(PLAIN_STDERR_A).signature == (
            signature_for(PLAIN_STDERR_A2).signature
        )

    def test_plain_stderr_distinct_messages_distinct_signature(self):
        assert signature_for(PLAIN_STDERR_A).signature != (
            signature_for(PLAIN_STDERR_B).signature
        )


class TestClustering:
    def test_dedups_same_bug_across_inputs(self, tmp_path):
        _write_run(
            tmp_path,
            [
                ("aaaa1111", "rps-overflow", ASAN_STDERR_A, 0, b"\x00" * 200),
                ("bbbb2222", "rps-overflow", ASAN_STDERR_A2, 1, b"\x00" * 100),
                ("cccc3333", "pps-deblocking", ASAN_STDERR_B, 2, b"\x00" * 150),
            ],
        )
        clusters = cluster_crashes(tmp_path)
        # Two inputs map to one bug (same frames + same mutator); the third is
        # a distinct bug -> 2 clusters total.
        assert len(clusters) == 2
        big = next(c for c in clusters if c.count == 2)
        assert big.mutator == "rps-overflow"
        assert big.signature_kind == "asan"
        assert set(big.member_hashes) == {"aaaa1111", "bbbb2222"}

    def test_representative_is_smallest_mutant(self, tmp_path):
        _write_run(
            tmp_path,
            [
                ("aaaa1111", "rps-overflow", ASAN_STDERR_A, 0, b"\x00" * 200),
                ("bbbb2222", "rps-overflow", ASAN_STDERR_A2, 1, b"\x00" * 100),
            ],
        )
        clusters = cluster_crashes(tmp_path)
        assert len(clusters) == 1
        # bbbb2222 has the smaller (100-byte) mutant.
        assert clusters[0].representative_hash == "bbbb2222"

    def test_mutator_is_part_of_key(self, tmp_path):
        # Identical signature but different mutators -> two clusters.
        _write_run(
            tmp_path,
            [
                ("aaaa1111", "rps-overflow", ASAN_STDERR_A, 0, b"\x00" * 50),
                ("bbbb2222", "sps-bit-depth", ASAN_STDERR_A, 1, b"\x00" * 50),
            ],
        )
        clusters = cluster_crashes(tmp_path)
        assert len(clusters) == 2

    def test_clusters_sorted_by_descending_count(self, tmp_path):
        _write_run(
            tmp_path,
            [
                ("a1", "m", ASAN_STDERR_A, 0, b"\x00" * 10),
                ("a2", "m", ASAN_STDERR_A2, 1, b"\x00" * 10),
                ("b1", "m", ASAN_STDERR_B, 2, b"\x00" * 10),
            ],
        )
        clusters = cluster_crashes(tmp_path)
        assert [c.count for c in clusters] == [2, 1]
        assert [c.cluster_id for c in clusters] == [0, 1]

    def test_ignores_clean_iterations(self, tmp_path):
        _write_run(
            tmp_path,
            [("aaaa1111", "m", ASAN_STDERR_A, 0, b"\x00" * 10)],
        )
        clusters = cluster_crashes(tmp_path)
        assert sum(c.count for c in clusters) == 1

    def test_missing_results_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            cluster_crashes(tmp_path)

    def test_deterministic(self, tmp_path):
        run = [
            ("a1", "m", ASAN_STDERR_A, 0, b"\x00" * 30),
            ("a2", "m", ASAN_STDERR_A2, 1, b"\x00" * 20),
            ("b1", "n", ASAN_STDERR_B, 2, b"\x00" * 40),
        ]
        _write_run(tmp_path, run)
        first = cluster_crashes(tmp_path)
        second = cluster_crashes(tmp_path)
        assert [c.representative_hash for c in first] == [
            c.representative_hash for c in second
        ]
        assert [c.signature for c in first] == [c.signature for c in second]


class TestTriageOutput:
    def test_writes_triage_jsonl_and_uniques(self, tmp_path):
        _write_run(
            tmp_path,
            [
                ("aaaa1111", "rps-overflow", ASAN_STDERR_A, 0, b"\x00" * 200),
                ("bbbb2222", "rps-overflow", ASAN_STDERR_A2, 1, b"\x00" * 100),
                ("cccc3333", "pps-deblocking", ASAN_STDERR_B, 2, b"\x00" * 150),
            ],
        )
        clusters = triage(tmp_path)
        triage_path = tmp_path / "triage.jsonl"
        assert triage_path.exists()
        lines = [
            json.loads(line)
            for line in triage_path.read_text().splitlines()
            if line.strip()
        ]
        assert len(lines) == len(clusters) == 2

        unique_dir = tmp_path / "unique-crashes"
        # One representative .h265 + .txt per cluster.
        h265 = sorted(p.name for p in unique_dir.glob("*.h265"))
        txt = sorted(p.name for p in unique_dir.glob("*.txt"))
        assert len(h265) == 2
        assert len(txt) == 2
        # The 2x cluster's representative is the smaller mutant (bbbb2222).
        assert "bbbb2222.h265" in h265
        assert "cccc3333.h265" in h265

    def test_unique_poc_bytes_match_original(self, tmp_path):
        payload = b"\xde\xad\xbe\xef" * 25
        _write_run(
            tmp_path,
            [("aaaa1111", "m", ASAN_STDERR_A, 0, payload)],
        )
        triage(tmp_path)
        copied = (tmp_path / "unique-crashes" / "aaaa1111.h265").read_bytes()
        assert copied == payload

    def test_triage_jsonl_schema(self, tmp_path):
        _write_run(
            tmp_path,
            [("aaaa1111", "rps-overflow", ASAN_STDERR_A, 0, b"\x00" * 10)],
        )
        triage(tmp_path)
        line = (tmp_path / "triage.jsonl").read_text().splitlines()[0]
        obj = json.loads(line)
        for field_name in (
            "cluster_id",
            "signature_kind",
            "signature",
            "decoder",
            "mutator",
            "count",
            "representative_hash",
            "representative_frames",
            "member_hashes",
        ):
            assert field_name in obj
        assert obj["representative_frames"][0] == "ff_hevc_decode_short_term_rps"


class TestTriageCli:
    def test_cli_triage_runs(self, tmp_path, capsys):
        _write_run(
            tmp_path,
            [
                ("aaaa1111", "rps-overflow", ASAN_STDERR_A, 0, b"\x00" * 200),
                ("bbbb2222", "rps-overflow", ASAN_STDERR_A2, 1, b"\x00" * 100),
            ],
        )
        rc = main(["triage", "--output-dir", str(tmp_path)])
        assert rc == 0
        out = capsys.readouterr().out
        assert "1 unique bug(s)" in out
        assert (tmp_path / "triage.jsonl").exists()
        assert (tmp_path / "unique-crashes").is_dir()

    def test_cli_triage_missing_dir_errors(self, tmp_path, capsys):
        rc = main(["triage", "--output-dir", str(tmp_path / "nope")])
        assert rc == 1
        err = capsys.readouterr().err
        assert "error:" in err

    def test_cli_frame_depth_option(self, tmp_path):
        _write_run(
            tmp_path,
            [("aaaa1111", "m", ASAN_STDERR_A, 0, b"\x00" * 10)],
        )
        rc = main(
            ["triage", "--output-dir", str(tmp_path), "--frame-depth", "1"]
        )
        assert rc == 0
        obj = json.loads((tmp_path / "triage.jsonl").read_text().splitlines()[0])
        # Depth 1 => signature is just the single top frame.
        assert obj["signature"] == "ff_hevc_decode_short_term_rps"


def test_crash_signature_dataclass_defaults():
    sig = CrashSignature(kind="stderr", signature="abc")
    assert sig.frames == []
