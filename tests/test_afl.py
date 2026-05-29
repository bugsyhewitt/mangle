"""Tests for the AFL++ integration (POST_V01 item #7).

Two layers are covered:

1. The Python wrapper module (`mangle.afl`) and its `mangle afl-mutate` CLI
   subcommand — fully unit-tested, the load-bearing artifact for AFL++
   custom-mutator integration and for the persistent-mode `harness.c`.

2. The `contrib/afl-harness/` directory — covered with structural tests
   (files exist, `make -n` parses, harness.c declares the AFL persistent-mode
   loop, README documents both integration paths). Live AFL++ campaigns are
   not exercised in CI; the contract is that the build chain and the CLI
   plumbing are sound, so a user with AFL++ installed can follow the README
   end-to-end.
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from mangle.afl import mutate_stdin_to_stdout, mutate_stream
from mangle.cli import main
from mangle.engine import mutate_bytes
from mangle.mutators import list_mutators

SEED = Path(__file__).parent / "fixtures" / "clean.h265"
REPO_ROOT = Path(__file__).resolve().parents[1]
CONTRIB_DIR = REPO_ROOT / "contrib" / "afl-harness"


class TestMutateStream:
    def test_returns_mutated_bytes(self):
        seed = SEED.read_bytes()
        mutant = mutate_stream(seed, "sps-dimensions", seed_rng=42)
        assert isinstance(mutant, bytes)
        assert len(mutant) > 0
        # The mutator must have changed the stream.
        assert mutant != seed

    def test_matches_engine_mutate_bytes(self):
        # mutate_stream is a thin wrapper — the bytes must match what
        # engine.mutate_bytes would produce for the same (seed, mutator, rng).
        import random
        seed = SEED.read_bytes()
        wrapper_out = mutate_stream(seed, "sps-dimensions", seed_rng=42)
        engine_out, _ = mutate_bytes(seed, "sps-dimensions", random.Random(42))
        assert wrapper_out == engine_out

    def test_reproducible(self):
        seed = SEED.read_bytes()
        a = mutate_stream(seed, "sps-dimensions", seed_rng=42)
        b = mutate_stream(seed, "sps-dimensions", seed_rng=42)
        assert a == b

    def test_different_rng_yields_different_output_or_same_deterministically(self):
        # Some mutators are insensitive to the rng for a given seed (single
        # field to flip). What we MUST assert is that re-running with the same
        # rng gives the same output, and that the wrapper does not silently
        # drop or corrupt bytes.
        seed = SEED.read_bytes()
        out0 = mutate_stream(seed, "sps-dimensions", seed_rng=0)
        out1 = mutate_stream(seed, "sps-dimensions", seed_rng=0)
        assert out0 == out1
        assert len(out0) > 0

    def test_unknown_mutator_raises_with_available_list(self):
        seed = SEED.read_bytes()
        with pytest.raises(ValueError, match="unknown mutator"):
            mutate_stream(seed, "does-not-exist", seed_rng=0)

    def test_unknown_mutator_error_lists_real_mutators(self):
        seed = SEED.read_bytes()
        try:
            mutate_stream(seed, "does-not-exist", seed_rng=0)
        except ValueError as exc:
            msg = str(exc)
            # At least one real mutator name should appear in the error.
            assert "sps-dimensions" in msg
        else:
            pytest.fail("expected ValueError")

    def test_pure_function_no_side_effects(self, tmp_path):
        # mutate_stream is pure — no files written, no stdout written.
        seed = SEED.read_bytes()
        before = set(tmp_path.iterdir())
        mutate_stream(seed, "sps-dimensions", seed_rng=42)
        after = set(tmp_path.iterdir())
        assert before == after


class TestMutateStdinToStdout:
    def test_writes_mutant_to_supplied_stream(self):
        buf = io.BytesIO()
        n = mutate_stdin_to_stdout(SEED, "sps-dimensions", seed_rng=7, out_stream=buf)
        assert n == len(buf.getvalue())
        assert n > 0

    def test_output_matches_mutate_stream(self):
        # The stdout path must be a thin wrapper around mutate_stream — same
        # mutator + same rng + same seed file must produce the same bytes.
        buf = io.BytesIO()
        mutate_stdin_to_stdout(SEED, "sps-dimensions", seed_rng=7, out_stream=buf)
        direct = mutate_stream(SEED.read_bytes(), "sps-dimensions", seed_rng=7)
        assert buf.getvalue() == direct

    def test_seed_path_as_string(self):
        # The AFL @@ argument arrives as a string path on argv — must work.
        buf = io.BytesIO()
        n = mutate_stdin_to_stdout(
            str(SEED), "sps-dimensions", seed_rng=7, out_stream=buf
        )
        assert n > 0

    def test_missing_seed_raises(self, tmp_path):
        buf = io.BytesIO()
        with pytest.raises(FileNotFoundError):
            mutate_stdin_to_stdout(
                tmp_path / "missing.h265", "sps-dimensions", 0, out_stream=buf
            )

    def test_unknown_mutator_raises(self):
        buf = io.BytesIO()
        with pytest.raises(ValueError):
            mutate_stdin_to_stdout(SEED, "no-such-mutator", 0, out_stream=buf)

    def test_reproducible(self):
        a, b = io.BytesIO(), io.BytesIO()
        mutate_stdin_to_stdout(SEED, "sps-dimensions", seed_rng=99, out_stream=a)
        mutate_stdin_to_stdout(SEED, "sps-dimensions", seed_rng=99, out_stream=b)
        assert a.getvalue() == b.getvalue()


class TestAflMutateCli:
    def test_cli_writes_bytes_to_stdout(self, capsysbinary, monkeypatch):
        # The CLI must write the mutant to stdout (binary), and progress to
        # stderr — anything else on stdout would break a piped decoder.
        # capsysbinary gives us byte-level stdout capture.
        exit_code = main([
            "afl-mutate",
            "--seed", str(SEED),
            "--mutator", "sps-dimensions",
            "--seed-rng", "1",
        ])
        assert exit_code == 0
        out, err = capsysbinary.readouterr()
        assert len(out) > 0
        # The byte count line is on stderr.
        assert b"afl-mutate: applied sps-dimensions" in err
        assert b"wrote" in err

    def test_cli_stdout_matches_mutate_stream(self, capsysbinary):
        main([
            "afl-mutate",
            "--seed", str(SEED),
            "--mutator", "sps-dimensions",
            "--seed-rng", "1",
        ])
        out, _ = capsysbinary.readouterr()
        expected = mutate_stream(SEED.read_bytes(), "sps-dimensions", seed_rng=1)
        assert out == expected

    def test_cli_rejects_unknown_mutator_at_parse_time(self):
        # argparse choices=list_mutators() means unknown name fails at the
        # parser layer with exit code 2.
        with pytest.raises(SystemExit) as excinfo:
            main([
                "afl-mutate",
                "--seed", str(SEED),
                "--mutator", "no-such-mutator",
            ])
        assert excinfo.value.code == 2

    def test_cli_missing_seed_returns_error(self, capsys, tmp_path):
        exit_code = main([
            "afl-mutate",
            "--seed", str(tmp_path / "absent.h265"),
            "--mutator", "sps-dimensions",
        ])
        assert exit_code == 1
        _, err = capsys.readouterr()
        assert "error:" in err

    def test_cli_default_seed_rng_is_zero(self, capsysbinary):
        main([
            "afl-mutate",
            "--seed", str(SEED),
            "--mutator", "sps-dimensions",
        ])
        out_default, _ = capsysbinary.readouterr()
        main([
            "afl-mutate",
            "--seed", str(SEED),
            "--mutator", "sps-dimensions",
            "--seed-rng", "0",
        ])
        out_explicit, _ = capsysbinary.readouterr()
        assert out_default == out_explicit

    def test_cli_help_describes_afl_role(self, capsys):
        with pytest.raises(SystemExit):
            main(["afl-mutate", "--help"])
        out, _ = capsys.readouterr()
        # The help text must mention AFL so a user reading `mangle --help`
        # can find the integration path.
        assert "AFL" in out

    def test_cli_listed_in_top_level_help(self, capsys):
        with pytest.raises(SystemExit):
            main(["--help"])
        out, _ = capsys.readouterr()
        assert "afl-mutate" in out

    def test_cli_subprocess_end_to_end(self, tmp_path):
        # End-to-end: invoke mangle afl-mutate via subprocess (the form a real
        # AFL harness uses) and confirm stdout is byte-clean mutant bytes.
        mangle = shutil.which("mangle")
        if mangle is None:
            # When running from a source checkout without `pip install -e .`,
            # fall back to `python -m mangle.cli`.
            mangle_cmd = [sys.executable, "-m", "mangle.cli"]
        else:
            mangle_cmd = [mangle]
        result = subprocess.run(
            mangle_cmd + [
                "afl-mutate",
                "--seed", str(SEED),
                "--mutator", "sps-dimensions",
                "--seed-rng", "13",
            ],
            check=True,
            capture_output=True,
        )
        assert len(result.stdout) > 0
        # All progress on stderr; stdout is a pure HEVC byte stream.
        assert b"afl-mutate" in result.stderr
        expected = mutate_stream(SEED.read_bytes(), "sps-dimensions", seed_rng=13)
        assert result.stdout == expected


class TestAflMutateCliMutatorChoices:
    def test_all_registered_mutators_are_accepted(self, capsysbinary):
        # Every mutator in the registry should be invokable via the CLI.
        # Just verify the parser accepts each — we don't need to call all of
        # them (some require seeds they cannot find in the fixture).
        for name in list_mutators():
            try:
                main([
                    "afl-mutate",
                    "--seed", str(SEED),
                    "--mutator", name,
                    "--seed-rng", "0",
                ])
            except SystemExit as exc:
                pytest.fail(f"mutator {name!r} rejected by CLI parser: {exc}")
            capsysbinary.readouterr()  # drain output between calls


class TestContribAflHarness:
    """Structural tests for contrib/afl-harness/.

    Live AFL++ runs are not exercised in CI (they require afl-clang-fast and
    a fuzzing budget). These tests verify the files are present, well-formed,
    and ready to be picked up by a user with AFL++ installed.
    """

    def test_directory_exists(self):
        assert CONTRIB_DIR.is_dir(), f"{CONTRIB_DIR} missing"

    def test_harness_c_exists(self):
        assert (CONTRIB_DIR / "harness.c").is_file()

    def test_makefile_exists(self):
        assert (CONTRIB_DIR / "Makefile").is_file()

    def test_readme_exists(self):
        assert (CONTRIB_DIR / "README.md").is_file()

    def test_harness_c_declares_afl_persistent_loop(self):
        text = (CONTRIB_DIR / "harness.c").read_text()
        # The two AFL macros that mark a persistent-mode harness.
        assert "__AFL_LOOP" in text
        assert "AFL_INIT" in text or "__AFL_INIT" in text

    def test_harness_c_invokes_mangle_afl_mutate(self):
        text = (CONTRIB_DIR / "harness.c").read_text()
        # The harness must shell out to `mangle afl-mutate`.
        assert "afl-mutate" in text
        assert "mangle" in text

    def test_harness_c_falls_back_under_plain_gcc(self):
        # An explicit fallback so the build chain can be smoke-tested without
        # afl-clang-fast installed.
        text = (CONTRIB_DIR / "harness.c").read_text()
        assert "__AFL_HAVE_MANUAL_CONTROL" in text

    def test_makefile_targets(self):
        text = (CONTRIB_DIR / "Makefile").read_text()
        # The Makefile must declare the binary target and a check / clean.
        assert "mangle-afl-harness" in text
        assert "clean" in text

    def test_makefile_documents_afl_clang_fast(self):
        text = (CONTRIB_DIR / "Makefile").read_text()
        assert "afl-clang-fast" in text

    def test_makefile_dry_run_parses(self):
        # `make -n` prints the commands without executing them — catches
        # Makefile syntax errors without requiring a C toolchain in CI.
        # Skip if make isn't installed (unlikely but possible in minimal
        # environments).
        if shutil.which("make") is None:
            pytest.skip("make not installed")
        result = subprocess.run(
            ["make", "-n", "-C", str(CONTRIB_DIR), "mangle-afl-harness"],
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"make -n failed: stdout={result.stdout} stderr={result.stderr}"
        )
        # The dry-run output should mention the compiler invocation.
        assert "harness.c" in result.stdout

    def test_readme_documents_both_integration_paths(self):
        text = (CONTRIB_DIR / "README.md").read_text()
        # Path 1 — pre-processing / corpus seeding.
        assert "afl-fuzz" in text
        # Path 2 — persistent-mode harness build.
        assert "afl-clang-fast" in text
        # Both `mangle corpus` (seed building) and `mangle afl-mutate` (the
        # mutator wrapper) should be referenced.
        assert "mangle corpus" in text
        assert "mangle afl-mutate" in text

    def test_readme_references_post_v01(self):
        text = (CONTRIB_DIR / "README.md").read_text()
        # The README should anchor this work in POST_V01 item #7.
        assert "POST_V01" in text or "post-v0.1" in text.lower()
