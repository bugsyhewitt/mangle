# Changelog

All notable changes to mangle are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] — 2026-06-19

The first production-ready release of mangle — a structured H.265 (HEVC) bitstream
fuzzer for security research. mangle ships with 12 CLI subcommands, 15 public
sub-modules, and a 652-test base suite (8055 test LOC).

### Added

- **CLI subcommands** (12 total): `mutate`, `fuzz`, `diff`, `corpus`, `corpus-trim`,
  `triage`, `reduce`, `replay`, `coverage`, `heatmap`, `mutation-score`, `afl-mutate`
  (AFL++ harness stdin/stdout wrapper).
- **Mutators library** (`src/mangle/mutators.py`): 2312 LOC covering VPS/SPS/PPS
  NAL-unit mutations, timing-info splicing, and HEVC header corruption patterns.
- **Engine** (`src/mangle/engine.py`): 860 LOC — fuzzing feedback loop with
  `--max-crashes` / `--max-time-without-crash` campaign stops, `--crash-dedup`,
  `--scheduler-state` adaptive resume from prior scoreboard.
- **Triage** (`src/mangle/triage.py`): 508 LOC — bucket crashes by severity.
- **Reduce** (`src/mangle/reduce.py`): 324 LOC — delta-debugging crash minimisation.
- **Coverage** (`src/mangle/coverage.py`): 358 LOC — AFL++ coverage-feedback integration.
- **Heatmap** (`src/mangle/heatmap.py`): 420 LOC — crash-density visualisations.
- **Diff oracle** (`src/mangle/engine.py` `--compare-output`): silent-acceptor /
  pixel-divergence detection.
- **Multi-seed corpus** (`--seed-corpus-dir`): single seed corpus replayable via
  `mangle replay --seed-dir`.
- **Mutation-score reporter** (`mutation-score` subcommand): campaign kill-ratio.

### Changed

- **Version bumped** from `0.1.0` → `1.0.0` in `pyproject.toml` and
  `src/mangle/__init__.py`.

### Fixed

- (None since 0.1.0 — see git log for prior 0.1.x feature-add commits.)

### Removed

- (None since 0.1.0.)

### Notes

- **Test count**: 652 collected (verified), all PASS at HEAD `bfd6183`
  on Python 3.14.5. Test base covers all mutators, all CLI subcommands, the AFL
  harness subprocess path, the campaign loop, and the triage/reduce/replay flows.
- **Wheel-install contract**: `pip install mangle-1.0.0-py3-none-any.whl` produces
  a working `mangle` console script; `mangle --version` prints "mangle 1.0.0".
- **Python compatibility**: `requires-python = ">=3.13"` (verified: 3.13.3 and
  3.14.5 both pass the full suite).
- **No external runtime dependencies** — `dependencies = []` in `pyproject.toml`.
  mangle is a self-contained H.265 bitstream fuzzer with no third-party imports
  beyond the Python stdlib.

[1.0.0]: https://github.com/bugsyhewitt/mangle/releases/tag/v1.0.0
