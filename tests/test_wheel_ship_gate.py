"""Ship-gate tests — pin the wheel-install contract at v1.0.0.

All tests are marked @pytest.mark.ship_gate so they can be deselected with
``-m "not ship_gate"`` for fast iteration. They are included in the default
test run (no deselection) for the v1.0 release ship-gate.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
EXPECTED_VERSION = "1.0.0"


@pytest.mark.ship_gate
def test_wheel_builds_and_sdist_produced(tmp_path):
    """Build wheel + sdist from a fresh venv; assert both artifacts exist."""
    venv_dir = tmp_path / "build-venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
    )
    pip = str(venv_dir / "bin" / "pip")
    subprocess.run(
        [pip, "install", "--quiet", "build"],
        check=True,
        capture_output=True,
    )
    python = str(venv_dir / "bin" / "python")
    result = subprocess.run(
        [python, "-m", "build", "--wheel", "--sdist", str(REPO_ROOT)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"build failed:\n{result.stderr}"
    dist_dir = REPO_ROOT / "dist"
    whl_files = list(dist_dir.glob(f"mangle-{EXPECTED_VERSION}-*.whl"))
    sdist_files = list(dist_dir.glob(f"mangle-{EXPECTED_VERSION}.tar.gz"))
    assert whl_files, f"No wheel found in {dist_dir} matching mangle-{EXPECTED_VERSION}-*.whl"
    assert sdist_files, f"No sdist found in {dist_dir} matching mangle-{EXPECTED_VERSION}.tar.gz"


@pytest.mark.ship_gate
def test_installed_wheel_cli_version_wires_through(tmp_path):
    """Install the wheel into a fresh venv; assert `mangle --version` == 'mangle 1.0.0'."""
    dist_dir = REPO_ROOT / "dist"
    whl_files = list(dist_dir.glob(f"mangle-{EXPECTED_VERSION}-*.whl"))
    if not whl_files:
        pytest.skip(f"Wheel not found in {dist_dir}; run test_wheel_builds_and_sdist_produced first")
    whl = whl_files[0]

    venv_dir = tmp_path / "install-venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
    )
    pip = str(venv_dir / "bin" / "pip")
    subprocess.run(
        [pip, "install", "--quiet", str(whl)],
        check=True,
        capture_output=True,
    )
    mangle_bin = str(venv_dir / "bin" / "mangle")
    result = subprocess.run(
        [mangle_bin, "--version"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"mangle --version failed: {result.stderr}"
    assert result.stdout.strip() == f"mangle {EXPECTED_VERSION}", (
        f"Expected 'mangle {EXPECTED_VERSION}', got '{result.stdout.strip()}'"
    )


@pytest.mark.ship_gate
def test_installed_wheel_imports_all_submodules(tmp_path):
    """Install the wheel; assert all 15 sub-modules import and __version__ is correct."""
    dist_dir = REPO_ROOT / "dist"
    whl_files = list(dist_dir.glob(f"mangle-{EXPECTED_VERSION}-*.whl"))
    if not whl_files:
        pytest.skip(f"Wheel not found in {dist_dir}; run test_wheel_builds_and_sdist_produced first")
    whl = whl_files[0]

    venv_dir = tmp_path / "import-venv"
    subprocess.run(
        [sys.executable, "-m", "venv", str(venv_dir)],
        check=True,
        capture_output=True,
    )
    pip = str(venv_dir / "bin" / "pip")
    subprocess.run(
        [pip, "install", "--quiet", str(whl)],
        check=True,
        capture_output=True,
    )
    python = str(venv_dir / "bin" / "python")
    import_stmt = (
        "import mangle, mangle.afl, mangle.bitstream, mangle.cli, mangle.corpus, "
        "mangle.corpus_trim, mangle.coverage, mangle.decoder, mangle.engine, "
        "mangle.heatmap, mangle.hevc, mangle.mutation_score, mangle.reduce, "
        "mangle.replay, mangle.scheduler, mangle.triage; "
        "print(mangle.__version__)"
    )
    result = subprocess.run(
        [python, "-c", import_stmt],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"Sub-module import failed:\n{result.stderr}"
    assert result.stdout.strip() == EXPECTED_VERSION, (
        f"Expected __version__ == '{EXPECTED_VERSION}', got '{result.stdout.strip()}'"
    )


@pytest.mark.ship_gate
def test_installed_wheel_py_version_compatible():
    """Verify this interpreter satisfies requires-python >= 3.13."""
    assert sys.version_info >= (3, 13), (
        f"Python {sys.version_info.major}.{sys.version_info.minor} < 3.13 "
        "— does not satisfy mangle's requires-python constraint"
    )


@pytest.mark.ship_gate
def test_changelog_exists_with_v1_0_0_entry():
    """Assert CHANGELOG.md exists at repo root and contains '## [1.0.0]'."""
    changelog = REPO_ROOT / "CHANGELOG.md"
    assert changelog.exists(), f"CHANGELOG.md not found at {changelog}"
    content = changelog.read_text(encoding="utf-8")
    assert "## [1.0.0]" in content, (
        "CHANGELOG.md does not contain '## [1.0.0]' entry"
    )


@pytest.mark.ship_gate
def test_repo_version_matches_pyproject_and_module():
    """Assert version in pyproject.toml and src/mangle/__init__.py both equal 1.0.0."""
    pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    init_py = (REPO_ROOT / "src" / "mangle" / "__init__.py").read_text(encoding="utf-8")

    assert f'version = "{EXPECTED_VERSION}"' in pyproject, (
        f"pyproject.toml does not contain version = \"{EXPECTED_VERSION}\""
    )
    assert f'__version__ = "{EXPECTED_VERSION}"' in init_py, (
        f"src/mangle/__init__.py does not contain __version__ = \"{EXPECTED_VERSION}\""
    )
