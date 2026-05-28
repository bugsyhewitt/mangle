"""Crash triage and deduplication engine (POST_V01 item #8).

At scale (10K+ iterations) the raw ``crashes/`` directory and ``results.jsonl``
become unmanageable: the same decoder bug fires from many distinct mutants, so
the artifact count vastly exceeds the unique-bug count. Bug-bounty workflows and
responsible disclosure both require *dedup* before submission — you report one
PoC per bug, not one per crashing input.

This module is a pure post-processing pass over the artifacts that
:func:`mangle.engine.fuzz_async` already writes. It reads ``results.jsonl`` and
the ``crashes/`` directory and clusters crashes by a stable *signature*:

  1. **ASAN/UBSAN stack frames** — when the decoder was built with
     AddressSanitizer/UndefinedBehaviorSanitizer, its stderr embeds a symbolised
     stack trace. The top frames of that trace are the gold-standard crash
     fingerprint: two inputs whose top frames match are (almost always) the same
     bug. We extract the top ``frame_depth`` frame *function names*.
  2. **stderr signature fallback** — when no sanitizer trace is present (a plain
     ffmpeg/libde265 build), we fall back to a normalised hash of the decoder's
     stderr: lower-cased, with addresses / line numbers / temp paths / iteration
     digits stripped, so that two messages differing only in incidental numbers
     cluster together.

The cluster key is the triple ``(signature, decoder, mutator)`` — the same
``(top_frame, second_frame, mutation_type)`` triple recommended in the roadmap,
generalised to also work without a sanitizer. Each cluster keeps the
*representative* crash: the one with the smallest mutant file (the most minimal
PoC), tie-broken by lowest iteration for determinism.

Outputs:

  * ``triage.jsonl`` — one JSON line per cluster: cluster id, signature kind,
    signature, decoder, mutator, member count, representative hash, the member
    crash hashes, and the representative's top stack frames (if any).
  * ``unique-crashes/`` — the representative ``<hash>.h265`` + ``<hash>.txt`` of
    each cluster, copied verbatim from ``crashes/``, ready for disclosure.

Triage makes **zero changes** to the core mutation or fuzzing pipeline; it only
reads what ``fuzz`` already produced. It is fully deterministic.

References: the dedup-before-disclosure practice is standard in coverage-guided
fuzzing (AFL++ ``afl-cmin`` / crash-dedup); ASAN top-frame clustering is the
approach used by ClusterFuzz and OSS-Fuzz.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Signature extraction
# ---------------------------------------------------------------------------

# An ASAN/UBSAN backtrace frame line looks like:
#     #1 0x55a3c0ffee21 in hevc_decode_frame /src/libavcodec/hevcdec.c:1234:7
# We capture the frame index and the symbol (function) name. The trailing
# file:line:col is intentionally *not* part of the signature — line numbers shift
# between builds, function names are stable.
_ASAN_FRAME_RE = re.compile(
    r"^\s*#(?P<idx>\d+)\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>[^\s]+)",
    re.MULTILINE,
)

# Heuristic detector for "this stderr contains a sanitizer report at all".
_SANITIZER_MARKER_RE = re.compile(
    r"(AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|"
    r"runtime error:|ERROR: AddressSanitizer|SUMMARY: \w*Sanitizer)",
)

# Tokens to scrub from a plain stderr before hashing so that incidental,
# input-specific numbers do not split one bug into many clusters:
#   * hex addresses (0x....)
#   * standalone integers (offsets, line numbers, frame/packet counts)
#   * temp-file paths mangle writes (……/tmpXXXX.h265 or any .h265/.hevc path)
_HEX_RE = re.compile(r"0x[0-9a-fA-F]+")
_PATH_RE = re.compile(r"\S*\.(?:h265|hevc)\b")
_INT_RE = re.compile(r"\b\d+\b")


@dataclass
class CrashSignature:
    """The fingerprint of a single crash artifact.

    Attributes:
        kind: ``"asan"`` when derived from a sanitizer backtrace, else
            ``"stderr"`` for the normalised-stderr fallback.
        signature: the stable signature string (joined top frames, or a hash).
        frames: the extracted top stack-frame function names (empty for
            ``stderr`` kind).
    """

    kind: str
    signature: str
    frames: list[str] = field(default_factory=list)


def extract_frames(stderr: str, frame_depth: int = 3) -> list[str]:
    """Return the top ``frame_depth`` sanitizer stack-frame function names.

    Frames are ordered by their ``#N`` index (the crashing frame is ``#0``).
    Returns an empty list when no sanitizer frames are present.
    """
    frames: list[tuple[int, str]] = []
    for m in _ASAN_FRAME_RE.finditer(stderr):
        frames.append((int(m.group("idx")), m.group("func")))
    frames.sort(key=lambda t: t[0])
    return [func for _idx, func in frames[:frame_depth]]


def _normalise_stderr(stderr: str) -> str:
    """Collapse a plain stderr to its stable shape for signature hashing."""
    text = stderr.lower()
    text = _HEX_RE.sub("0xADDR", text)
    text = _PATH_RE.sub("FILE", text)
    text = _INT_RE.sub("N", text)
    # Collapse runs of whitespace so cosmetic wrapping does not matter.
    text = re.sub(r"\s+", " ", text).strip()
    return text


def signature_for(stderr: str, frame_depth: int = 3) -> CrashSignature:
    """Compute the dedup signature for one crash's stderr.

    Prefers the sanitizer top-frame signature; falls back to a normalised
    stderr hash when no sanitizer trace is present.
    """
    if _SANITIZER_MARKER_RE.search(stderr):
        frames = extract_frames(stderr, frame_depth)
        if frames:
            return CrashSignature(
                kind="asan",
                signature="|".join(frames),
                frames=frames,
            )
    normalised = _normalise_stderr(stderr)
    digest = hashlib.sha256(normalised.encode("utf-8")).hexdigest()[:16]
    return CrashSignature(kind="stderr", signature=digest, frames=[])


# ---------------------------------------------------------------------------
# Clustering
# ---------------------------------------------------------------------------


@dataclass
class CrashRecord:
    """One crash artifact assembled from results.jsonl + the crashes/ dir."""

    crash_hash: str
    decoder: str
    mutator: str
    iteration: int
    size: int
    signature: CrashSignature


@dataclass
class CrashCluster:
    """A deduplicated group of crashes sharing one (signature, decoder, mutator)."""

    cluster_id: int
    signature_kind: str
    signature: str
    decoder: str
    mutator: str
    count: int
    representative_hash: str
    representative_frames: list[str]
    member_hashes: list[str]


def _load_results(results_path: Path) -> list[dict]:
    """Parse a results.jsonl, returning the crash iteration records only."""
    records: list[dict] = []
    with results_path.open() as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if obj.get("crash_hash"):
                records.append(obj)
    return records


def cluster_crashes(
    output_dir: str | Path,
    decoder: str = "ffmpeg",
    frame_depth: int = 3,
) -> list[CrashCluster]:
    """Cluster the crashes in a fuzz ``output_dir`` into unique buckets.

    Reads ``<output_dir>/results.jsonl`` (for iteration/mutator metadata) and
    ``<output_dir>/crashes/<hash>.txt`` (for the decoder stderr that yields the
    signature). The ``<hash>.h265`` size is used to pick the most-minimal
    representative per cluster.

    ``decoder`` labels the campaign (results.jsonl does not record which decoder
    ran); it becomes part of the cluster key so a combined triage of two
    campaigns keeps per-decoder buckets distinct.

    Returns clusters sorted by descending member count, then by signature for
    deterministic ordering.
    """
    out_dir = Path(output_dir)
    results_path = out_dir / "results.jsonl"
    crashes_dir = out_dir / "crashes"
    if not results_path.exists():
        raise FileNotFoundError(f"no results.jsonl in {out_dir}")

    records: dict[str, CrashRecord] = {}
    for obj in _load_results(results_path):
        crash_hash = obj["crash_hash"]
        txt_path = crashes_dir / f"{crash_hash}.txt"
        bin_path = crashes_dir / f"{crash_hash}.h265"
        stderr = txt_path.read_text() if txt_path.exists() else ""
        size = bin_path.stat().st_size if bin_path.exists() else 0
        sig = signature_for(stderr, frame_depth)
        # The same crash_hash can appear from re-runs; keep the first (lowest
        # iteration) record per hash for stability.
        existing = records.get(crash_hash)
        if existing is None or obj["iteration"] < existing.iteration:
            records[crash_hash] = CrashRecord(
                crash_hash=crash_hash,
                decoder=decoder,
                mutator=obj.get("mutator", "unknown"),
                iteration=obj["iteration"],
                size=size,
                signature=sig,
            )

    buckets: dict[tuple[str, str, str], list[CrashRecord]] = {}
    for rec in records.values():
        key = (rec.signature.signature, rec.decoder, rec.mutator)
        buckets.setdefault(key, []).append(rec)

    clusters: list[CrashCluster] = []
    for (signature, dec, mutator), members in buckets.items():
        # Representative = smallest mutant (most minimal PoC), tie-broken by the
        # lowest iteration for full determinism.
        members.sort(key=lambda r: (r.size, r.iteration, r.crash_hash))
        rep = members[0]
        clusters.append(
            CrashCluster(
                cluster_id=0,  # assigned after global sort
                signature_kind=rep.signature.kind,
                signature=signature,
                decoder=dec,
                mutator=mutator,
                count=len(members),
                representative_hash=rep.crash_hash,
                representative_frames=rep.signature.frames,
                member_hashes=sorted(r.crash_hash for r in members),
            )
        )

    clusters.sort(key=lambda c: (-c.count, c.signature, c.decoder, c.mutator))
    for i, c in enumerate(clusters):
        c.cluster_id = i
    return clusters


def triage(
    output_dir: str | Path,
    decoder: str = "ffmpeg",
    frame_depth: int = 3,
) -> list[CrashCluster]:
    """Run the full triage pass: cluster, then write triage.jsonl + uniques.

    Writes ``<output_dir>/triage.jsonl`` (one cluster per line) and copies each
    cluster's representative ``<hash>.h265`` and ``<hash>.txt`` into
    ``<output_dir>/unique-crashes/``. Returns the cluster list.
    """
    out_dir = Path(output_dir)
    clusters = cluster_crashes(out_dir, decoder=decoder, frame_depth=frame_depth)

    crashes_dir = out_dir / "crashes"
    unique_dir = out_dir / "unique-crashes"
    unique_dir.mkdir(parents=True, exist_ok=True)

    triage_path = out_dir / "triage.jsonl"
    with triage_path.open("w") as fh:
        for c in clusters:
            fh.write(json.dumps(asdict(c)) + "\n")
            for suffix in (".h265", ".txt"):
                src = crashes_dir / f"{c.representative_hash}{suffix}"
                if src.exists():
                    shutil.copy2(src, unique_dir / src.name)
    return clusters
