"""Structured HEVC bitstream mutators.

Each mutator targets a specific parameter-set or slice-header field and produces
a syntactically-correct but semantically spec-non-compliant H.265 bitstream.

A mutator is a callable with the signature::

    mutate(nals: list[NalUnit], rng: random.Random) -> MutationResult

Register new mutators in ``MUTATORS`` keyed by their CLI name.
"""

from __future__ import annotations

from .registry import MUTATORS, MutationResult, get_mutator, list_mutators

__all__ = ["MUTATORS", "MutationResult", "get_mutator", "list_mutators"]
