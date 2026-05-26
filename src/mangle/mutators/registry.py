"""Mutator registry and shared result type."""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable

from ..bitstream import NalUnit


@dataclass
class MutationResult:
    """Outcome of applying a mutator to a NAL list.

    Attributes:
        nals: the mutated NAL list (ready to assemble).
        mutator: the mutator's CLI name.
        bytes_changed: number of bytes that differ from the original stream.
        detail: a human-readable note about what was changed.
    """

    nals: list[NalUnit]
    mutator: str
    bytes_changed: int
    detail: str


Mutator = Callable[[list[NalUnit], random.Random], MutationResult]

# Populated by register() calls in mutators.builtin (imported below).
MUTATORS: dict[str, Mutator] = {}


def register(name: str) -> Callable[[Mutator], Mutator]:
    def deco(fn: Mutator) -> Mutator:
        MUTATORS[name] = fn
        return fn

    return deco


def get_mutator(name: str) -> Mutator:
    if name not in MUTATORS:
        raise KeyError(
            f"unknown mutator '{name}'. available: {', '.join(sorted(MUTATORS))}"
        )
    return MUTATORS[name]


def list_mutators() -> list[str]:
    return sorted(MUTATORS)


def count_changed_bytes(original: bytes, mutated: bytes) -> int:
    """Count differing bytes between two byte strings (length-aware)."""
    changed = abs(len(original) - len(mutated))
    for a, b in zip(original, mutated):
        if a != b:
            changed += 1
    return changed


# Import built-in mutators so their @register decorators run on package import.
from . import builtin as _builtin  # noqa: E402,F401
