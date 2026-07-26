"""Deterministic, exact inspection reports for password policy state spaces."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from math import gcd, prod

from password_policy_lab.policy import PasswordPolicy
from password_policy_lab.space import (
    MAX_DP_CELLS,
    MAX_DP_TRANSITIONS,
    PasswordSpace,
)

REPORT_SCHEMA_VERSION = 1
POLICY_FINGERPRINT_SCHEMA_VERSION = 1
RANK_ORDER_VERSION = "class-symbol-lexicographic-v1"


def policy_sha256(policy: PasswordPolicy) -> str:
    """Bind rank semantics to one exact ordered policy."""

    if type(policy) is not PasswordPolicy:
        raise TypeError("policy must be a PasswordPolicy")

    canonical_policy = {
        "classes": [
            {
                "minimum": character_class.minimum,
                "name": character_class.name,
                "symbols": character_class.symbols,
            }
            for character_class in policy.classes
        ],
        "length": policy.length,
        "policy_fingerprint_schema_version": POLICY_FINGERPRINT_SCHEMA_VERSION,
    }
    encoded = json.dumps(
        canonical_policy,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


@dataclass(frozen=True, slots=True)
class StateSpaceInspection:
    """One immutable exact report, with no timestamps or environment data."""

    policy: PasswordPolicy
    policy_sha256: str
    valid: int
    unconstrained: int
    excluded: int
    fraction_numerator: int
    fraction_denominator: int
    entropy_bits_floor: int
    entropy_bits_ceiling: int
    deficit_vectors_upper_bound_per_layer: int
    dp_cells_upper_bound: int
    dp_transitions_upper_bound: int

    def to_mapping(self) -> dict[str, object]:
        """Return the stable, JSON-safe report contract."""

        return {
            "report_schema_version": REPORT_SCHEMA_VERSION,
            "rank_order_version": RANK_ORDER_VERSION,
            "policy_sha256": self.policy_sha256,
            "policy": {
                "length": self.policy.length,
                "class_count": len(self.policy.classes),
                "alphabet_size": len(self.policy.alphabet),
                "minimum_total": sum(self.policy.minima),
                "classes": [
                    {
                        "name": character_class.name,
                        "size": len(character_class.symbols),
                        "minimum": character_class.minimum,
                    }
                    for character_class in self.policy.classes
                ],
            },
            "state_space": {
                "valid": str(self.valid),
                "unconstrained": str(self.unconstrained),
                "excluded": str(self.excluded),
                "satisfying_fraction": {
                    "numerator": str(self.fraction_numerator),
                    "denominator": str(self.fraction_denominator),
                },
                "rank": {
                    "minimum": "0",
                    "maximum": str(self.valid - 1),
                },
                "uniform_candidate_probability": {
                    "numerator": "1",
                    "denominator": str(self.valid),
                },
                "entropy_bits": {
                    "floor": self.entropy_bits_floor,
                    "ceiling": self.entropy_bits_ceiling,
                },
            },
            "dynamic_programming": {
                "deficit_vectors_upper_bound_per_layer": (
                    self.deficit_vectors_upper_bound_per_layer
                ),
                "cells_upper_bound": self.dp_cells_upper_bound,
                "transitions_upper_bound": self.dp_transitions_upper_bound,
                "cells_budget": MAX_DP_CELLS,
                "transitions_budget": MAX_DP_TRANSITIONS,
            },
        }


def inspect_policy(policy: PasswordPolicy) -> StateSpaceInspection:
    """Compute exact counts and bounded-DP metadata without consuming entropy."""

    if type(policy) is not PasswordPolicy:
        raise TypeError("policy must be a PasswordPolicy")

    return inspect_space(PasswordSpace(policy))


def inspect_space(space: PasswordSpace) -> StateSpaceInspection:
    """Inspect one already-built space without repeating its DP construction."""

    if type(space) is not PasswordSpace:
        raise TypeError("space must be a PasswordSpace")

    policy = space.policy
    alphabet_size = len(policy.alphabet)
    unconstrained = alphabet_size**policy.length
    valid = space.total
    divisor = gcd(valid, unconstrained)
    deficit_vectors = prod(minimum + 1 for minimum in policy.minima)
    cells = (policy.length + 1) * deficit_vectors

    return StateSpaceInspection(
        policy=policy,
        policy_sha256=policy_sha256(policy),
        valid=valid,
        unconstrained=unconstrained,
        excluded=unconstrained - valid,
        fraction_numerator=valid // divisor,
        fraction_denominator=unconstrained // divisor,
        entropy_bits_floor=valid.bit_length() - 1,
        entropy_bits_ceiling=(valid - 1).bit_length(),
        deficit_vectors_upper_bound_per_layer=deficit_vectors,
        dp_cells_upper_bound=cells,
        dp_transitions_upper_bound=len(policy.classes) * cells,
    )
