"""Deterministic, exact inspection reports for password policy state spaces."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
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
SENSITIVITY_SCHEMA_VERSION = 1
SENSITIVITY_ANALYSIS = "one-step-class-minimum-relaxation-v1"


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


@dataclass(frozen=True, slots=True)
class MinimumRelaxation:
    """Exact effect of relaxing one class minimum by at most one."""

    class_name: str
    original_minimum: int
    relaxation_applied: bool
    relaxed_minimum: int
    relaxed_policy_sha256: str
    relaxed_valid: int
    added_if_relaxed: int
    baseline_fraction_numerator: int
    baseline_fraction_denominator: int

    def to_mapping(self) -> dict[str, object]:
        """Return one stable JSON-safe sensitivity row."""

        return {
            "class_name": self.class_name,
            "original_minimum": self.original_minimum,
            "relaxation_applied": self.relaxation_applied,
            "relaxed_minimum": self.relaxed_minimum,
            "relaxed_policy_sha256": self.relaxed_policy_sha256,
            "relaxed_valid": str(self.relaxed_valid),
            "added_if_relaxed": str(self.added_if_relaxed),
            "baseline_share_of_relaxed": {
                "numerator": str(self.baseline_fraction_numerator),
                "denominator": str(self.baseline_fraction_denominator),
            },
        }


@dataclass(frozen=True, slots=True)
class PolicySensitivity:
    """One exact, entropy-free one-step minimum sensitivity report."""

    policy: PasswordPolicy
    policy_sha256: str
    baseline_valid: int
    rows: tuple[MinimumRelaxation, ...]

    def to_mapping(self) -> dict[str, object]:
        """Return the stable sensitivity report contract."""

        return {
            "sensitivity_schema_version": SENSITIVITY_SCHEMA_VERSION,
            "analysis": SENSITIVITY_ANALYSIS,
            "rank_order_version": RANK_ORDER_VERSION,
            "policy_sha256": self.policy_sha256,
            "policy": {
                "length": self.policy.length,
                "alphabet_size": len(self.policy.alphabet),
                "class_minima": {
                    character_class.name: character_class.minimum
                    for character_class in self.policy.classes
                },
            },
            "baseline_valid": str(self.baseline_valid),
            "rows": [row.to_mapping() for row in self.rows],
            "claim_boundary": {
                "one_step_only": True,
                "effects_are_not_additive": True,
                "contains_candidate": False,
                "samples_entropy": False,
            },
        }


def analyze_policy_sensitivity(policy: PasswordPolicy) -> PolicySensitivity:
    """Measure each class minimum's exact one-step marginal effect."""

    if type(policy) is not PasswordPolicy:
        raise TypeError("policy must be a PasswordPolicy")

    baseline_valid = PasswordSpace(policy).total
    baseline_sha256 = policy_sha256(policy)
    rows: list[MinimumRelaxation] = []
    for class_index, character_class in enumerate(policy.classes):
        relaxed_minimum = max(0, character_class.minimum - 1)
        relaxation_applied = relaxed_minimum != character_class.minimum
        if relaxation_applied:
            relaxed_policy = PasswordPolicy(
                length=policy.length,
                classes=tuple(
                    replace(candidate, minimum=relaxed_minimum)
                    if index == class_index
                    else candidate
                    for index, candidate in enumerate(policy.classes)
                ),
            )
            relaxed_valid = PasswordSpace(relaxed_policy).total
            relaxed_sha256 = policy_sha256(relaxed_policy)
        else:
            relaxed_valid = baseline_valid
            relaxed_sha256 = baseline_sha256

        divisor = gcd(baseline_valid, relaxed_valid)
        rows.append(
            MinimumRelaxation(
                class_name=character_class.name,
                original_minimum=character_class.minimum,
                relaxation_applied=relaxation_applied,
                relaxed_minimum=relaxed_minimum,
                relaxed_policy_sha256=relaxed_sha256,
                relaxed_valid=relaxed_valid,
                added_if_relaxed=relaxed_valid - baseline_valid,
                baseline_fraction_numerator=baseline_valid // divisor,
                baseline_fraction_denominator=relaxed_valid // divisor,
            )
        )

    return PolicySensitivity(
        policy=policy,
        policy_sha256=baseline_sha256,
        baseline_valid=baseline_valid,
        rows=tuple(rows),
    )
