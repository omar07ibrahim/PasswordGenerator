from __future__ import annotations

import json
from itertools import combinations, pairwise

import pytest

from password_policy_lab import (
    CharacterClass,
    PasswordPolicy,
    PasswordSpace,
    inspect_policy,
    inspect_space,
    policy_sha256,
    visible_ascii_policy,
)
from password_policy_lab.inspection import (
    POLICY_FINGERPRINT_SCHEMA_VERSION,
    RANK_ORDER_VERSION,
    REPORT_SCHEMA_VERSION,
)
from password_policy_lab.space import MAX_DP_CELLS, MAX_DP_TRANSITIONS


def test_inspection_reports_exact_counts_fraction_and_dp_bounds() -> None:
    policy = PasswordPolicy(
        2,
        (
            CharacterClass("letters", "ab", 1),
            CharacterClass("digits", "0", 1),
        ),
    )

    report = inspect_policy(policy)
    mapping = report.to_mapping()

    assert report.policy is policy
    assert report.valid == 4
    assert report.unconstrained == 9
    assert report.excluded == 5
    assert (report.fraction_numerator, report.fraction_denominator) == (4, 9)
    assert (report.entropy_bits_floor, report.entropy_bits_ceiling) == (2, 2)
    assert report.deficit_vectors_upper_bound_per_layer == 4
    assert report.dp_cells_upper_bound == 12
    assert report.dp_transitions_upper_bound == 24
    assert mapping == {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "rank_order_version": RANK_ORDER_VERSION,
        "policy_sha256": report.policy_sha256,
        "policy": {
            "length": 2,
            "class_count": 2,
            "alphabet_size": 3,
            "minimum_total": 2,
            "classes": [
                {"name": "letters", "size": 2, "minimum": 1},
                {"name": "digits", "size": 1, "minimum": 1},
            ],
        },
        "state_space": {
            "valid": "4",
            "unconstrained": "9",
            "excluded": "5",
            "satisfying_fraction": {"numerator": "4", "denominator": "9"},
            "rank": {"minimum": "0", "maximum": "3"},
            "uniform_candidate_probability": {
                "numerator": "1",
                "denominator": "4",
            },
            "entropy_bits": {"floor": 2, "ceiling": 2},
        },
        "dynamic_programming": {
            "deficit_vectors_upper_bound_per_layer": 4,
            "cells_upper_bound": 12,
            "transitions_upper_bound": 24,
            "cells_budget": MAX_DP_CELLS,
            "transitions_budget": MAX_DP_TRANSITIONS,
        },
    }


def test_existing_space_can_be_inspected_without_reconstruction() -> None:
    space = PasswordSpace(PasswordPolicy(2, (CharacterClass("letters", "ab"),)))

    report = inspect_space(space)

    assert report.policy is space.policy
    assert report.valid == space.total == 4


def test_inspect_space_requires_an_exact_password_space() -> None:
    with pytest.raises(TypeError, match="PasswordSpace"):
        inspect_space("not-a-space")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("policy", "valid", "floor", "ceiling"),
    [
        (PasswordPolicy(1, (CharacterClass("one", "a"),)), 1, 0, 0),
        (PasswordPolicy(2, (CharacterClass("two", "ab"),)), 4, 2, 2),
        (PasswordPolicy(1, (CharacterClass("three", "abc"),)), 3, 1, 2),
    ],
)
def test_entropy_bounds_are_exact_for_edge_shapes(
    policy: PasswordPolicy,
    valid: int,
    floor: int,
    ceiling: int,
) -> None:
    report = inspect_policy(policy)

    assert report.valid == valid
    assert report.entropy_bits_floor == floor
    assert report.entropy_bits_ceiling == ceiling


def test_large_counts_remain_decimal_strings_in_mapping() -> None:
    mapping = inspect_policy(visible_ascii_policy(256)).to_mapping()
    state_space = mapping["state_space"]

    assert isinstance(state_space, dict)
    assert len(state_space["valid"]) > 500
    assert isinstance(state_space["valid"], str)
    assert isinstance(state_space["unconstrained"], str)
    assert isinstance(state_space["excluded"], str)


def test_visible_ascii_count_matches_independent_inclusion_exclusion() -> None:
    length = 8
    widths = (26, 26, 10, 32)
    expected = 0
    for excluded_class_count in range(len(widths) + 1):
        sign = -1 if excluded_class_count % 2 else 1
        for excluded in combinations(widths, excluded_class_count):
            expected += sign * (sum(widths) - sum(excluded)) ** length

    report = inspect_policy(visible_ascii_policy(length))

    assert report.valid == expected
    assert report.policy_sha256 == (
        "sha256:1147a3e1e23b038a44892960665003fa5ef20e6cffd972491c29bc8af8ab5451"
    )


def test_visible_ascii_sweep_obeys_exact_extension_and_fraction_invariants() -> None:
    reports = [inspect_policy(visible_ascii_policy(length)) for length in range(4, 17)]

    for previous, current in pairwise(reports):
        assert current.valid >= len(current.policy.alphabet) * previous.valid
        assert (
            current.valid * previous.unconstrained
            >= previous.valid * current.unconstrained
        )


def test_policy_fingerprint_is_semantic_stable_and_order_sensitive() -> None:
    first = PasswordPolicy(
        2,
        (
            CharacterClass("letters", "ab", 1),
            CharacterClass("digits", "01", 1),
        ),
    )
    equivalent = PasswordPolicy(
        length=2,
        classes=(
            CharacterClass(name="letters", symbols="ab", minimum=1),
            CharacterClass(name="digits", symbols="01", minimum=1),
        ),
    )
    reordered = PasswordPolicy(
        2,
        (
            CharacterClass("digits", "01", 1),
            CharacterClass("letters", "ab", 1),
        ),
    )

    fingerprint = policy_sha256(first)

    assert fingerprint == policy_sha256(equivalent)
    assert fingerprint != policy_sha256(reordered)
    assert fingerprint.startswith("sha256:")
    assert len(fingerprint) == len("sha256:") + 64
    assert POLICY_FINGERPRINT_SCHEMA_VERSION == 1
    assert json.dumps(inspect_policy(first).to_mapping(), sort_keys=True)


@pytest.mark.parametrize("function", [policy_sha256, inspect_policy])
def test_inspection_entry_points_require_exact_password_policies(
    function: object,
) -> None:
    assert callable(function)
    with pytest.raises(TypeError, match="PasswordPolicy"):
        function("not-a-policy")
