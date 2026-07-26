from __future__ import annotations

from collections.abc import Iterator

import pytest

from password_policy_lab import (
    CharacterClass,
    PasswordPolicy,
    PasswordSpace,
    PolicyComplexityError,
)


def test_all_optional_classes_reduce_to_the_cartesian_power() -> None:
    space = PasswordSpace(
        PasswordPolicy(
            64,
            (
                CharacterClass("left", "ab"),
                CharacterClass("right", "XYZ"),
            ),
        )
    )

    assert space.total == 5**64


def test_required_classes_have_exact_known_counts() -> None:
    two_positions = PasswordSpace(
        PasswordPolicy(
            2,
            (
                CharacterClass("letters", "ab", 1),
                CharacterClass("digits", "01", 1),
            ),
        )
    )
    three_positions = PasswordSpace(
        PasswordPolicy(
            3,
            (
                CharacterClass("letters", "ab", 1),
                CharacterClass("digits", "01", 1),
            ),
        )
    )

    assert two_positions.total == 8
    assert three_positions.total == 48


def test_minima_equal_to_length_match_the_multinomial_closed_form() -> None:
    space = PasswordSpace(
        PasswordPolicy(
            3,
            (
                CharacterClass("letters", "ab", 2),
                CharacterClass("digits", "012", 1),
            ),
        )
    )

    assert space.total == 3 * (2**2) * 3


def test_one_required_class_uses_arbitrary_precision_integers() -> None:
    space = PasswordSpace(
        PasswordPolicy(
            256,
            (CharacterClass("bits", "01", 256),),
        )
    )

    assert space.total == 2**256


def test_complexity_is_rejected_before_state_enumeration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = PasswordPolicy(
        32,
        tuple(
            CharacterClass(f"class-{index}", chr(ord("!") + index), 4)
            for index in range(8)
        ),
    )

    def fail_product(*values: object) -> Iterator[tuple[object, ...]]:
        raise AssertionError(f"state product must not be called: {len(values)}")

    monkeypatch.setattr("password_policy_lab.space.product", fail_product)

    with pytest.raises(PolicyComplexityError, match="complexity budget"):
        PasswordSpace(policy)
