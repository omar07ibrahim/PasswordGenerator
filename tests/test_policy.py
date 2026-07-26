from __future__ import annotations

import pytest

from password_policy_lab import (
    CharacterClass,
    PasswordPolicy,
    PolicyValidationError,
)
from password_policy_lab.policy import MAX_CLASSES, MAX_LENGTH


def test_policy_preserves_normative_declaration_order() -> None:
    policy = PasswordPolicy(
        length=4,
        classes=(
            CharacterClass("letters", "ba", 1),
            CharacterClass("digits", "10", 2),
        ),
    )

    assert policy.alphabet == "ba10"
    assert policy.minima == (1, 2)


@pytest.mark.parametrize(
    ("name", "symbols", "minimum", "error"),
    [
        ("", "ab", 0, PolicyValidationError),
        ("UPPER", "ab", 0, PolicyValidationError),
        ("two words", "ab", 0, PolicyValidationError),
        ("a" * 33, "ab", 0, PolicyValidationError),
        ("letters", "", 0, PolicyValidationError),
        ("letters", "!" * 95, 0, PolicyValidationError),
        ("letters", "aa", 0, PolicyValidationError),
        ("letters", "a ", 0, PolicyValidationError),
        ("letters", "a\n", 0, PolicyValidationError),
        ("letters", "aé", 0, PolicyValidationError),
        ("letters", "ab", -1, PolicyValidationError),
        (1, "ab", 0, TypeError),
        ("letters", 1, 0, TypeError),
        ("letters", "ab", True, TypeError),
    ],
)
def test_character_class_rejects_ambiguous_inputs(
    name: object,
    symbols: object,
    minimum: object,
    error: type[Exception],
) -> None:
    with pytest.raises(error):
        CharacterClass(name=name, symbols=symbols, minimum=minimum)  # type: ignore[arg-type]


def test_visible_ascii_boundaries_are_supported() -> None:
    character_class = CharacterClass("edges", "!~", 0)

    assert character_class.symbols == "!~"


@pytest.mark.parametrize("length", [0, -1, MAX_LENGTH + 1])
def test_policy_rejects_out_of_range_length(length: int) -> None:
    with pytest.raises(PolicyValidationError, match="length"):
        PasswordPolicy(length, (CharacterClass("letters", "ab"),))


def test_policy_rejects_boolean_length() -> None:
    with pytest.raises(TypeError, match="length"):
        PasswordPolicy(True, (CharacterClass("letters", "ab"),))


def test_policy_requires_an_immutable_tuple_of_classes() -> None:
    with pytest.raises(TypeError, match="tuple"):
        PasswordPolicy(4, [CharacterClass("letters", "ab")])  # type: ignore[arg-type]


def test_policy_rejects_empty_or_excessive_class_count() -> None:
    with pytest.raises(PolicyValidationError, match="between"):
        PasswordPolicy(4, ())

    too_many = tuple(
        CharacterClass(f"class-{index}", chr(ord("!") + index))
        for index in range(MAX_CLASSES + 1)
    )
    with pytest.raises(PolicyValidationError, match="between"):
        PasswordPolicy(MAX_CLASSES + 1, too_many)


def test_policy_requires_character_class_values() -> None:
    with pytest.raises(TypeError, match="CharacterClass"):
        PasswordPolicy(4, ("letters",))  # type: ignore[arg-type]


def test_policy_rejects_duplicate_names_and_overlapping_symbols() -> None:
    with pytest.raises(PolicyValidationError, match="names"):
        PasswordPolicy(
            4,
            (
                CharacterClass("letters", "ab"),
                CharacterClass("letters", "CD"),
            ),
        )

    with pytest.raises(PolicyValidationError, match="disjoint"):
        PasswordPolicy(
            4,
            (
                CharacterClass("letters", "ab"),
                CharacterClass("more", "bC"),
            ),
        )


def test_policy_rejects_impossible_minima() -> None:
    with pytest.raises(PolicyValidationError, match="policy length"):
        PasswordPolicy(2, (CharacterClass("letters", "ab", 3),))

    with pytest.raises(PolicyValidationError, match="sum"):
        PasswordPolicy(
            3,
            (
                CharacterClass("letters", "ab", 2),
                CharacterClass("digits", "01", 2),
            ),
        )
