from __future__ import annotations

from itertools import product

import pytest

from password_policy_lab import (
    CharacterClass,
    PasswordPolicy,
    PasswordSpace,
    PasswordValidationError,
    RankOutOfRangeError,
)


def _oracle(policy: PasswordPolicy) -> list[str]:
    valid: list[str] = []
    for symbols in product(policy.alphabet, repeat=policy.length):
        password = "".join(symbols)
        if all(
            sum(symbol in character_class.symbols for symbol in password)
            >= character_class.minimum
            for character_class in policy.classes
        ):
            valid.append(password)
    return valid


@pytest.mark.parametrize(
    "policy",
    [
        PasswordPolicy(2, (CharacterClass("letters", "ab"),)),
        PasswordPolicy(
            2,
            (
                CharacterClass("letters", "ab", 1),
                CharacterClass("digits", "01", 1),
            ),
        ),
        PasswordPolicy(
            3,
            (
                CharacterClass("letters", "ba", 1),
                CharacterClass("digits", "0", 1),
                CharacterClass("symbols", "!", 0),
            ),
        ),
        PasswordPolicy(
            4,
            (
                CharacterClass("letters", "ab", 2),
                CharacterClass("digits", "01", 1),
            ),
        ),
    ],
)
def test_rank_and_unrank_match_an_independent_exhaustive_oracle(
    policy: PasswordPolicy,
) -> None:
    expected = _oracle(policy)
    space = PasswordSpace(policy)

    actual = [space.unrank(index) for index in range(space.total)]

    assert space.total == len(expected)
    assert actual == expected
    assert len(set(actual)) == space.total
    assert [space.rank(password) for password in expected] == list(range(space.total))
    assert space.policy is policy
    assert space.alphabet == policy.alphabet


def test_golden_rank_order_is_stable() -> None:
    space = PasswordSpace(
        PasswordPolicy(
            2,
            (
                CharacterClass("letters", "ab", 1),
                CharacterClass("digits", "01", 1),
            ),
        )
    )

    assert [space.unrank(index) for index in range(space.total)] == [
        "a0",
        "a1",
        "b0",
        "b1",
        "0a",
        "0b",
        "1a",
        "1b",
    ]


@pytest.mark.parametrize("index", [-1, 8])
def test_unrank_rejects_out_of_range_indices(index: int) -> None:
    space = PasswordSpace(
        PasswordPolicy(
            2,
            (
                CharacterClass("letters", "ab", 1),
                CharacterClass("digits", "01", 1),
            ),
        )
    )

    with pytest.raises(RankOutOfRangeError, match="outside"):
        space.unrank(index)


@pytest.mark.parametrize("index", [True, 1.0, "1"])
def test_unrank_requires_an_exact_integer(index: object) -> None:
    space = PasswordSpace(PasswordPolicy(1, (CharacterClass("letters", "ab"),)))

    with pytest.raises(TypeError, match="integer"):
        space.unrank(index)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("candidate", "message"),
    [
        ("UNIQUE-WRONG-LENGTH", "wrong length"),
        ("a?", "outside"),
        ("aa", "minima"),
    ],
)
def test_rank_rejects_invalid_password_without_echoing_it(
    candidate: str,
    message: str,
) -> None:
    space = PasswordSpace(
        PasswordPolicy(
            2,
            (
                CharacterClass("letters", "ab", 1),
                CharacterClass("digits", "01", 1),
            ),
        )
    )

    with pytest.raises(PasswordValidationError, match=message) as raised:
        space.rank(candidate)

    assert candidate not in str(raised.value)


def test_rank_requires_a_string() -> None:
    space = PasswordSpace(PasswordPolicy(1, (CharacterClass("letters", "ab"),)))

    with pytest.raises(TypeError, match="string"):
        space.rank(1)  # type: ignore[arg-type]


def test_space_requires_a_password_policy() -> None:
    with pytest.raises(TypeError, match="PasswordPolicy"):
        PasswordSpace("not-a-policy")  # type: ignore[arg-type]
