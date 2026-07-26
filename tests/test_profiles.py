from __future__ import annotations

import string

import pytest

from password_policy_lab import visible_ascii_policy
from password_policy_lab.profiles import (
    DEFAULT_VISIBLE_ASCII_MINIMA,
    VISIBLE_ASCII_CLASS_NAMES,
    VISIBLE_ASCII_CLASS_SYMBOLS,
)


def test_visible_ascii_profile_has_stable_normative_order() -> None:
    policy = visible_ascii_policy(12)

    assert policy.length == 12
    assert tuple(item.name for item in policy.classes) == VISIBLE_ASCII_CLASS_NAMES
    assert tuple(item.symbols for item in policy.classes) == (
        string.ascii_lowercase,
        string.ascii_uppercase,
        string.digits,
        string.punctuation,
    )
    assert tuple(item.symbols for item in policy.classes) == VISIBLE_ASCII_CLASS_SYMBOLS
    assert policy.minima == DEFAULT_VISIBLE_ASCII_MINIMA
    assert len(policy.alphabet) == 94


def test_visible_ascii_profile_accepts_explicit_minima() -> None:
    assert visible_ascii_policy(8, (2, 1, 0, 3)).minima == (2, 1, 0, 3)


@pytest.mark.parametrize("minima", [[], (1, 1, 1)])
def test_visible_ascii_profile_requires_an_exact_four_item_tuple(
    minima: object,
) -> None:
    with pytest.raises(TypeError, match="four-item tuple"):
        visible_ascii_policy(8, minima)  # type: ignore[arg-type]


def test_visible_ascii_profile_defers_exact_item_types_to_the_core() -> None:
    with pytest.raises(TypeError, match="integer"):
        visible_ascii_policy(8, (True, 1, 1, 1))
