from __future__ import annotations

import pytest

from password_policy_lab import CharacterClass, PasswordPolicy, PasswordSpace


def test_uniform_sampling_uses_one_exact_state_space_rank(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    space = PasswordSpace(
        PasswordPolicy(
            3,
            (
                CharacterClass("narrow", "a", 1),
                CharacterClass("wide", "012", 1),
            ),
        )
    )
    calls: list[int] = []

    def fixed_rank(upper_bound: int) -> int:
        calls.append(upper_bound)
        return upper_bound - 1

    monkeypatch.setattr("password_policy_lab.space.secrets.randbelow", fixed_rank)

    assert space.sample_uniform() == space.unrank(space.total - 1)
    assert calls == [space.total]


def test_count_rank_and_unrank_do_not_consume_randomness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_randomness(upper_bound: int) -> int:
        raise AssertionError(f"unexpected randomness request: {upper_bound}")

    monkeypatch.setattr(
        "password_policy_lab.space.secrets.randbelow",
        forbidden_randomness,
    )
    space = PasswordSpace(
        PasswordPolicy(
            2,
            (
                CharacterClass("letters", "ab", 1),
                CharacterClass("digits", "01", 1),
            ),
        )
    )

    assert space.total == 8
    assert space.unrank(3) == "b1"
    assert space.rank("b1") == 3
