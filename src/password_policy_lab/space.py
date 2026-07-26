"""Exact dynamic programming, ranking, and unbiased password sampling."""

from __future__ import annotations

import secrets
from itertools import product
from math import prod

from password_policy_lab.errors import (
    PasswordValidationError,
    PolicyComplexityError,
    RankOutOfRangeError,
)
from password_policy_lab.policy import PasswordPolicy

MAX_DP_CELLS = 250_000
MAX_DP_TRANSITIONS = 2_000_000

Deficits = tuple[int, ...]
CountLayer = dict[Deficits, int]


def _consume(deficits: Deficits, class_index: int) -> Deficits:
    if deficits[class_index] == 0:
        return deficits
    return (
        *deficits[:class_index],
        deficits[class_index] - 1,
        *deficits[class_index + 1 :],
    )


class PasswordSpace:
    """A bounded exact state space for one immutable password policy.

    Class and symbol declaration order defines the rank order. Sampling chooses
    one uniform rank and applies the same deterministic unranking bijection used
    by tests; this layer never retries candidate passwords or makes per-position
    random choices.
    """

    __slots__ = (
        "_alphabet",
        "_layers",
        "_locations",
        "_policy",
        "_total",
    )

    def __init__(self, policy: PasswordPolicy) -> None:
        if type(policy) is not PasswordPolicy:
            raise TypeError("policy must be a PasswordPolicy")

        state_count = prod(minimum + 1 for minimum in policy.minima)
        cell_upper_bound = (policy.length + 1) * state_count
        transition_upper_bound = len(policy.classes) * cell_upper_bound
        if (
            cell_upper_bound > MAX_DP_CELLS
            or transition_upper_bound > MAX_DP_TRANSITIONS
        ):
            raise PolicyComplexityError(
                "policy exceeds the dynamic-programming complexity budget"
            )

        self._policy = policy
        self._alphabet = policy.alphabet
        self._locations = {
            symbol: (class_index, symbol_offset)
            for class_index, character_class in enumerate(policy.classes)
            for symbol_offset, symbol in enumerate(character_class.symbols)
        }
        self._layers = self._build_layers()
        self._total = self._count(policy.length, policy.minima)
        if self._total == 0:  # pragma: no cover - guarded by policy invariants
            raise RuntimeError("validated policy produced an empty state space")

    @property
    def policy(self) -> PasswordPolicy:
        """Return the immutable policy represented by this space."""

        return self._policy

    @property
    def alphabet(self) -> str:
        """Return the normative rank order for symbols."""

        return self._alphabet

    @property
    def total(self) -> int:
        """Return the exact number of valid passwords."""

        return self._total

    def _build_layers(self) -> tuple[CountLayer, ...]:
        class_widths = tuple(
            len(character_class.symbols) for character_class in self._policy.classes
        )
        deficit_ranges = tuple(range(minimum + 1) for minimum in self._policy.minima)
        zero = (0,) * len(self._policy.classes)
        layers: list[CountLayer] = [{zero: 1}]

        for remaining in range(1, self._policy.length + 1):
            previous = layers[-1]
            layer: CountLayer = {}
            for deficits in product(*deficit_ranges):
                if sum(deficits) > remaining:
                    continue
                count = sum(
                    width * previous.get(_consume(deficits, class_index), 0)
                    for class_index, width in enumerate(class_widths)
                )
                layer[deficits] = count
            layers.append(layer)

        return tuple(layers)

    def _count(self, remaining: int, deficits: Deficits) -> int:
        return self._layers[remaining].get(deficits, 0)

    def _validated_locations(self, password: str) -> tuple[tuple[int, int], ...]:
        if type(password) is not str:
            raise TypeError("password must be a string")
        if len(password) != self._policy.length:
            raise PasswordValidationError("password has the wrong length")

        counts = [0] * len(self._policy.classes)
        locations: list[tuple[int, int]] = []
        for symbol in password:
            location = self._locations.get(symbol)
            if location is None:
                raise PasswordValidationError(
                    "password contains a symbol outside the policy"
                )
            counts[location[0]] += 1
            locations.append(location)

        if any(
            count < character_class.minimum
            for count, character_class in zip(
                counts,
                self._policy.classes,
                strict=True,
            )
        ):
            raise PasswordValidationError("password does not satisfy class minima")
        return tuple(locations)

    def rank(self, password: str) -> int:
        """Return the exact zero-based rank of a valid password."""

        locations = self._validated_locations(password)
        rank = 0
        deficits = self._policy.minima

        for position, (actual_class, symbol_offset) in enumerate(locations):
            remaining = self._policy.length - position - 1
            for class_index in range(actual_class):
                next_deficits = _consume(deficits, class_index)
                rank += len(self._policy.classes[class_index].symbols) * self._count(
                    remaining,
                    next_deficits,
                )

            actual_deficits = _consume(deficits, actual_class)
            rank += symbol_offset * self._count(remaining, actual_deficits)
            deficits = actual_deficits

        return rank

    def unrank(self, index: int) -> str:
        """Return the password at an exact zero-based rank."""

        if type(index) is not int:
            raise TypeError("rank must be an integer")
        if not 0 <= index < self._total:
            raise RankOutOfRangeError("rank is outside the policy state space")

        deficits = self._policy.minima
        password: list[str] = []
        for remaining in range(self._policy.length - 1, -1, -1):
            for class_index, character_class in enumerate(self._policy.classes):
                next_deficits = _consume(deficits, class_index)
                suffix_count = self._count(remaining, next_deficits)
                block_size = len(character_class.symbols) * suffix_count
                if index >= block_size:
                    index -= block_size
                    continue

                symbol_offset, index = divmod(index, suffix_count)
                password.append(character_class.symbols[symbol_offset])
                deficits = next_deficits
                break
            else:  # pragma: no cover - protected by the rank and DP invariants
                raise RuntimeError("rank could not be resolved")

        return "".join(password)

    def sample_uniform(self) -> str:
        """Sample every valid password with probability ``1 / total``."""

        return self.unrank(secrets.randbelow(self._total))
