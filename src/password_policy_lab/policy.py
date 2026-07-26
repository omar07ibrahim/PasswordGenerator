"""Immutable policy definitions with a deliberately narrow character model."""

from __future__ import annotations

import re
from dataclasses import dataclass

from password_policy_lab.errors import PolicyValidationError

MAX_CLASSES = 8
MAX_LENGTH = 256

_CLASS_NAME = re.compile(r"[a-z][a-z0-9_-]{0,31}\Z")
_FIRST_VISIBLE_ASCII = ord("!")
_LAST_VISIBLE_ASCII = ord("~")
_VISIBLE_ASCII_SIZE = _LAST_VISIBLE_ASCII - _FIRST_VISIBLE_ASCII + 1


@dataclass(frozen=True, slots=True)
class CharacterClass:
    """One ordered, disjoint set of visible ASCII symbols."""

    name: str
    symbols: str
    minimum: int = 0

    def __post_init__(self) -> None:
        if type(self.name) is not str:
            raise TypeError("class name must be a string")
        if _CLASS_NAME.fullmatch(self.name) is None:
            raise PolicyValidationError("class name has an invalid format")
        if type(self.symbols) is not str:
            raise TypeError("class symbols must be a string")
        if not self.symbols:
            raise PolicyValidationError("class symbols must not be empty")
        if len(self.symbols) > _VISIBLE_ASCII_SIZE:
            raise PolicyValidationError(
                "class symbols must contain at most 94 characters"
            )
        if any(
            not _FIRST_VISIBLE_ASCII <= ord(symbol) <= _LAST_VISIBLE_ASCII
            for symbol in self.symbols
        ):
            raise PolicyValidationError("class symbols must be visible ASCII")
        if len(set(self.symbols)) != len(self.symbols):
            raise PolicyValidationError("class symbols must be unique")
        if type(self.minimum) is not int:
            raise TypeError("class minimum must be an integer")
        if self.minimum < 0:
            raise PolicyValidationError("class minimum must not be negative")


@dataclass(frozen=True, slots=True)
class PasswordPolicy:
    """A fixed length and ordered character classes with minimum counts."""

    length: int
    classes: tuple[CharacterClass, ...]

    def __post_init__(self) -> None:
        if type(self.length) is not int:
            raise TypeError("policy length must be an integer")
        if not 1 <= self.length <= MAX_LENGTH:
            raise PolicyValidationError(
                f"policy length must be between 1 and {MAX_LENGTH}"
            )
        if type(self.classes) is not tuple:
            raise TypeError("policy classes must be a tuple")
        if not 1 <= len(self.classes) <= MAX_CLASSES:
            raise PolicyValidationError(
                f"policy must contain between 1 and {MAX_CLASSES} classes"
            )
        if any(
            type(character_class) is not CharacterClass
            for character_class in self.classes
        ):
            raise TypeError("policy classes must contain CharacterClass values")

        names: set[str] = set()
        symbols: set[str] = set()
        minimum_total = 0
        for character_class in self.classes:
            if character_class.name in names:
                raise PolicyValidationError("class names must be unique")
            names.add(character_class.name)

            overlap = symbols.intersection(character_class.symbols)
            if overlap:
                raise PolicyValidationError("character classes must be disjoint")
            symbols.update(character_class.symbols)

            if character_class.minimum > self.length:
                raise PolicyValidationError(
                    "class minimum must not exceed policy length"
                )
            minimum_total += character_class.minimum

        if minimum_total > self.length:
            raise PolicyValidationError(
                "sum of class minima must not exceed policy length"
            )

    @property
    def alphabet(self) -> str:
        """Return the normative class-then-symbol ordering."""

        return "".join(character_class.symbols for character_class in self.classes)

    @property
    def minima(self) -> tuple[int, ...]:
        """Return class deficits at the start of generation."""

        return tuple(character_class.minimum for character_class in self.classes)
