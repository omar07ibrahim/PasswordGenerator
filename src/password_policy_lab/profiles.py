"""Named, versioned policy profiles shared by every interface."""

from __future__ import annotations

import string

from password_policy_lab.policy import CharacterClass, PasswordPolicy

VISIBLE_ASCII_PROFILE = "visible-ascii-v1"
VISIBLE_ASCII_CLASS_NAMES = ("lower", "upper", "digits", "punctuation")
VISIBLE_ASCII_CLASS_SYMBOLS = (
    string.ascii_lowercase,
    string.ascii_uppercase,
    string.digits,
    string.punctuation,
)
DEFAULT_VISIBLE_ASCII_MINIMA = (1, 1, 1, 1)

VisibleAsciiMinima = tuple[int, int, int, int]


def visible_ascii_policy(
    length: int,
    minima: VisibleAsciiMinima = DEFAULT_VISIBLE_ASCII_MINIMA,
) -> PasswordPolicy:
    """Build the normative four-class visible-ASCII policy."""

    if type(minima) is not tuple or len(minima) != len(VISIBLE_ASCII_CLASS_NAMES):
        raise TypeError("visible-ASCII minima must be a four-item tuple")

    classes = tuple(
        CharacterClass(name, symbols, minimum)
        for name, symbols, minimum in zip(
            VISIBLE_ASCII_CLASS_NAMES,
            VISIBLE_ASCII_CLASS_SYMBOLS,
            minima,
            strict=True,
        )
    )
    return PasswordPolicy(length=length, classes=classes)
