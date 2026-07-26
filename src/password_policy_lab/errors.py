"""Public, data-safe errors raised by the policy state-space core."""


class PasswordPolicyError(ValueError):
    """Base class for rejected policies, ranks, and candidate passwords."""


class PolicyValidationError(PasswordPolicyError):
    """A policy is malformed or has no valid password."""


class PolicyComplexityError(PolicyValidationError):
    """A valid policy exceeds the bounded dynamic-programming budget."""


class PasswordValidationError(PasswordPolicyError):
    """A candidate is outside the policy state space."""


class RankOutOfRangeError(PasswordPolicyError):
    """A rank is not an index in the policy state space."""
