"""Allow ``python -m password_policy_lab`` to invoke the audit CLI."""

from password_policy_lab.cli import main  # pragma: no cover - interpreter wiring

if __name__ == "__main__":  # pragma: no cover - interpreter entry point
    raise SystemExit(main())
