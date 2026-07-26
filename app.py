"""Compatibility WSGI entry point for the local web interface."""

from password_policy_lab import create_app

app = create_app()
