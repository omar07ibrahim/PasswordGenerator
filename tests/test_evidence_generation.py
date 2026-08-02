from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from typing import Protocol, cast

import pytest


class _Generator(Protocol):
    def _normalize_quality_output(self, output: str) -> str: ...


def _load_generator() -> _Generator:
    scripts = Path(__file__).resolve().parents[1] / "scripts"
    path = scripts / "generate_evidence.py"
    spec = importlib.util.spec_from_file_location(
        "password_policy_evidence_generator",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the evidence generator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    sys.path.insert(0, str(scripts))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return cast(_Generator, module)


generator = _load_generator()


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("294 passed in 130.25s\n", "294 passed\n"),
        ("293 passed, 1 skipped in 131.04s\n", "293 passed, 1 skipped\n"),
        ("294 passed (0:02:10)\n", "294 passed\n"),
        ("297 passed in 129.08s (0:02:09)\n", "297 passed\n"),
    ],
)
def test_quality_normalization_removes_both_pytest_duration_formats(
    raw: str,
    expected: str,
) -> None:
    assert generator._normalize_quality_output(raw) == expected
