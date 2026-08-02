from __future__ import annotations

import importlib.util
import json
import secrets
import sys
from itertools import product
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest

import password_policy_lab.space as space_module
from password_policy_lab import CharacterClass, PasswordPolicy, PasswordSpace


def _load_profiler() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/profile_complexity.py"
    spec = importlib.util.spec_from_file_location("complexity_profile_for_tests", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the complexity profiler")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


profiler = cast(Any, _load_profiler())


def _cases(report: dict[str, object]) -> dict[str, dict[str, object]]:
    return {
        cast(str, item["case_id"]): item
        for item in cast(list[dict[str, object]], report["cases"])
    }


def test_profile_records_exact_sparse_work_and_fail_fast_boundary() -> None:
    report = cast(dict[str, object], profiler.build_profile())
    cases = _cases(report)

    assert list(cases) == [scenario.identifier for scenario in profiler.SCENARIOS]
    expected = {
        "default-visible-ascii-20": (304, 336, 1_212),
        "balanced-visible-ascii-24": (31_213, 60_025, 124_848),
        "skewed-visible-ascii-24": (2_288, 4_400, 9_148),
        "near-budget-eight-class-32": (164_025, 216_513, 1_312_192),
        "arbitrary-precision-one-class-256": (33_153, 66_049, 33_152),
    }
    for identifier, (cells, upper_bound, transitions) in expected.items():
        case = cases[identifier]
        observed = cast(dict[str, object], case["observed"])
        bounds = cast(dict[str, object], case["bounds"])
        calls = cast(dict[str, dict[str, int]], case["profiled_calls"])
        work = cast(dict[str, int], case["work_counters"])
        oracles = cast(dict[str, object], case["independent_oracles"])
        assert case["outcome"] == "accepted"
        assert observed["occupied_cells"] == cells
        assert bounds["dp_cells_upper_bound"] == upper_bound
        assert observed["transitions"] == transitions
        assert calls["build_layers"] == {
            "primitive_calls": 1,
            "total_calls": 1,
        }
        assert calls["consume"] == {
            "primitive_calls": transitions,
            "total_calls": transitions,
        }
        assert work == {
            "product_calls": cast(
                int, cast(dict[str, object], case["policy"])["length"]
            ),
            "product_vectors": cast(
                int, cast(dict[str, object], case["policy"])["length"]
            )
            * cast(int, bounds["state_vectors_upper_bound_per_layer"]),
            "consume_calls": transitions,
        }
        assert oracles["occupied_cells"] == cells
        assert oracles["transitions"] == transitions
        assert oracles["valid_state_space"] == observed["valid_state_space"]

    arbitrary = cast(
        dict[str, object], cases["arbitrary-precision-one-class-256"]["observed"]
    )
    assert arbitrary["peak_count_bits"] == (94**256).bit_length()

    rejected = cases["rejected-eight-class-32"]
    rejected_bounds = cast(dict[str, object], rejected["bounds"])
    assert rejected["outcome"] == "rejected-before-enumeration"
    assert rejected["rejection"] == "dynamic-programming-complexity-budget"
    assert rejected_bounds["dp_cells_upper_bound"] == 2_162_688
    assert rejected_bounds["dp_transitions_upper_bound"] == 17_301_504
    assert rejected["profiled_calls"] == {
        "build_layers": {"primitive_calls": 0, "total_calls": 0},
        "consume": {"primitive_calls": 0, "total_calls": 0},
    }
    assert rejected["work_counters"] == {
        "product_calls": 0,
        "product_vectors": 0,
        "consume_calls": 0,
    }


def test_independent_oracles_match_a_small_exhaustive_space() -> None:
    policy = PasswordPolicy(
        4,
        (
            CharacterClass("letters", "ab", 2),
            CharacterClass("digits", "01", 1),
        ),
    )
    exhaustive = sum(
        all(
            sum(symbol in character_class.symbols for symbol in candidate)
            >= character_class.minimum
            for character_class in policy.classes
        )
        for candidate in product(policy.alphabet, repeat=policy.length)
    )
    oracle = profiler._state_space_oracle(
        policy.length,
        tuple(len(item.symbols) for item in policy.classes),
        policy.minima,
    )
    occupancy = profiler._layer_occupancy_oracle(policy.length, policy.minima)
    space = PasswordSpace(policy)

    assert oracle == exhaustive == space.total
    assert occupancy == tuple(len(layer) for layer in space._layers)


def test_rejected_profile_never_enters_product_or_consume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rejected = profiler.SCENARIOS[-1]

    def fail(*values: object) -> None:
        raise AssertionError(f"enumeration must not start: {len(values)}")

    monkeypatch.setattr(space_module, "product", fail)
    monkeypatch.setattr(space_module, "_consume", fail)

    case = profiler.profile_scenario(rejected)

    assert case["outcome"] == "rejected-before-enumeration"


def test_profile_never_uses_candidate_or_entropy_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_entropy(upper_bound: int) -> int:
        raise AssertionError(f"entropy must not be consumed: {upper_bound}")

    def fail_candidate(*values: object, **named: object) -> None:
        raise AssertionError(
            f"candidate path must not run: {len(values)} positional, {len(named)} named"
        )

    monkeypatch.setattr(secrets, "randbelow", fail_entropy)
    for method in ("rank", "unrank", "sample_uniform"):
        monkeypatch.setattr(PasswordSpace, method, fail_candidate)

    report = profiler.build_profile()

    assert (
        cast(dict[str, object], report["claim_boundaries"])["entropy_consumed"] is False
    )


def test_serializations_are_canonical_stable_and_candidate_free() -> None:
    report = profiler.build_profile()
    first_json = profiler.profile_json(report)
    second_json = profiler.profile_json(profiler.build_profile())
    csv_text = profiler.profile_csv(report)
    text = profiler.profile_text(report)

    assert first_json == second_json
    assert first_json == (
        json.dumps(json.loads(first_json), ensure_ascii=True, indent=2, sort_keys=True)
        + "\n"
    )
    assert csv_text.splitlines()[0] == ",".join(profiler._CSV_COLUMNS)
    assert len(csv_text.splitlines()) == len(profiler.SCENARIOS) + 1
    assert "timing discarded" in text
    assert "no elapsed-time, RSS, hardware, or speed claim" in text
    assert "no password candidate constructed or emitted" in text
    assert "\N{EM DASH}" not in text
    combined = first_json + csv_text + text
    assert "/home/" not in combined
    assert "generated_password" not in combined
    assert 'wall_clock_timing_included": true' not in combined


@pytest.mark.parametrize("output_format", ("json", "csv", "text"))
def test_cli_emits_exact_selected_representation(
    output_format: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert profiler.main(["--format", output_format]) == 0
    captured = capsys.readouterr()
    assert captured.err == ""
    assert captured.out
    assert captured.out.endswith("\n")
