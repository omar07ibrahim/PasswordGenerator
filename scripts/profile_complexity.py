#!/usr/bin/env python3
"""Profile deterministic dynamic-programming work without timing claims.

The profiler deliberately retains only selected project-function call counts.
Wall-clock and CPU timings collected internally by :mod:`cProfile` are dropped
before a report is built.  The report never samples or emits a password.
"""

from __future__ import annotations

import argparse
import cProfile
import csv
import io
import json
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from math import comb, prod
from typing import Any, Literal, cast

import password_policy_lab.space as space_module
from password_policy_lab.errors import PolicyComplexityError
from password_policy_lab.policy import CharacterClass, PasswordPolicy
from password_policy_lab.profiles import VISIBLE_ASCII_CLASS_SYMBOLS
from password_policy_lab.space import (
    MAX_DP_CELLS,
    MAX_DP_TRANSITIONS,
    PasswordSpace,
)

PROFILE_SCHEMA_VERSION = 1
SCENARIO_SET = "deterministic-dp-work-v1"

_ALL_VISIBLE_ASCII = "".join(VISIBLE_ASCII_CLASS_SYMBOLS)


@dataclass(frozen=True, slots=True)
class ComplexityScenario:
    """One fixed, public, candidate-free profiling policy."""

    identifier: str
    length: int
    classes: tuple[tuple[str, str, int], ...]


@dataclass(slots=True)
class _ProductCounter:
    calls: int = 0
    vectors: int = 0


SCENARIOS = (
    ComplexityScenario(
        identifier="default-visible-ascii-20",
        length=20,
        classes=tuple(
            (name, symbols, 1)
            for name, symbols in zip(
                ("lower", "upper", "digits", "punctuation"),
                VISIBLE_ASCII_CLASS_SYMBOLS,
                strict=True,
            )
        ),
    ),
    ComplexityScenario(
        identifier="balanced-visible-ascii-24",
        length=24,
        classes=tuple(
            (name, symbols, 6)
            for name, symbols in zip(
                ("lower", "upper", "digits", "punctuation"),
                VISIBLE_ASCII_CLASS_SYMBOLS,
                strict=True,
            )
        ),
    ),
    ComplexityScenario(
        identifier="skewed-visible-ascii-24",
        length=24,
        classes=tuple(
            (name, symbols, minimum)
            for name, symbols, minimum in zip(
                ("lower", "upper", "digits", "punctuation"),
                VISIBLE_ASCII_CLASS_SYMBOLS,
                (21, 1, 1, 1),
                strict=True,
            )
        ),
    ),
    ComplexityScenario(
        identifier="near-budget-eight-class-32",
        length=32,
        classes=tuple(
            (f"class-{index}", symbol, 2)
            for index, symbol in enumerate(_ALL_VISIBLE_ASCII[:8])
        ),
    ),
    ComplexityScenario(
        identifier="arbitrary-precision-one-class-256",
        length=256,
        classes=(("visible-ascii", _ALL_VISIBLE_ASCII, 256),),
    ),
    ComplexityScenario(
        identifier="rejected-eight-class-32",
        length=32,
        classes=tuple(
            (f"class-{index}", symbol, 3)
            for index, symbol in enumerate(_ALL_VISIBLE_ASCII[:8])
        ),
    ),
)

_CSV_COLUMNS = (
    "case_id",
    "outcome",
    "length",
    "class_count",
    "class_minima",
    "state_vectors_upper_bound_per_layer",
    "dp_cells_upper_bound",
    "observed_occupied_cells",
    "dp_transitions_upper_bound",
    "observed_transitions",
    "peak_count_bits",
)


def _policy(scenario: ComplexityScenario) -> PasswordPolicy:
    return PasswordPolicy(
        length=scenario.length,
        classes=tuple(
            CharacterClass(name, symbols, minimum)
            for name, symbols, minimum in scenario.classes
        ),
    )


def _bounds(policy: PasswordPolicy) -> dict[str, int]:
    vectors = prod(minimum + 1 for minimum in policy.minima)
    cells = (policy.length + 1) * vectors
    return {
        "state_vectors_upper_bound_per_layer": vectors,
        "dp_cells_upper_bound": cells,
        "dp_transitions_upper_bound": len(policy.classes) * cells,
        "dp_cells_budget": MAX_DP_CELLS,
        "dp_transitions_budget": MAX_DP_TRANSITIONS,
    }


def _layer_occupancy_oracle(length: int, minima: tuple[int, ...]) -> tuple[int, ...]:
    """Count bounded deficit vectors by an independent polynomial convolution."""

    coefficients = [1]
    for minimum in minima:
        updated = [0] * (len(coefficients) + minimum)
        for subtotal, coefficient in enumerate(coefficients):
            for deficit in range(minimum + 1):
                updated[subtotal + deficit] += coefficient
        coefficients = updated

    return tuple(
        sum(coefficients[: min(remaining, len(coefficients) - 1) + 1])
        for remaining in range(length + 1)
    )


def _state_space_oracle(
    length: int,
    class_widths: tuple[int, ...],
    minima: tuple[int, ...],
) -> int:
    """Count strings by interleaving class populations, not deficit-state DP."""

    ways = [0] * (length + 1)
    ways[0] = 1
    for width, minimum in zip(class_widths, minima, strict=True):
        updated = [0] * (length + 1)
        for used, existing in enumerate(ways):
            if existing == 0:
                continue
            for amount in range(minimum, length - used + 1):
                combined = used + amount
                updated[combined] += existing * comb(combined, amount) * width**amount
        ways = updated
    return ways[length]


def _profiled_calls(
    profiler: cProfile.Profile,
    function: Callable[..., object],
) -> dict[str, int]:
    code = function.__code__
    for raw_entry in cast(list[Any], profiler.getstats()):
        if raw_entry.code is code:
            total = int(raw_entry.callcount)
            recursive = int(raw_entry.reccallcount)
            return {
                "primitive_calls": total - recursive,
                "total_calls": total,
            }
    return {"primitive_calls": 0, "total_calls": 0}


@contextmanager
def _count_product_vectors(counter: _ProductCounter) -> Iterator[None]:
    """Wrap the production iterator while preserving its exact yielded values."""

    module = cast(Any, space_module)
    original = cast(Callable[..., Iterator[tuple[int, ...]]], module.product)

    def counted_product(*iterables: Iterable[int]) -> Iterator[tuple[int, ...]]:
        counter.calls += 1
        for vector in original(*iterables):
            counter.vectors += 1
            yield vector

    module.product = counted_product
    try:
        yield
    finally:
        module.product = original


def profile_scenario(scenario: ComplexityScenario) -> dict[str, object]:
    """Profile one construction and cross-check every retained work counter."""

    if type(scenario) is not ComplexityScenario:
        raise TypeError("scenario must be a ComplexityScenario")

    policy = _policy(scenario)
    bounds = _bounds(policy)
    expected_rejection = (
        bounds["dp_cells_upper_bound"] > MAX_DP_CELLS
        or bounds["dp_transitions_upper_bound"] > MAX_DP_TRANSITIONS
    )
    profiler = cProfile.Profile()
    product_counter = _ProductCounter()
    space: PasswordSpace | None = None
    rejected = False
    with _count_product_vectors(product_counter):
        profiler.enable()
        try:
            space = PasswordSpace(policy)
        except PolicyComplexityError:
            rejected = True
        finally:
            profiler.disable()

    build_calls = _profiled_calls(profiler, PasswordSpace._build_layers)
    consume_calls = _profiled_calls(profiler, space_module._consume)
    common: dict[str, object] = {
        "case_id": scenario.identifier,
        "policy": {
            "length": policy.length,
            "class_count": len(policy.classes),
            "class_widths": [len(item.symbols) for item in policy.classes],
            "class_minima": list(policy.minima),
        },
        "bounds": bounds,
        "profiled_calls": {
            "build_layers": build_calls,
            "consume": consume_calls,
        },
        "work_counters": {
            "product_calls": product_counter.calls,
            "product_vectors": product_counter.vectors,
            "consume_calls": consume_calls["total_calls"],
        },
    }

    if rejected:
        if not expected_rejection:
            raise RuntimeError("profiled policy was rejected below the declared budget")
        if build_calls != {
            "primitive_calls": 0,
            "total_calls": 0,
        } or consume_calls != {
            "primitive_calls": 0,
            "total_calls": 0,
        }:
            raise RuntimeError(
                "rejected policy entered dynamic-programming enumeration"
            )
        if product_counter != _ProductCounter():
            raise RuntimeError("rejected policy entered deficit-vector enumeration")
        return {
            **common,
            "outcome": "rejected-before-enumeration",
            "rejection": "dynamic-programming-complexity-budget",
        }

    if expected_rejection or space is None:
        raise RuntimeError("profiled policy did not enforce the declared budget")

    layers = cast(tuple[dict[tuple[int, ...], int], ...], cast(Any, space)._layers)
    layer_occupancy = tuple(len(layer) for layer in layers)
    oracle_occupancy = _layer_occupancy_oracle(policy.length, policy.minima)
    occupied_cells = sum(layer_occupancy)
    expected_product_calls = policy.length
    expected_product_vectors = (
        policy.length * bounds["state_vectors_upper_bound_per_layer"]
    )
    expected_transitions = len(policy.classes) * (occupied_cells - 1)
    widths = tuple(len(item.symbols) for item in policy.classes)
    oracle_total = _state_space_oracle(policy.length, widths, policy.minima)
    peak_count_bits = max(
        value.bit_length() for layer in layers for value in layer.values()
    )

    if layer_occupancy != oracle_occupancy:
        raise RuntimeError("profiled layer occupancy disagrees with the oracle")
    if product_counter.calls != expected_product_calls:
        raise RuntimeError("profiled product calls disagree with the loop contract")
    if product_counter.vectors != expected_product_vectors:
        raise RuntimeError("profiled product vectors disagree with the oracle")
    if consume_calls != {
        "primitive_calls": expected_transitions,
        "total_calls": expected_transitions,
    }:
        raise RuntimeError("profiled transition calls disagree with the oracle")
    if build_calls != {"primitive_calls": 1, "total_calls": 1}:
        raise RuntimeError(
            "profiled construction did not build exactly one layer stack"
        )
    if space.total != oracle_total:
        raise RuntimeError("profiled exact count disagrees with the class-count oracle")

    return {
        **common,
        "outcome": "accepted",
        "observed": {
            "layer_occupancy": list(layer_occupancy),
            "occupied_cells": occupied_cells,
            "transitions": expected_transitions,
            "peak_count_bits": peak_count_bits,
            "valid_state_space": str(space.total),
        },
        "independent_oracles": {
            "occupied_cells": sum(oracle_occupancy),
            "transitions": expected_transitions,
            "valid_state_space": str(oracle_total),
        },
    }


def build_profile() -> dict[str, object]:
    """Run the complete fixed scenario set and return a stable report."""

    return {
        "schema_version": PROFILE_SCHEMA_VERSION,
        "scenario_set": SCENARIO_SET,
        "counter_contract": "logical-dp-operations-v1",
        "profiler": {
            "engine": "cProfile",
            "selected_project_functions": [
                "PasswordSpace._build_layers",
                "_consume",
            ],
            "retained_fields": ["primitive_calls", "total_calls"],
            "timing_fields_retained": False,
        },
        "claim_boundaries": {
            "candidate_output_included": False,
            "entropy_consumed": False,
            "hardware_performance_claimed": False,
            "memory_usage_claimed": False,
            "wall_clock_timing_included": False,
        },
        "cases": [profile_scenario(scenario) for scenario in SCENARIOS],
    }


def profile_json(report: dict[str, object]) -> str:
    """Serialize a canonical human-readable JSON receipt."""

    return json.dumps(report, ensure_ascii=True, indent=2, sort_keys=True) + "\n"


def _accepted_observation(case: dict[str, object]) -> dict[str, object] | None:
    value = case.get("observed")
    if value is None:
        return None
    return cast(dict[str, object], value)


def profile_csv(report: dict[str, object]) -> str:
    """Serialize one deterministic summary row per scenario."""

    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=_CSV_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for raw_case in cast(list[dict[str, object]], report["cases"]):
        policy = cast(dict[str, object], raw_case["policy"])
        bounds = cast(dict[str, object], raw_case["bounds"])
        observed = _accepted_observation(raw_case)
        writer.writerow(
            {
                "case_id": raw_case["case_id"],
                "outcome": raw_case["outcome"],
                "length": policy["length"],
                "class_count": policy["class_count"],
                "class_minima": ";".join(
                    str(value) for value in cast(list[int], policy["class_minima"])
                ),
                "state_vectors_upper_bound_per_layer": bounds[
                    "state_vectors_upper_bound_per_layer"
                ],
                "dp_cells_upper_bound": bounds["dp_cells_upper_bound"],
                "observed_occupied_cells": (
                    observed["occupied_cells"] if observed is not None else 0
                ),
                "dp_transitions_upper_bound": bounds["dp_transitions_upper_bound"],
                "observed_transitions": (
                    observed["transitions"] if observed is not None else 0
                ),
                "peak_count_bits": (
                    observed["peak_count_bits"] if observed is not None else 0
                ),
            }
        )
    return output.getvalue()


def profile_text(report: dict[str, object]) -> str:
    """Render a concise transcript without candidate or timing data."""

    lines = [
        "Password Policy State-Space Lab — deterministic DP work profile",
        f"schema_version: {PROFILE_SCHEMA_VERSION}",
        f"scenario_set: {SCENARIO_SET}",
        "profiler: cProfile selected project call counts; timing discarded",
        "",
    ]
    for raw_case in cast(list[dict[str, object]], report["cases"]):
        bounds = cast(dict[str, object], raw_case["bounds"])
        observed = _accepted_observation(raw_case)
        if observed is None:
            lines.append(
                f"{raw_case['case_id']}: rejected before enumeration · "
                f"cells bound {bounds['dp_cells_upper_bound']} · "
                f"transitions bound {bounds['dp_transitions_upper_bound']} · "
                "build calls 0 · consume calls 0"
            )
        else:
            lines.append(
                f"{raw_case['case_id']}: accepted · "
                f"cells {observed['occupied_cells']}/"
                f"{bounds['dp_cells_upper_bound']} · "
                f"transitions {observed['transitions']}/"
                f"{bounds['dp_transitions_upper_bound']} · "
                f"peak integer {observed['peak_count_bits']} bits"
            )
    lines.extend(
        (
            "",
            (
                "Scope: deterministic work counts only; no elapsed-time, RSS, "
                "hardware, or speed claim."
            ),
            (
                "Safety: no entropy consumed and no password candidate "
                "constructed or emitted."
            ),
            "",
        )
    )
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """Run the fixed profile and write exactly one selected representation."""

    parser = argparse.ArgumentParser(
        description="Profile deterministic PasswordSpace construction work.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--format",
        choices=("json", "csv", "text"),
        default="json",
    )
    arguments = parser.parse_args(argv)
    report = build_profile()
    output_format = cast(Literal["json", "csv", "text"], arguments.format)
    rendered = {
        "json": profile_json,
        "csv": profile_csv,
        "text": profile_text,
    }[output_format](report)
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
