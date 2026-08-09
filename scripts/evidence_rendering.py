# ruff: noqa: E501
"""Deterministic renderers used by the portfolio evidence generator.

SVG source is intentionally kept as readable one-element-per-line markup.
"""

from __future__ import annotations

import importlib
import textwrap
from collections.abc import Sequence
from dataclasses import dataclass
from io import BytesIO
from itertools import pairwise
from math import gcd, prod
from pathlib import Path
from typing import Any, Literal, cast

Image: Any = importlib.import_module("PIL.Image")
ImageDraw: Any = importlib.import_module("PIL.ImageDraw")
ImageFont: Any = importlib.import_module("PIL.ImageFont")

BACKGROUND = "#0a1014"
SURFACE = "#111c21"
SURFACE_RAISED = "#17262d"
LINE = "#36505a"
TEXT = "#edf5f1"
MUTED = "#9fb4ad"
TEAL = "#63e6d2"
GOLD = "#f4c95d"


@dataclass(frozen=True)
class FrameFidelity:
    """Localized decoded-GIF error metrics against one lossless browser frame."""

    bad_pixel_ratio: float
    mae: float
    maximum_channel_error: int
    maximum_tile_bad_pixel_ratio: float
    maximum_tile_mae: float
    p999_pixel_error: int


@dataclass(frozen=True)
class GifFidelity:
    """Fidelity result for every ordered frame in the validation animation."""

    frames: tuple[FrameFidelity, ...]

    @property
    def frame_count(self) -> int:
        return len(self.frames)


@dataclass(frozen=True, slots=True)
class _SensitivityRow:
    class_name: str
    original_minimum: int
    relaxed_minimum: int
    relaxed_valid: int
    added_if_relaxed: int
    fraction_numerator: int
    fraction_denominator: int


@dataclass(frozen=True, slots=True)
class _DpCaseSpec:
    identifier: str
    title: str
    length: int
    class_widths: tuple[int, ...]
    class_minima: tuple[int, ...]
    outcome: Literal["accepted", "rejected-before-enumeration"]


@dataclass(frozen=True, slots=True)
class _DpProfileCase:
    spec: _DpCaseSpec
    cells_upper_bound: int
    transitions_upper_bound: int
    product_calls: int
    product_vectors: int
    consume_calls: int
    layer_occupancy: tuple[int, ...] | None
    occupied_cells: int
    transitions: int
    peak_count_bits: int | None


_DP_CASE_SPECS = (
    _DpCaseSpec(
        "default-visible-ascii-20",
        "Default visible ASCII",
        20,
        (26, 26, 10, 32),
        (1, 1, 1, 1),
        "accepted",
    ),
    _DpCaseSpec(
        "balanced-visible-ascii-24",
        "Balanced strict minima",
        24,
        (26, 26, 10, 32),
        (6, 6, 6, 6),
        "accepted",
    ),
    _DpCaseSpec(
        "skewed-visible-ascii-24",
        "Skewed strict minima",
        24,
        (26, 26, 10, 32),
        (21, 1, 1, 1),
        "accepted",
    ),
    _DpCaseSpec(
        "near-budget-eight-class-32",
        "Eight-class budget edge",
        32,
        (1, 1, 1, 1, 1, 1, 1, 1),
        (2, 2, 2, 2, 2, 2, 2, 2),
        "accepted",
    ),
    _DpCaseSpec(
        "arbitrary-precision-one-class-256",
        "Arbitrary-precision depth",
        256,
        (94,),
        (256,),
        "accepted",
    ),
    _DpCaseSpec(
        "rejected-eight-class-32",
        "Fail-fast budget guard",
        32,
        (1, 1, 1, 1, 1, 1, 1, 1),
        (3, 3, 3, 3, 3, 3, 3, 3),
        "rejected-before-enumeration",
    ),
)


def _profile_mapping(
    value: object,
    *,
    keys: set[str],
    label: str,
) -> dict[str, object]:
    if type(value) is not dict:
        raise ValueError(f"invalid complexity profile {label}")
    mapping = cast(dict[str, object], value)
    if set(mapping) != keys:
        raise ValueError(f"invalid complexity profile {label}")
    return mapping


def _profile_list(value: object, *, label: str) -> list[object]:
    if type(value) is not list:
        raise ValueError(f"invalid complexity profile {label}")
    return cast(list[object], value)


def _profile_integer(
    value: object,
    *,
    label: str,
    minimum: int = 0,
) -> int:
    if type(value) is not int or value < minimum:
        raise ValueError(f"invalid complexity profile {label}")
    return value


def _profile_integer_tuple(
    value: object,
    *,
    label: str,
    minimum: int,
) -> tuple[int, ...]:
    values = _profile_list(value, label=label)
    return tuple(
        _profile_integer(item, label=label, minimum=minimum) for item in values
    )


def _profile_calls(value: object, *, label: str) -> tuple[int, int]:
    calls = _profile_mapping(
        value,
        keys={"primitive_calls", "total_calls"},
        label=label,
    )
    primitive = _profile_integer(
        calls["primitive_calls"],
        label=f"{label}.primitive_calls",
    )
    total = _profile_integer(calls["total_calls"], label=f"{label}.total_calls")
    if primitive > total:
        raise ValueError(f"invalid complexity profile {label}")
    return primitive, total


def _profile_decimal(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 4096
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
        or value == "0"
    ):
        raise ValueError(f"invalid complexity profile {label}")
    return value


def _validated_dp_profile(report: object) -> tuple[_DpProfileCase, ...]:
    document = _profile_mapping(
        report,
        keys={
            "cases",
            "claim_boundaries",
            "counter_contract",
            "profiler",
            "scenario_set",
            "schema_version",
        },
        label="document",
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["scenario_set"] != "deterministic-dp-work-v1"
        or document["counter_contract"] != "logical-dp-operations-v1"
    ):
        raise ValueError("invalid complexity profile identity")

    profiler = _profile_mapping(
        document["profiler"],
        keys={
            "engine",
            "retained_fields",
            "selected_project_functions",
            "timing_fields_retained",
        },
        label="profiler",
    )
    if (
        profiler["engine"] != "cProfile"
        or profiler["selected_project_functions"]
        != ["PasswordSpace._build_layers", "_consume"]
        or profiler["retained_fields"] != ["primitive_calls", "total_calls"]
        or profiler["timing_fields_retained"] is not False
    ):
        raise ValueError("invalid complexity profile profiler contract")

    boundaries = _profile_mapping(
        document["claim_boundaries"],
        keys={
            "candidate_output_included",
            "entropy_consumed",
            "hardware_performance_claimed",
            "memory_usage_claimed",
            "wall_clock_timing_included",
        },
        label="claim_boundaries",
    )
    if any(value is not False for value in boundaries.values()):
        raise ValueError("invalid complexity profile claim boundaries")

    raw_cases = _profile_list(document["cases"], label="cases")
    if len(raw_cases) != len(_DP_CASE_SPECS):
        raise ValueError("invalid complexity profile cases")

    validated: list[_DpProfileCase] = []
    for index, (raw_case, spec) in enumerate(
        zip(raw_cases, _DP_CASE_SPECS, strict=True)
    ):
        common_keys = {
            "bounds",
            "case_id",
            "outcome",
            "policy",
            "profiled_calls",
            "work_counters",
        }
        case_keys = (
            common_keys | {"independent_oracles", "observed"}
            if spec.outcome == "accepted"
            else common_keys | {"rejection"}
        )
        case = _profile_mapping(
            raw_case,
            keys=case_keys,
            label=f"cases[{index}]",
        )
        if case["case_id"] != spec.identifier or case["outcome"] != spec.outcome:
            raise ValueError("invalid complexity profile case identity")

        policy = _profile_mapping(
            case["policy"],
            keys={"class_count", "class_minima", "class_widths", "length"},
            label=f"cases[{index}].policy",
        )
        length = _profile_integer(
            policy["length"],
            label=f"cases[{index}].policy.length",
            minimum=1,
        )
        class_count = _profile_integer(
            policy["class_count"],
            label=f"cases[{index}].policy.class_count",
            minimum=1,
        )
        class_widths = _profile_integer_tuple(
            policy["class_widths"],
            label=f"cases[{index}].policy.class_widths",
            minimum=1,
        )
        class_minima = _profile_integer_tuple(
            policy["class_minima"],
            label=f"cases[{index}].policy.class_minima",
            minimum=0,
        )
        if (
            length != spec.length
            or class_count != len(spec.class_widths)
            or class_widths != spec.class_widths
            or class_minima != spec.class_minima
            or len(class_minima) != class_count
        ):
            raise ValueError("invalid complexity profile policy")

        vectors_upper_bound = prod(minimum + 1 for minimum in class_minima)
        cells_upper_bound = (length + 1) * vectors_upper_bound
        transitions_upper_bound = class_count * cells_upper_bound
        bounds = _profile_mapping(
            case["bounds"],
            keys={
                "dp_cells_budget",
                "dp_cells_upper_bound",
                "dp_transitions_budget",
                "dp_transitions_upper_bound",
                "state_vectors_upper_bound_per_layer",
            },
            label=f"cases[{index}].bounds",
        )
        expected_bounds = {
            "dp_cells_budget": 250_000,
            "dp_cells_upper_bound": cells_upper_bound,
            "dp_transitions_budget": 2_000_000,
            "dp_transitions_upper_bound": transitions_upper_bound,
            "state_vectors_upper_bound_per_layer": vectors_upper_bound,
        }
        if any(bounds[key] != value for key, value in expected_bounds.items()):
            raise ValueError("invalid complexity profile bounds")

        profiled_calls = _profile_mapping(
            case["profiled_calls"],
            keys={"build_layers", "consume"},
            label=f"cases[{index}].profiled_calls",
        )
        build_primitive, build_total = _profile_calls(
            profiled_calls["build_layers"],
            label=f"cases[{index}].profiled_calls.build_layers",
        )
        consume_primitive, consume_total = _profile_calls(
            profiled_calls["consume"],
            label=f"cases[{index}].profiled_calls.consume",
        )
        work = _profile_mapping(
            case["work_counters"],
            keys={"consume_calls", "product_calls", "product_vectors"},
            label=f"cases[{index}].work_counters",
        )
        product_calls = _profile_integer(
            work["product_calls"],
            label=f"cases[{index}].work_counters.product_calls",
        )
        product_vectors = _profile_integer(
            work["product_vectors"],
            label=f"cases[{index}].work_counters.product_vectors",
        )
        work_consume_calls = _profile_integer(
            work["consume_calls"],
            label=f"cases[{index}].work_counters.consume_calls",
        )

        if spec.outcome == "rejected-before-enumeration":
            if (
                case["rejection"] != "dynamic-programming-complexity-budget"
                or cells_upper_bound <= 250_000
                or transitions_upper_bound <= 2_000_000
                or any(
                    value != 0
                    for value in (
                        build_primitive,
                        build_total,
                        consume_primitive,
                        consume_total,
                        product_calls,
                        product_vectors,
                        work_consume_calls,
                    )
                )
            ):
                raise ValueError("invalid complexity profile rejection")
            validated.append(
                _DpProfileCase(
                    spec=spec,
                    cells_upper_bound=cells_upper_bound,
                    transitions_upper_bound=transitions_upper_bound,
                    product_calls=0,
                    product_vectors=0,
                    consume_calls=0,
                    layer_occupancy=None,
                    occupied_cells=0,
                    transitions=0,
                    peak_count_bits=None,
                )
            )
            continue

        observed = _profile_mapping(
            case["observed"],
            keys={
                "layer_occupancy",
                "occupied_cells",
                "peak_count_bits",
                "transitions",
                "valid_state_space",
            },
            label=f"cases[{index}].observed",
        )
        layer_occupancy = _profile_integer_tuple(
            observed["layer_occupancy"],
            label=f"cases[{index}].observed.layer_occupancy",
            minimum=1,
        )
        occupied_cells = _profile_integer(
            observed["occupied_cells"],
            label=f"cases[{index}].observed.occupied_cells",
            minimum=1,
        )
        transitions = _profile_integer(
            observed["transitions"],
            label=f"cases[{index}].observed.transitions",
            minimum=1,
        )
        peak_count_bits = _profile_integer(
            observed["peak_count_bits"],
            label=f"cases[{index}].observed.peak_count_bits",
            minimum=1,
        )
        valid_state_space = _profile_decimal(
            observed["valid_state_space"],
            label=f"cases[{index}].observed.valid_state_space",
        )
        independent = _profile_mapping(
            case["independent_oracles"],
            keys={"occupied_cells", "transitions", "valid_state_space"},
            label=f"cases[{index}].independent_oracles",
        )
        if (
            len(layer_occupancy) != length + 1
            or layer_occupancy[0] != 1
            or layer_occupancy[-1] != vectors_upper_bound
            or any(
                current < previous for previous, current in pairwise(layer_occupancy)
            )
            or any(value > vectors_upper_bound for value in layer_occupancy)
            or sum(layer_occupancy) != occupied_cells
            or transitions != class_count * (occupied_cells - 1)
            or peak_count_bits != (sum(class_widths) ** length).bit_length()
            or build_primitive != 1
            or build_total != 1
            or consume_primitive != transitions
            or consume_total != transitions
            or product_calls != length
            or product_vectors != length * vectors_upper_bound
            or work_consume_calls != transitions
            or independent["occupied_cells"] != occupied_cells
            or independent["transitions"] != transitions
            or independent["valid_state_space"] != valid_state_space
        ):
            raise ValueError("invalid complexity profile accepted case")
        validated.append(
            _DpProfileCase(
                spec=spec,
                cells_upper_bound=cells_upper_bound,
                transitions_upper_bound=transitions_upper_bound,
                product_calls=product_calls,
                product_vectors=product_vectors,
                consume_calls=work_consume_calls,
                layer_occupancy=layer_occupancy,
                occupied_cells=occupied_cells,
                transitions=transitions,
                peak_count_bits=peak_count_bits,
            )
        )

    return tuple(validated)


def _svg_document(
    *,
    title: str,
    description: str,
    width: int,
    height: int,
    body: str,
) -> str:
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-labelledby="title description">
  <title id="title">{title}</title>
  <desc id="description">{description}</desc>
  <defs>
    <marker id="arrow-teal" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="{TEAL}"/>
    </marker>
    <marker id="arrow-gold" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
      <path d="M 0 0 L 10 5 L 0 10 z" fill="{GOLD}"/>
    </marker>
    <filter id="shadow" x="-20%" y="-20%" width="140%" height="140%">
      <feDropShadow dx="0" dy="8" stdDeviation="12" flood-color="#000000" flood-opacity=".28"/>
    </filter>
    <style>
      .title {{ fill: {TEXT}; font: 700 42px system-ui, sans-serif; letter-spacing: -1px; }}
      .subtitle {{ fill: {MUTED}; font: 400 20px system-ui, sans-serif; }}
      .lane {{ fill: {TEAL}; font: 700 15px ui-monospace, monospace; letter-spacing: 2px; }}
      .node-title {{ fill: {TEXT}; font: 700 22px system-ui, sans-serif; }}
      .node-detail {{ fill: {MUTED}; font: 400 16px system-ui, sans-serif; }}
      .node-code {{ fill: {GOLD}; font: 600 15px ui-monospace, monospace; }}
      .step {{ fill: {BACKGROUND}; font: 800 15px ui-monospace, monospace; }}
      .caption {{ fill: {MUTED}; font: 400 16px system-ui, sans-serif; }}
    </style>
  </defs>
  <rect width="{width}" height="{height}" rx="28" fill="{BACKGROUND}"/>
  <path d="M0 0 H{width} V{height} H0 Z" fill="none" stroke="{LINE}" stroke-width="2"/>
{body}
</svg>
"""


def _svg_node(
    *,
    x: int,
    y: int,
    width: int,
    height: int,
    index: str,
    title: str,
    details: Sequence[str],
    accent: str = TEAL,
) -> str:
    detail_lines = "\n".join(
        f'      <tspan x="{x + 26}" dy="{24 if offset else 0}">{line}</tspan>'
        for offset, line in enumerate(details)
    )
    return f"""  <g filter="url(#shadow)">
    <rect x="{x}" y="{y}" width="{width}" height="{height}" rx="18" fill="{SURFACE}" stroke="{LINE}" stroke-width="2"/>
    <rect x="{x}" y="{y}" width="8" height="{height}" rx="4" fill="{accent}"/>
    <circle cx="{x + 34}" cy="{y + 34}" r="17" fill="{accent}"/>
    <text x="{x + 34}" y="{y + 39}" text-anchor="middle" class="step">{index}</text>
    <text x="{x + 62}" y="{y + 41}" class="node-title">{title}</text>
    <text x="{x + 26}" y="{y + 76}" class="node-detail">
{detail_lines}
    </text>
  </g>"""


def write_architecture_svg(path: Path) -> None:
    """Render the AST-verified web, CLI, and shared-core architecture."""

    nodes = (
        _svg_node(
            x=55,
            y=210,
            width=230,
            height=132,
            index="1",
            title="Browser",
            details=("server-rendered HTML", "same-origin CSS only"),
        ),
        _svg_node(
            x=330,
            y=210,
            width=230,
            height=132,
            index="2",
            title="Waitress",
            details=("127.0.0.1 listener", "bounded WSGI requests"),
        ),
        _svg_node(
            x=605,
            y=210,
            width=300,
            height=132,
            index="3",
            title="Flask validation",
            details=("parse one bounded length", "invalid → HTTP 400 stop"),
        ),
        _svg_node(
            x=55,
            y=480,
            width=300,
            height=132,
            index="1",
            title="Strict CLI parser",
            details=("inspect + sweep", "value-safe failures"),
            accent=GOLD,
        ),
        _svg_node(
            x=605,
            y=430,
            width=300,
            height=132,
            index="4",
            title="PasswordPolicy",
            details=("visible-ascii-v1", "four disjoint classes"),
            accent=GOLD,
        ),
        _svg_node(
            x=965,
            y=335,
            width=300,
            height=154,
            index="5",
            title="PasswordSpace",
            details=("bounded bottom-up DP", "rank ↔ candidate bijection"),
            accent=GOLD,
        ),
        _svg_node(
            x=1325,
            y=190,
            width=230,
            height=154,
            index="6",
            title="Inspection",
            details=("cardinalities", "fingerprint + bounds"),
        ),
        _svg_node(
            x=1325,
            y=410,
            width=230,
            height=154,
            index="7",
            title="Audit output",
            details=("Jinja audit panel", "CLI text / JSON / CSV"),
        ),
        _svg_node(
            x=965,
            y=650,
            width=300,
            height=154,
            index="P",
            title="Valid POST only",
            details=(
                "one application-level",
                "secrets.randbelow(total) call",
                "deterministic unrank",
            ),
            accent=GOLD,
        ),
        _svg_node(
            x=1325,
            y=650,
            width=230,
            height=154,
            index="8",
            title="HTML response",
            details=("candidate response", "no persistence"),
            accent=GOLD,
        ),
    )
    arrows = f"""
  <g fill="none" stroke="{TEAL}" stroke-width="4" marker-end="url(#arrow-teal)">
    <path d="M285 276 H330"/>
    <path d="M560 276 H605"/>
    <path d="M755 342 V430"/>
    <path d="M1265 380 C1305 380 1290 267 1325 267"/>
    <path d="M1440 344 V410"/>
  </g>
  <g fill="none" stroke="{GOLD}" stroke-width="4" marker-end="url(#arrow-gold)">
    <path d="M355 546 H605"/>
    <path d="M905 496 C940 496 925 445 965 430"/>
    <path d="M1115 489 V650"/>
    <path d="M1265 727 H1325"/>
  </g>
"""
    body = f"""  <text x="80" y="82" class="title">One exact core, two bounded interfaces</text>
  <text x="80" y="120" class="subtitle">Architecture recovered from imports and call sites in the shipped Python source.</text>
  <text x="80" y="178" class="lane">LOCAL WEB PATH</text>
  <text x="80" y="448" class="lane" fill="{GOLD}">DETERMINISTIC CLI PATH</text>
{"".join(nodes)}
{arrows}
  <text x="1095" y="625" text-anchor="end" class="node-code">valid POST sampling edge</text>
  <rect x="55" y="690" width="850" height="104" rx="16" fill="{SURFACE_RAISED}" stroke="{LINE}"/>
  <text x="85" y="731" class="node-title">Invalid web request</text>
  <text x="85" y="765" class="caption">Returns before profile or PasswordSpace construction; inspection remains withheld.</text>
  <path d="M650 342 C600 375 540 390 500 390 H24 V742 H55" fill="none" stroke="{GOLD}" stroke-width="3" stroke-dasharray="9 9" marker-end="url(#arrow-gold)"/>"""
    path.write_text(
        _svg_document(
            title="Password Policy State-Space Lab architecture",
            description=(
                "A local browser and a deterministic CLI converge on one exact "
                "policy, dynamic-programming, and inspection core."
            ),
            width=1600,
            height=880,
            body=body,
        ),
        encoding="utf-8",
    )


def write_sampling_svg(path: Path) -> None:
    """Render the AST-verified one-random-rank sampling path."""

    node_specs = (
        ("1", "Validated policy", ("ordered classes", "fixed minima")),
        ("2", "Exact DP count", ("total valid strings", "no enumeration")),
        (
            "3",
            "Uniform rank",
            (
                "secrets.randbelow(total)",
                "one application-level call",
            ),
        ),
        ("4", "Exact unrank", ("block subtraction", "stable bijection")),
        (
            "5",
            "Valid candidate",
            ("probability 1 / total", "no project rejection loop"),
        ),
    )
    rendered: list[str] = []
    arrow_parts: list[str] = []
    x = 55
    for offset, (index, title, details) in enumerate(node_specs):
        rendered.append(
            _svg_node(
                x=x,
                y=250,
                width=270,
                height=154,
                index=index,
                title=title,
                details=details,
                accent=TEAL if offset < 2 or offset == 4 else GOLD,
            )
        )
        if offset < len(node_specs) - 1:
            arrow_parts.append(
                f'<path d="M{x + 270} 327 H{x + 315}" fill="none" '
                f'stroke="{GOLD if offset == 1 else TEAL}" stroke-width="4" '
                f'marker-end="url(#{"arrow-gold" if offset == 1 else "arrow-teal"})"/>'
            )
        x += 315

    body = f"""  <text x="55" y="82" class="title">Uniform sampling is rank selection, not trial and error</text>
  <text x="55" y="120" class="subtitle">The generator verifies this exact call shape in PasswordSpace.sample_uniform before rendering.</text>
  <rect x="55" y="158" width="1490" height="48" rx="24" fill="{SURFACE_RAISED}" stroke="{LINE}"/>
  <text x="800" y="190" text-anchor="middle" class="node-code">return self.unrank(secrets.randbelow(self._total))</text>
{"".join(rendered)}
  <g>{"".join(arrow_parts)}</g>
  <rect x="180" y="478" width="1240" height="126" rx="16" fill="{SURFACE_RAISED}" stroke="{LINE}"/>
  <text x="800" y="528" text-anchor="middle" class="node-title">Every valid string owns exactly one rank</text>
  <text x="800" y="558" text-anchor="middle" class="caption">Project code has no candidate-rejection loop; the application makes one secrets.randbelow(total) call.</text>
  <text x="800" y="584" text-anchor="middle" class="caption">The standard-library implementation may internally reject random-bit draws.</text>"""
    path.write_text(
        _svg_document(
            title="Exact uniform sampling flow",
            description=(
                "A validated policy is counted exactly, one uniform rank is "
                "selected, and deterministic unranking returns the candidate."
            ),
            width=1600,
            height=650,
            body=body,
        ),
        encoding="utf-8",
    )


def write_setup_svg(path: Path) -> None:
    """Render the reproducible setup-to-evidence workflow."""

    setup_steps = (
        ("01", "Create venv", ("python -m venv .venv", "activate locally")),
        (
            "02",
            "Install project",
            ("pip install -e '.[dev]'", "pinned top-level dev tools"),
        ),
        (
            "03",
            "Run gates",
            ("make check", "lint · types · tests", "distribution · evidence"),
        ),
    )
    nodes: list[str] = []
    arrows: list[str] = []
    for offset, (index, title, details) in enumerate(setup_steps):
        column = offset
        x = 70 + column * 505
        y = 205
        nodes.append(
            _svg_node(
                x=x,
                y=y,
                width=430,
                height=150,
                index=index,
                title=title,
                details=details,
                accent=TEAL,
            )
        )
        if column < 2:
            arrows.append(
                f'<path d="M{x + 430} {y + 75} H{x + 505}" fill="none" '
                f'stroke="{TEAL}" stroke-width="4" '
                'marker-end="url(#arrow-teal)"/>'
            )

    branch_steps = (
        ("A", "Inspect space", ("password-policy-lab", "inspect --length 20")),
        ("B", "Serve locally", ("waitress-serve", "127.0.0.1 only")),
        (
            "C",
            "Rebuild evidence",
            ("make evidence", "Playwright-linked Chromium"),
        ),
    )
    for offset, (index, title, details) in enumerate(branch_steps):
        x = 70 + offset * 505
        nodes.append(
            _svg_node(
                x=x,
                y=475,
                width=430,
                height=150,
                index=index,
                title=title,
                details=details,
                accent=GOLD,
            )
        )
        branch_x = x + 215
        arrows.append(
            f'<path d="M1295 355 V410 H{branch_x} V475" fill="none" '
            f'stroke="{GOLD}" stroke-width="4" '
            'marker-end="url(#arrow-gold)"/>'
        )
    body = f"""  <text x="70" y="82" class="title">From a clean checkout to verified evidence</text>
  <text x="70" y="120" class="subtitle">Local commands are repeatable with the recorded runtime and tool versions.</text>
  <text x="70" y="175" class="lane">SETUP + VERIFY</text>
  <text x="70" y="445" class="lane" fill="{GOLD}">INDEPENDENT NEXT WORKFLOWS</text>
{"".join(nodes)}
  <g>{"".join(arrows)}</g>"""
    path.write_text(
        _svg_document(
            title="Reproducible setup and evidence workflow",
            description=(
                "Six steps cover environment setup, quality gates, state-space "
                "inspection, local serving, and guarded evidence capture."
            ),
            width=1600,
            height=650,
            body=body,
        ),
        encoding="utf-8",
    )


def write_distribution_svg(
    path: Path,
    *,
    input_sha256: str,
    wheel_sha256: str,
    sdist_sha256: str,
) -> None:
    """Render the measured Git-input-to-installed-wheel attestation flow."""

    digests = (input_sha256, wheel_sha256, sdist_sha256)
    if any(
        len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
        for digest in digests
    ):
        raise ValueError("distribution evidence requires lowercase SHA-256 values")

    nodes = (
        _svg_node(
            x=55,
            y=205,
            width=310,
            height=162,
            index="1",
            title="Immutable inputs",
            details=(
                "15 stage-zero Git blobs",
                f"sha256 {input_sha256[:16]}…",
                "normalized modes + mtime",
            ),
        ),
        _svg_node(
            x=430,
            y=205,
            width=310,
            height=162,
            index="2",
            title="Build A + B",
            details=(
                "setuptools 83.0.0",
                "fixed epoch · umask 0022",
                "package index disabled",
            ),
        ),
        _svg_node(
            x=805,
            y=145,
            width=350,
            height=162,
            index="3W",
            title="Canonical wheel",
            details=(
                "17 exact members · 0644",
                f"sha256 {wheel_sha256[:16]}…",
                "two raw wheels byte-equal",
            ),
            accent=GOLD,
        ),
        _svg_node(
            x=805,
            y=380,
            width=350,
            height=162,
            index="3S",
            title="Canonical sdist",
            details=(
                "23 files + 6 directories",
                f"sha256 {sdist_sha256[:16]}…",
                "raw sdist equality unclaimed",
            ),
            accent=GOLD,
        ),
        _svg_node(
            x=1220,
            y=265,
            width=310,
            height=162,
            index="4",
            title="Sdist rebuild",
            details=(
                "safe manual materialization",
                "canonical wheel byte-equal",
                "no extractall",
            ),
        ),
        _svg_node(
            x=1595,
            y=265,
            width=310,
            height=162,
            index="5",
            title="Installed smoke",
            details=(
                "offline pip --target",
                "external cwd + exact origin",
                "inspect only · no sample",
            ),
        ),
    )
    arrows = f"""
  <g fill="none" stroke="{TEAL}" stroke-width="4" marker-end="url(#arrow-teal)">
    <path d="M365 286 H430"/>
    <path d="M740 286 C770 286 775 226 805 226"/>
    <path d="M740 286 C770 286 775 461 805 461"/>
    <path d="M1155 461 C1185 461 1190 346 1220 346"/>
    <path d="M1530 346 H1595"/>
  </g>
  <path d="M1155 226 C1185 226 1190 316 1220 316" fill="none" stroke="{GOLD}" stroke-width="4" stroke-dasharray="10 8" marker-end="url(#arrow-gold)"/>
"""
    body = f"""  <text x="55" y="76" class="title">The release archive is measured, normalized, rebuilt, then installed</text>
  <text x="55" y="116" class="subtitle">Every value comes from the real project-specific attestation; raw backend artifacts are never presented as canonical releases.</text>
{"".join(nodes)}
{arrows}
  <rect x="55" y="625" width="1850" height="150" rx="18" fill="{SURFACE_RAISED}" stroke="{LINE}" stroke-width="2"/>
  <text x="85" y="670" class="node-title">Claim boundary</text>
  <text x="85" y="708" class="caption">No license, signature, dependency-integrity, cross-platform, or arbitrary-archive guarantee.</text>
  <text x="85" y="742" class="caption">The smoke uses current pinned checker dependencies; it is not a fresh dependency environment.</text>
  <text x="1855" y="742" text-anchor="end" class="node-code">official: false</text>"""
    path.write_text(
        _svg_document(
            title="Reproducible distribution attestation flow",
            description=(
                "Fifteen immutable Git inputs feed two builds, canonical wheel "
                "and source archives, a source-archive rebuild, and an installed "
                "deterministic inspection smoke test."
            ),
            width=1960,
            height=830,
            body=body,
        ),
        encoding="utf-8",
    )


_SENSITIVITY_CLASS_NAMES = ("lower", "upper", "digits", "punctuation")


def _sensitivity_decimal(value: object, *, label: str, minimum: int = 0) -> int:
    if (
        type(value) is not str
        or not value
        or len(value) > 4096
        or not value.isascii()
        or not value.isdecimal()
        or (len(value) > 1 and value.startswith("0"))
    ):
        raise ValueError(f"invalid policy sensitivity {label}")
    parsed = int(value)
    if parsed < minimum:
        raise ValueError(f"invalid policy sensitivity {label}")
    return parsed


def _sensitivity_sha256(value: object, *, label: str) -> str:
    if (
        type(value) is not str
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise ValueError(f"invalid policy sensitivity {label}")
    return value


def _validated_policy_sensitivity(
    report: object,
) -> tuple[int, str, tuple[_SensitivityRow, ...]]:
    document = _profile_mapping(
        report,
        keys={
            "analysis",
            "baseline_valid",
            "claim_boundary",
            "operation",
            "policy",
            "policy_sha256",
            "profile",
            "rank_order_version",
            "rows",
            "sensitivity_schema_version",
        },
        label="policy sensitivity document",
    )
    if (
        type(document["sensitivity_schema_version"]) is not int
        or document["sensitivity_schema_version"] != 1
        or document["analysis"] != "one-step-class-minimum-relaxation-v1"
        or document["operation"] != "sensitivity"
        or document["profile"] != "visible-ascii-v1"
        or document["rank_order_version"] != "class-symbol-lexicographic-v1"
    ):
        raise ValueError("invalid policy sensitivity identity")
    policy_sha256 = _sensitivity_sha256(
        document["policy_sha256"],
        label="policy_sha256",
    )
    policy = _profile_mapping(
        document["policy"],
        keys={"alphabet_size", "class_minima", "length"},
        label="policy sensitivity policy",
    )
    minima = _profile_mapping(
        policy["class_minima"],
        keys=set(_SENSITIVITY_CLASS_NAMES),
        label="policy sensitivity class minima",
    )
    if (
        policy["length"] != 20
        or policy["alphabet_size"] != 94
        or minima != {name: 1 for name in _SENSITIVITY_CLASS_NAMES}
    ):
        raise ValueError("invalid policy sensitivity canonical policy")
    boundary = _profile_mapping(
        document["claim_boundary"],
        keys={
            "contains_candidate",
            "effects_are_not_additive",
            "one_step_only",
            "samples_entropy",
        },
        label="policy sensitivity claim boundary",
    )
    if boundary != {
        "contains_candidate": False,
        "effects_are_not_additive": True,
        "one_step_only": True,
        "samples_entropy": False,
    }:
        raise ValueError("invalid policy sensitivity claim boundary")

    baseline = _sensitivity_decimal(
        document["baseline_valid"],
        label="baseline_valid",
        minimum=1,
    )
    raw_rows = _profile_list(document["rows"], label="policy sensitivity rows")
    if len(raw_rows) != len(_SENSITIVITY_CLASS_NAMES):
        raise ValueError("invalid policy sensitivity row count")
    rows: list[_SensitivityRow] = []
    for index, expected_name in enumerate(_SENSITIVITY_CLASS_NAMES):
        row = _profile_mapping(
            raw_rows[index],
            keys={
                "added_if_relaxed",
                "baseline_share_of_relaxed",
                "class_name",
                "original_minimum",
                "relaxation_applied",
                "relaxed_minimum",
                "relaxed_policy_sha256",
                "relaxed_valid",
            },
            label=f"policy sensitivity rows[{index}]",
        )
        relaxed_valid = _sensitivity_decimal(
            row["relaxed_valid"],
            label=f"rows[{index}].relaxed_valid",
            minimum=1,
        )
        added = _sensitivity_decimal(
            row["added_if_relaxed"],
            label=f"rows[{index}].added_if_relaxed",
            minimum=1,
        )
        fraction = _profile_mapping(
            row["baseline_share_of_relaxed"],
            keys={"denominator", "numerator"},
            label=f"policy sensitivity rows[{index}] fraction",
        )
        numerator = _sensitivity_decimal(
            fraction["numerator"],
            label=f"rows[{index}].fraction.numerator",
            minimum=1,
        )
        denominator = _sensitivity_decimal(
            fraction["denominator"],
            label=f"rows[{index}].fraction.denominator",
            minimum=1,
        )
        _sensitivity_sha256(
            row["relaxed_policy_sha256"],
            label=f"rows[{index}].relaxed_policy_sha256",
        )
        if (
            row["class_name"] != expected_name
            or row["original_minimum"] != 1
            or row["relaxation_applied"] is not True
            or row["relaxed_minimum"] != 0
            or relaxed_valid != baseline + added
            or numerator * relaxed_valid != denominator * baseline
            or gcd(numerator, denominator) != 1
        ):
            raise ValueError(f"invalid policy sensitivity rows[{index}]")
        rows.append(
            _SensitivityRow(
                class_name=expected_name,
                original_minimum=1,
                relaxed_minimum=0,
                relaxed_valid=relaxed_valid,
                added_if_relaxed=added,
                fraction_numerator=numerator,
                fraction_denominator=denominator,
            )
        )
    return baseline, policy_sha256, tuple(rows)


def render_policy_sensitivity_svg(report: object) -> str:
    """Return an exact source-bound one-step minimum-impact chart."""

    baseline, policy_sha256, rows = _validated_policy_sensitivity(report)
    maximum_added = max(row.added_if_relaxed for row in rows)
    rendered_rows: list[str] = []
    for index, row in enumerate(rows):
        y = 270 + index * 125
        bar_width = max(3, 710 * row.added_if_relaxed // maximum_added)
        aria = (
            f"{row.class_name}; minimum one to zero; added "
            f"{row.added_if_relaxed}; relaxed valid {row.relaxed_valid}"
        )
        rendered_rows.append(
            f"""  <g id="sensitivity-{row.class_name}" role="group" aria-label="{aria}">
    <text x="80" y="{y + 24}" class="node-title">{row.class_name}</text>
    <text x="80" y="{y + 53}" class="node-code">minimum {row.original_minimum} → {row.relaxed_minimum}</text>
    <rect x="350" y="{y}" width="710" height="32" rx="16" fill="{SURFACE_RAISED}" stroke="{LINE}"/>
    <rect x="350" y="{y}" width="{bar_width}" height="32" rx="16" fill="{TEAL}"/>
    <text x="1095" y="{y + 24}" class="node-code">+{row.added_if_relaxed:,}</text>
    <text x="1095" y="{y + 53}" class="node-detail">relaxed total {row.relaxed_valid:,}</text>
    <text x="1095" y="{y + 78}" class="caption">baseline numerator {row.fraction_numerator}</text>
    <text x="1095" y="{y + 101}" class="caption">relaxed denominator {row.fraction_denominator}</text>
  </g>"""
        )

    body = f"""  <text x="70" y="78" class="title">One-step minimum sensitivity · exact state-space impact</text>
  <text x="70" y="118" class="subtitle">Length 20 · lower exactly one class minimum from 1 to 0 while every other policy field stays fixed.</text>
  <rect x="70" y="150" width="1660" height="78" rx="18" fill="{SURFACE}" stroke="{LINE}"/>
  <text x="100" y="182" class="lane">BASELINE VALID STRINGS</text>
  <text x="100" y="211" class="node-code">{baseline:,}</text>
  <text x="1688" y="183" text-anchor="end" class="caption">policy …{policy_sha256[-16:]}</text>
  <text x="350" y="252" class="lane">ADDED IF THIS ONE MINIMUM IS RELAXED · BARS NORMALIZED TO LARGEST EXACT COUNT</text>
{"".join(rendered_rows)}
  <rect x="70" y="775" width="1660" height="42" rx="14" fill="{SURFACE_RAISED}" stroke="{LINE}"/>
  <text x="100" y="802" class="caption">One step only · effects are not additive · no candidate · no entropy · exact integer dynamic programming</text>"""
    return _svg_document(
        title="Exact one-step password-policy minimum sensitivity",
        description=(
            "Four exact bars show how many valid length-twenty visible-ASCII "
            "strings are added when one class minimum is lowered from one to "
            "zero. Effects are explicitly non-additive and entropy-free."
        ),
        width=1800,
        height=850,
        body=body,
    )


def write_policy_sensitivity_svg(report: object, path: Path) -> None:
    """Write the deterministic exact minimum-sensitivity SVG."""

    path.write_text(render_policy_sensitivity_svg(report), encoding="utf-8")


def _counter_bar(*, x: int, y: int, width: int, observed: int, bound: int) -> str:
    if observed == 0:
        return (
            f'<rect x="{x}" y="{y}" width="{width}" height="18" rx="9" '
            f'fill="{SURFACE_RAISED}" stroke="{GOLD}" stroke-width="2" '
            'stroke-dasharray="8 7"/>'
        )
    filled = max(2, (width * observed + bound // 2) // bound)
    return (
        f'<rect x="{x}" y="{y}" width="{width}" height="18" rx="9" '
        f'fill="{SURFACE_RAISED}" stroke="{LINE}"/>'
        f'<rect x="{x}" y="{y}" width="{filled}" height="18" rx="9" '
        f'fill="{TEAL}"/>'
    )


def render_dp_work_counts_svg(report: object) -> str:
    """Return exact logical DP work against the preflight upper bounds."""

    cases = _validated_dp_profile(report)
    rows: list[str] = []
    for index, case in enumerate(cases):
        y = 300 + index * 120
        minima = " / ".join(str(value) for value in case.spec.class_minima)
        aria = (
            f"{case.spec.title}; length {case.spec.length}; "
            f"occupied cells {case.occupied_cells}; cell bound "
            f"{case.cells_upper_bound}; transition calls {case.transitions}; "
            f"transition bound {case.transitions_upper_bound}"
        )
        if case.layer_occupancy is None:
            cell_label = (
                f"preflight stop · bound {case.cells_upper_bound:,} / budget 250,000"
            )
            transition_label = (
                f"preflight stop · bound {case.transitions_upper_bound:,} / "
                "budget 2,000,000"
            )
            work_label = "product 0 calls · 0 vectors · consume 0"
        else:
            cell_label = (
                f"{case.occupied_cells:,} occupied / {case.cells_upper_bound:,} bound"
            )
            transition_label = (
                f"{case.transitions:,} calls / {case.transitions_upper_bound:,} bound"
            )
            work_label = (
                f"product {case.product_calls:,} calls · "
                f"{case.product_vectors:,} vectors · "
                f"consume {case.consume_calls:,}"
            )
        rows.append(
            f'''  <g id="dp-work-{case.spec.identifier}" role="group" aria-label="{aria}">
    <rect x="55" y="{y - 12}" width="1690" height="105" rx="15" fill="{SURFACE}" stroke="{LINE}"/>
    <text x="78" y="{y + 20}" class="node-title">{case.spec.title}</text>
    <text x="78" y="{y + 50}" class="node-detail">L={case.spec.length} · minima {minima}</text>
    <text x="78" y="{y + 77}" class="node-code">{work_label}</text>
    {_counter_bar(x=470, y=y + 3, width=500, observed=case.occupied_cells, bound=case.cells_upper_bound)}
    <text x="470" y="{y + 50}" class="node-detail">{cell_label}</text>
    {_counter_bar(x=1125, y=y + 3, width=500, observed=case.transitions, bound=case.transitions_upper_bound)}
    <text x="1125" y="{y + 50}" class="node-detail">{transition_label}</text>
  </g>'''
        )

    body = f'''  <text x="70" y="78" class="title">Logical DP work, measured without a stopwatch</text>
  <text x="70" y="118" class="subtitle">Five accepted policies expose actual table work; the sixth proves the preflight budget stops before enumeration.</text>
  <rect x="70" y="150" width="1660" height="74" rx="18" fill="{SURFACE_RAISED}" stroke="{LINE}"/>
  <text x="100" y="182" class="lane">DETERMINISTIC COUNTER CONTRACT · cProfile CALL COUNTS + ITERATOR COUNTERS</text>
  <text x="100" y="208" class="caption">Logical operations only · no elapsed time · no RSS · no hardware performance claim</text>
  <text x="470" y="270" class="lane">OCCUPIED DP CELLS / RECTANGULAR BOUND</text>
  <text x="1125" y="270" class="lane">_CONSUME CALLS / TRANSITION BOUND</text>
{"".join(rows)}
  <text x="70" y="1075" class="caption">Bars encode exact observed-to-bound ratios; every raw integer remains printed beside its bar.</text>
  <text x="1730" y="1075" text-anchor="end" class="node-code">rejected case: product 0 · consume 0</text>'''
    return _svg_document(
        title="Deterministic dynamic-programming work counts",
        description=(
            "Six fixed password-policy cases compare exact logical occupied "
            "cells and transition calls with preflight bounds. The rejected "
            "case records no dynamic-programming enumeration."
        ),
        width=1800,
        height=1120,
        body=body,
    )


def write_dp_work_counts_svg(report: object, path: Path) -> None:
    """Write the deterministic logical-work SVG."""

    path.write_text(render_dp_work_counts_svg(report), encoding="utf-8")


def _occupancy_points(
    values: tuple[int, ...],
    *,
    x: int,
    y: int,
    width: int,
    height: int,
) -> str:
    last_index = len(values) - 1
    peak = max(values)
    denominator = max(1, peak - 1)
    return " ".join(
        f"{x + index * width // last_index},"
        f"{y + height - (value - 1) * height // denominator}"
        for index, value in enumerate(values)
    )


def render_dp_layer_occupancy_svg(report: object) -> str:
    """Return exact per-layer sparse-table occupancy for accepted cases."""

    cases = _validated_dp_profile(report)
    panels: list[str] = []
    for index, case in enumerate(cases):
        column = index % 2
        row = index // 2
        x = 55 + column * 870
        y = 230 + row * 340
        minima = " / ".join(str(value) for value in case.spec.class_minima)
        if case.layer_occupancy is None:
            aria = (
                f"{case.spec.title}; rejected before enumeration; no layer "
                "occupancy curve; product calls zero; consume calls zero"
            )
            panels.append(
                f'''  <g id="dp-layer-{case.spec.identifier}" role="group" aria-label="{aria}">
    <rect x="{x}" y="{y}" width="820" height="300" rx="18" fill="{SURFACE}" stroke="{GOLD}" stroke-width="2"/>
    <text x="{x + 28}" y="{y + 42}" class="node-title">{case.spec.title}</text>
    <text x="{x + 28}" y="{y + 72}" class="node-detail">L={case.spec.length} · minima {minima}</text>
    <rect x="{x + 48}" y="{y + 108}" width="724" height="102" rx="14" fill="{SURFACE_RAISED}" stroke="{GOLD}" stroke-width="2" stroke-dasharray="10 8"/>
    <text x="{x + 410}" y="{y + 148}" text-anchor="middle" class="node-title">NO CURVE · PRECHECK REJECTED</text>
    <text x="{x + 410}" y="{y + 181}" text-anchor="middle" class="node-detail">cell bound {case.cells_upper_bound:,} / 250,000 · transition bound {case.transitions_upper_bound:,} / 2,000,000</text>
    <text x="{x + 28}" y="{y + 252}" class="node-code">product 0 calls · 0 vectors · consume 0</text>
    <text x="{x + 28}" y="{y + 280}" class="caption">No layer table exists, so no occupancy series is drawn.</text>
  </g>'''
            )
            continue

        values = case.layer_occupancy
        peak = max(values)
        plot_x = x + 48
        plot_y = y + 120
        plot_width = 724
        plot_height = 100
        points = _occupancy_points(
            values,
            x=plot_x,
            y=plot_y,
            width=plot_width,
            height=plot_height,
        )
        start_y = plot_y + plot_height
        end_y = plot_y
        aria = (
            f"{case.spec.title}; exact occupancy for layers zero through "
            f"{case.spec.length}; total occupied cells {case.occupied_cells}; "
            f"peak layer occupancy {peak}; transition calls {case.transitions}"
        )
        panels.append(
            f'''  <g id="dp-layer-{case.spec.identifier}" role="group" aria-label="{aria}">
    <rect x="{x}" y="{y}" width="820" height="300" rx="18" fill="{SURFACE}" stroke="{LINE}"/>
    <text x="{x + 28}" y="{y + 42}" class="node-title">{case.spec.title}</text>
    <text x="{x + 28}" y="{y + 72}" class="node-detail">L={case.spec.length} · minima {minima} · peak {peak:,} states</text>
    <text x="{plot_x}" y="{plot_y - 12}" class="node-code">states {peak:,}</text>
    <line x1="{plot_x}" y1="{plot_y}" x2="{plot_x + plot_width}" y2="{plot_y}" stroke="{LINE}" stroke-dasharray="6 7"/>
    <line x1="{plot_x}" y1="{plot_y + plot_height}" x2="{plot_x + plot_width}" y2="{plot_y + plot_height}" stroke="{LINE}"/>
    <polyline data-series="layer-occupancy" points="{points}" fill="none" stroke="{TEAL}" stroke-width="4" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="{plot_x}" cy="{start_y}" r="5" fill="{GOLD}"/>
    <circle cx="{plot_x + plot_width}" cy="{end_y}" r="5" fill="{GOLD}"/>
    <text x="{plot_x}" y="{plot_y + plot_height + 25}" class="caption">remaining 0 · states 1</text>
    <text x="{plot_x + plot_width}" y="{plot_y + plot_height + 25}" text-anchor="end" class="caption">remaining {case.spec.length} · states {peak:,}</text>
    <text x="{x + 28}" y="{y + 272}" class="node-code">occupied {case.occupied_cells:,} · product {case.product_calls:,} calls / {case.product_vectors:,} vectors · consume {case.consume_calls:,}</text>
  </g>'''
        )

    body = f'''  <text x="70" y="78" class="title">Sparse DP occupancy, layer by exact layer</text>
  <text x="70" y="118" class="subtitle">Every accepted curve is drawn directly from the profiled layer_occupancy array; the rejected policy has no invented series.</text>
  <rect x="70" y="150" width="1660" height="50" rx="16" fill="{SURFACE_RAISED}" stroke="{LINE}"/>
  <text x="900" y="182" text-anchor="middle" class="caption">Logical state counts only · no elapsed time · no RSS · no hardware performance claim</text>
{"".join(panels)}
  <text x="70" y="1280" class="caption">Horizontal axis: remaining positions. Vertical axis: retained bounded-deficit vectors on an exact linear scale within each panel.</text>
  <text x="1730" y="1280" text-anchor="end" class="node-code">5 observed curves · 1 fail-fast boundary</text>'''
    return _svg_document(
        title="Exact dynamic-programming layer occupancy",
        description=(
            "Five panels plot exact retained deficit-vector counts by "
            "remaining position. A sixth panel records a complexity-budget "
            "rejection and deliberately contains no curve."
        ),
        width=1800,
        height=1320,
        body=body,
    )


def write_dp_layer_occupancy_svg(report: object, path: Path) -> None:
    """Write the deterministic layer-occupancy SVG."""

    path.write_text(render_dp_layer_occupancy_svg(report), encoding="utf-8")


def _wrapped_lines(transcript: str, width: int) -> list[str]:
    lines: list[str] = []
    for line in transcript.rstrip("\n").splitlines():
        if not line:
            lines.append("")
            continue
        subsequent = "  " if line.startswith("$ ") else ""
        lines.extend(
            textwrap.wrap(
                line,
                width=width,
                subsequent_indent=subsequent,
                replace_whitespace=False,
                drop_whitespace=False,
            )
            or [""]
        )
    return lines


def render_terminal_png_bytes(*, transcript: str, title: str) -> bytes:
    """Return a deterministic PNG for a real, already-recorded transcript."""

    width = 1600
    padding = 54
    header_height = 118
    line_height = 30
    lines = _wrapped_lines(transcript, 120)
    height = header_height + padding + max(1, len(lines)) * line_height + padding
    image = Image.new("RGB", (width, height), BACKGROUND)
    draw = ImageDraw.Draw(image)
    title_font = ImageFont.load_default(size=29)
    body_font = ImageFont.load_default(size=22)
    label_font = ImageFont.load_default(size=18)

    draw.rounded_rectangle(
        (18, 18, width - 18, height - 18),
        radius=26,
        fill=SURFACE,
        outline=LINE,
        width=2,
    )
    draw.line((18, header_height, width - 18, header_height), fill=LINE, width=2)
    draw.text((padding, 48), title, fill=TEXT, font=title_font)
    label = "RECORDED COMMAND OUTPUT · REPRODUCIBLE TRANSCRIPT"
    label_width = draw.textlength(label, font=label_font)
    draw.text(
        (width - padding - label_width, 52),
        label,
        fill=MUTED,
        font=label_font,
    )

    y = header_height + 34
    for line in lines:
        color = GOLD if line.startswith("$ ") else TEXT
        if line.startswith(("All checks", "Success:", "No broken")):
            color = TEAL
        draw.text((padding, y), line, fill=color, font=body_font)
        y += line_height

    buffer = BytesIO()
    image.save(buffer, format="PNG", optimize=True, compress_level=9)
    return buffer.getvalue()


def render_terminal_png(*, transcript: str, title: str, path: Path) -> None:
    """Write a deterministic transcript PNG without terminal metadata."""

    path.write_bytes(render_terminal_png_bytes(transcript=transcript, title=title))


def recompress_png(path: Path) -> None:
    """Strip incidental PNG metadata and use deterministic lossless compression."""

    with Image.open(path) as image:
        clean = image.convert("RGB")
    buffer = BytesIO()
    clean.save(buffer, format="PNG", optimize=True, compress_level=9)
    path.write_bytes(buffer.getvalue())


def _frame_fidelity(expected: Any, actual: Any) -> FrameFidelity:
    numpy: Any = importlib.import_module("numpy")
    expected_array = numpy.asarray(expected, dtype=numpy.int16)
    actual_array = numpy.asarray(actual, dtype=numpy.int16)
    delta = numpy.abs(actual_array - expected_array)
    pixel_error = delta.max(axis=2)
    bad_pixels = pixel_error > 32
    height, width = pixel_error.shape
    tile_x = numpy.minimum(16, numpy.arange(width) * 17 // width)
    tile_y = numpy.minimum(14, numpy.arange(height) * 15 // height)
    tile_mae: list[float] = []
    tile_bad: list[float] = []
    for row in range(15):
        row_indices = numpy.flatnonzero(tile_y == row)
        for column in range(17):
            column_indices = numpy.flatnonzero(tile_x == column)
            tile_delta = delta[
                row_indices[0] : row_indices[-1] + 1,
                column_indices[0] : column_indices[-1] + 1,
            ]
            tile_pixels = bad_pixels[
                row_indices[0] : row_indices[-1] + 1,
                column_indices[0] : column_indices[-1] + 1,
            ]
            tile_mae.append(float(tile_delta.mean()))
            tile_bad.append(float(tile_pixels.mean()))

    return FrameFidelity(
        bad_pixel_ratio=float(bad_pixels.mean()),
        mae=float(delta.mean()),
        maximum_channel_error=int(delta.max()),
        maximum_tile_bad_pixel_ratio=max(tile_bad),
        maximum_tile_mae=max(tile_mae),
        p999_pixel_error=int(numpy.quantile(pixel_error, 0.999, method="higher")),
    )


def _assert_fidelity(metrics: FrameFidelity) -> None:
    if (
        metrics.mae > 1.0
        or metrics.bad_pixel_ratio > 0.002
        or metrics.maximum_tile_mae > 2.5
        or metrics.maximum_tile_bad_pixel_ratio > 0.03
        or metrics.maximum_channel_error > 64
        or metrics.p999_pixel_error > 32
    ):
        raise RuntimeError("localized GIF fidelity check failed")


def write_gif(
    *,
    frames: Sequence[bytes],
    path: Path,
    reference_path: Path,
) -> GifFidelity:
    """Write full GIF frames and their lossless ordered browser reference."""

    if not frames:
        raise ValueError("at least one GIF frame is required")
    images: list[Any] = []
    for payload in frames:
        with Image.open(BytesIO(payload)) as image:
            images.append(image.convert("RGB"))

    size = images[0].size
    if any(image.size != size for image in images):
        raise ValueError("all GIF frames must have the same dimensions")

    reference = Image.new("RGB", (size[0], size[1] * len(images)))
    for index, image in enumerate(images):
        reference.paste(image, (0, size[1] * index))
    reference.save(
        reference_path,
        format="PNG",
        optimize=True,
        compress_level=9,
    )
    with Image.open(reference_path) as rendered_reference:
        if rendered_reference.size != reference.size:
            raise RuntimeError("validation reference sheet has invalid dimensions")
        for index, expected in enumerate(images):
            box = (0, index * size[1], size[0], (index + 1) * size[1])
            if rendered_reference.crop(box).convert("RGB").tobytes() != (
                expected.tobytes()
            ):
                raise RuntimeError("validation reference sheet is not lossless")

    gif_plugin: Any = importlib.import_module("PIL.GifImagePlugin")
    paletted = [
        image.quantize(
            colors=256,
            method=Image.Quantize.MEDIANCUT,
            dither=Image.Dither.NONE,
        )
        for image in images
    ]
    durations = (1200, 800, 1800)
    with path.open("wb") as stream:
        header, _ = gif_plugin.getheader(
            paletted[0].copy(),
            info={"duration": durations[0]},
        )
        for chunk in header:
            stream.write(chunk)
        for index, (frame, duration) in enumerate(
            zip(paletted, durations, strict=True)
        ):
            chunks = gif_plugin.getdata(
                frame.copy(),
                offset=(0, 0),
                duration=duration,
                disposal=1,
                include_color_table=index > 0,
            )
            for chunk in chunks:
                stream.write(chunk)
        stream.write(b";")
    fidelity: list[FrameFidelity] = []
    with Image.open(path) as rendered:
        if rendered.info.get("loop") is not None:
            raise RuntimeError("validation GIF must play once without a loop extension")
        if rendered.n_frames != len(images):
            raise RuntimeError("validation GIF dropped a browser frame")
        for index, expected in enumerate(images):
            rendered.seek(index)
            if (
                rendered.disposal_method != 1
                or rendered.info.get("transparency") is not None
                or len(rendered.tile) != 1
                or tuple(rendered.tile[0].extents) != (0, 0, *size)
            ):
                raise RuntimeError(
                    "validation GIF frame is not an opaque full-canvas image"
                )
            decoded = rendered.convert("RGB")
            metrics = _frame_fidelity(expected, decoded)
            _assert_fidelity(metrics)
            fidelity.append(metrics)
    return GifFidelity(frames=tuple(fidelity))
