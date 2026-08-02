from __future__ import annotations

import copy
import importlib.util
import sys
import xml.etree.ElementTree as ElementTree
from pathlib import Path
from types import ModuleType
from typing import Any, cast

import pytest


def _load_script(name: str) -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"{name}_for_render_tests", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


rendering = cast(Any, _load_script("evidence_rendering"))
profiler = cast(Any, _load_script("profile_complexity"))


def _svg(path: Path) -> tuple[ElementTree.Element, str]:
    text = path.read_text(encoding="utf-8")
    root = ElementTree.fromstring(text)
    return root, text


def _local_name(element: ElementTree.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _assert_accessible_local_svg(
    root: ElementTree.Element,
    *,
    width: int,
    height: int,
) -> None:
    assert _local_name(root) == "svg"
    assert root.attrib["width"] == str(width)
    assert root.attrib["height"] == str(height)
    assert root.attrib["viewBox"] == f"0 0 {width} {height}"
    assert root.attrib["role"] == "img"
    assert root.attrib["aria-labelledby"] == "title description"
    assert sum(_local_name(item) == "title" for item in root) == 1
    assert sum(_local_name(item) == "desc" for item in root) == 1
    assert all(
        _local_name(item).lower() not in {"foreignobject", "script"}
        for item in root.iter()
    )
    for item in root.iter():
        for key, value in item.attrib.items():
            if key.rsplit("}", 1)[-1].lower() == "href":
                assert value.startswith("#")
            assert "url(http" not in value.lower()


def _groups(root: ElementTree.Element, prefix: str) -> list[ElementTree.Element]:
    return [
        item
        for item in root.iter()
        if _local_name(item) == "g" and item.attrib.get("id", "").startswith(prefix)
    ]


def test_work_counts_svg_is_exact_accessible_and_deterministic(
    tmp_path: Path,
) -> None:
    report = profiler.build_profile()
    before = copy.deepcopy(report)
    first = tmp_path / "work-a.svg"
    second = tmp_path / "work-b.svg"
    rendered = rendering.render_dp_work_counts_svg(report)

    rendering.write_dp_work_counts_svg(report, first)
    rendering.write_dp_work_counts_svg(report, second)

    root, text = _svg(first)
    _assert_accessible_local_svg(root, width=1800, height=1120)
    assert rendered == rendering.render_dp_work_counts_svg(report)
    assert first.read_text(encoding="utf-8") == rendered
    assert first.read_bytes() == second.read_bytes()
    assert report == before
    assert len(_groups(root, "dp-work-")) == 6
    assert all(
        group.attrib.get("role") == "group" for group in _groups(root, "dp-work-")
    )
    for expected in (
        "304 occupied / 336 bound",
        "31,213 occupied / 60,025 bound",
        "2,288 occupied / 4,400 bound",
        "164,025 occupied / 216,513 bound",
        "33,153 occupied / 66,049 bound",
        "1,312,192 calls / 1,732,104 bound",
        "bound 2,162,688 / budget 250,000",
        "bound 17,301,504 / budget 2,000,000",
        "product 0 calls · 0 vectors · consume 0",
    ):
        assert expected in text
    assert "no elapsed time · no RSS · no hardware performance claim" in text


def test_layer_occupancy_svg_draws_only_five_real_series(
    tmp_path: Path,
) -> None:
    report = profiler.build_profile()
    before = copy.deepcopy(report)
    first = tmp_path / "layers-a.svg"
    second = tmp_path / "layers-b.svg"
    rendered = rendering.render_dp_layer_occupancy_svg(report)

    rendering.write_dp_layer_occupancy_svg(report, first)
    rendering.write_dp_layer_occupancy_svg(report, second)

    root, text = _svg(first)
    _assert_accessible_local_svg(root, width=1800, height=1320)
    assert rendered == rendering.render_dp_layer_occupancy_svg(report)
    assert first.read_text(encoding="utf-8") == rendered
    assert first.read_bytes() == second.read_bytes()
    assert report == before
    groups = _groups(root, "dp-layer-")
    assert len(groups) == 6
    accepted = groups[:-1]
    rejected = groups[-1]
    assert [
        sum(
            _local_name(item) == "polyline"
            and item.attrib.get("data-series") == "layer-occupancy"
            for item in group.iter()
        )
        for group in accepted
    ] == [1, 1, 1, 1, 1]
    assert not any(_local_name(item) == "polyline" for item in rejected.iter())
    assert "NO CURVE · PRECHECK REJECTED" in text
    assert "No layer table exists, so no occupancy series is drawn." in text
    for expected in (
        "occupied 304 · product 20 calls / 320 vectors · consume 1,212",
        "occupied 31,213 · product 24 calls / 57,624 vectors · consume 124,848",
        "occupied 2,288 · product 24 calls / 4,224 vectors · consume 9,148",
        "occupied 164,025 · product 32 calls / 209,952 vectors · consume 1,312,192",
        "occupied 33,153 · product 256 calls / 65,792 vectors · consume 33,152",
    ):
        assert expected in text
    assert "no elapsed time · no RSS · no hardware performance claim" in text


def test_terminal_png_renderer_is_pure_and_matches_write_wrapper(
    tmp_path: Path,
) -> None:
    transcript = "$ profiler --format text\nASCII body · exact counters\n"
    title = "Deterministic DP work profile · six fixed policies"
    path = tmp_path / "profile.png"

    first = rendering.render_terminal_png_bytes(
        transcript=transcript,
        title=title,
    )
    second = rendering.render_terminal_png_bytes(
        transcript=transcript,
        title=title,
    )
    rendering.render_terminal_png(
        transcript=transcript,
        title=title,
        path=path,
    )

    assert first == second == path.read_bytes()
    assert first.startswith(b"\x89PNG\r\n\x1a\n")


def _mutated_report(mutation: str) -> dict[str, object]:
    report = cast(dict[str, object], copy.deepcopy(profiler.build_profile()))
    cases = cast(list[dict[str, object]], report["cases"])
    if mutation == "schema-bool":
        report["schema_version"] = True
    elif mutation == "case-order":
        cases[0], cases[1] = cases[1], cases[0]
    elif mutation == "missing-case":
        cases.pop()
    elif mutation == "timing-claim":
        cast(dict[str, object], report["profiler"])["timing_fields_retained"] = True
    elif mutation == "occupancy":
        observed = cast(dict[str, object], cases[0]["observed"])
        occupancy = cast(list[int], observed["layer_occupancy"])
        occupancy[1] += 1
    elif mutation == "product-counter":
        cast(dict[str, object], cases[0]["work_counters"])["product_vectors"] = 1
    elif mutation == "rejected-series":
        cases[-1]["observed"] = {
            "layer_occupancy": [1],
            "occupied_cells": 1,
            "peak_count_bits": 1,
            "transitions": 1,
            "valid_state_space": "1",
        }
    else:  # pragma: no cover - test helper contract
        raise AssertionError("unknown mutation")
    return report


@pytest.mark.parametrize(
    "mutation",
    (
        "schema-bool",
        "case-order",
        "missing-case",
        "timing-claim",
        "occupancy",
        "product-counter",
        "rejected-series",
    ),
)
@pytest.mark.parametrize(
    "renderer",
    (
        "write_dp_work_counts_svg",
        "write_dp_layer_occupancy_svg",
    ),
)
def test_complexity_renderers_fail_closed_before_writing(
    mutation: str,
    renderer: str,
    tmp_path: Path,
) -> None:
    path = tmp_path / f"{mutation}.svg"

    with pytest.raises(ValueError, match="invalid complexity profile"):
        getattr(rendering, renderer)(_mutated_report(mutation), path)

    assert not path.exists()
