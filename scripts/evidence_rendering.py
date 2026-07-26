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
from pathlib import Path
from typing import Any

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
        ("03", "Run gates", ("make check", "lint · types · tests")),
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


def render_terminal_png(*, transcript: str, title: str, path: Path) -> None:
    """Render a real, already-recorded transcript without terminal metadata."""

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

    image.save(path, format="PNG", optimize=True, compress_level=9)


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
