#!/usr/bin/env python3
"""Validate the reproducible, secret-free portfolio evidence bundle."""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import html
import io
import json
import re
import struct
import sys
import zlib
from collections.abc import Sequence
from pathlib import Path, PurePosixPath
from typing import NoReturn, cast
from xml.etree import ElementTree

from PIL import Image

from password_policy_lab.inspection import (
    RANK_ORDER_VERSION,
    REPORT_SCHEMA_VERSION,
    StateSpaceInspection,
    inspect_policy,
)
from password_policy_lab.profiles import (
    VISIBLE_ASCII_PROFILE,
    visible_ascii_policy,
)

MANIFEST_PATH = "docs/evidence/manifest.json"
GENERATOR_PATH = "scripts/generate_evidence.py"

EXPECTED_ASSETS = frozenset(
    {
        "docs/assets/architecture.svg",
        "docs/assets/cli-inspect.png",
        "docs/assets/distribution-check.png",
        "docs/assets/distribution-contract.svg",
        "docs/assets/quality-gate.png",
        "docs/assets/setup-workflow.svg",
        "docs/assets/state-space-sweep.png",
        "docs/assets/uniform-sampling-flow.svg",
        "docs/assets/web-home-mobile.png",
        "docs/assets/web-home.png",
        "docs/assets/web-invalid-length.png",
        "docs/assets/web-validation-demo.gif",
    }
)
EXPECTED_RAW_EVIDENCE = frozenset(
    {
        "docs/evidence/cli-inspect.txt",
        "docs/evidence/distribution-attestation.json",
        "docs/evidence/distribution-check.txt",
        "docs/evidence/quality-gate.txt",
        "docs/evidence/state-space-sweep.csv",
    }
)
GIF_REFERENCE_PATH = "docs/evidence/web-validation-reference.png"
EXPECTED_ARTIFACTS = EXPECTED_ASSETS | EXPECTED_RAW_EVIDENCE | {GIF_REFERENCE_PATH}
CAPTURE_VIEWPORTS = {
    "docs/assets/web-home-mobile.png": (390, 844),
    "docs/assets/web-home.png": (1_440, 960),
    "docs/assets/web-invalid-length.png": (1_440, 960),
    "docs/assets/web-validation-demo.gif": (1_080, 900),
}

_FIDELITY_COLUMNS = 17
_FIDELITY_ROWS = 15
_FIDELITY_BAD_DELTA = 32
_FIDELITY_MAX_GLOBAL_MAE = 1.0
_FIDELITY_MAX_GLOBAL_BAD_RATIO = 0.002
_FIDELITY_MAX_TILE_MAE = 2.5
_FIDELITY_MAX_TILE_BAD_RATIO = 0.03
_FIDELITY_MAX_CHANNEL_DELTA = 64
_FIDELITY_MAX_P999_DELTA = 32

MEDIA_TYPES = {
    ".csv": "text/csv",
    ".gif": "image/gif",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".txt": "text/plain",
}

SWEEP_COMMAND = (
    "password-policy-lab sweep --start-length 8 --end-length 32 --format csv"
)
INSPECT_COMMAND = "password-policy-lab inspect --length 20 --format text"
QUALITY_COMMANDS = (
    "python -m ruff check app.py scripts src tests",
    "python -m ruff format --check app.py scripts src tests",
    "MYPYPATH=src python -m mypy --strict app.py scripts src tests",
    (
        "PYTHONPATH=src python -m pytest --cov=password_policy_lab "
        "--cov-branch --cov-report=term-missing -q"
    ),
    "python scripts/attest_distribution.py",
    "python -m pip check",
)
DISTRIBUTION_INPUTS = (
    "MANIFEST.in",
    "PACKAGE.md",
    "pyproject.toml",
    "src/password_policy_lab/__init__.py",
    "src/password_policy_lab/__main__.py",
    "src/password_policy_lab/cli.py",
    "src/password_policy_lab/errors.py",
    "src/password_policy_lab/inspection.py",
    "src/password_policy_lab/policy.py",
    "src/password_policy_lab/profiles.py",
    "src/password_policy_lab/py.typed",
    "src/password_policy_lab/space.py",
    "src/password_policy_lab/static/styles.css",
    "src/password_policy_lab/templates/index.html",
    "src/password_policy_lab/web.py",
)
_DISTRIBUTION_ROOT = "password_policy_state_space-0.1.0"
_DIST_INFO = "password_policy_state_space-0.1.0.dist-info"
_EGG_INFO = "src/password_policy_state_space.egg-info"
_WHEEL_MEMBERS = (
    "password_policy_lab/__init__.py",
    "password_policy_lab/__main__.py",
    "password_policy_lab/cli.py",
    "password_policy_lab/errors.py",
    "password_policy_lab/inspection.py",
    "password_policy_lab/policy.py",
    "password_policy_lab/profiles.py",
    "password_policy_lab/py.typed",
    "password_policy_lab/space.py",
    "password_policy_lab/web.py",
    "password_policy_lab/static/styles.css",
    "password_policy_lab/templates/index.html",
    f"{_DIST_INFO}/METADATA",
    f"{_DIST_INFO}/WHEEL",
    f"{_DIST_INFO}/entry_points.txt",
    f"{_DIST_INFO}/top_level.txt",
    f"{_DIST_INFO}/RECORD",
)
_SDIST_FILES = tuple(
    sorted(
        {
            "MANIFEST.in",
            "PACKAGE.md",
            "PKG-INFO",
            "pyproject.toml",
            "setup.cfg",
            *DISTRIBUTION_INPUTS[3:],
            f"{_EGG_INFO}/PKG-INFO",
            f"{_EGG_INFO}/SOURCES.txt",
            f"{_EGG_INFO}/dependency_links.txt",
            f"{_EGG_INFO}/entry_points.txt",
            f"{_EGG_INFO}/requires.txt",
            f"{_EGG_INFO}/top_level.txt",
        }
    )
)
_FIXED_DISTRIBUTION_MTIME = 1_704_067_200
SWEEP_COLUMNS = (
    "length",
    "policy_sha256",
    "valid",
    "unconstrained",
    "excluded",
    "fraction_numerator",
    "fraction_denominator",
    "entropy_bits_floor",
    "entropy_bits_ceiling",
    "dp_cells_upper_bound",
    "dp_transitions_upper_bound",
)

_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_EMAIL = re.compile(
    r"(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@"
    r"[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9.-])"
)
_TIMESTAMP = re.compile(
    r"(?i)\b(?:19|20|21)[0-9]{2}-[01][0-9]-[0-3][0-9]"
    r"(?:[T ][0-2][0-9]:[0-5][0-9](?::[0-6][0-9](?:\.[0-9]+)?)?Z?)?\b"
)
_WORKSPACE_PATH = re.compile(
    r"(?:/home/[^/\s]+/|/Users/[^/\s]+/|[A-Za-z]:\\(?:Users|home)\\)"
)
_CREDENTIAL = re.compile(
    r"(?i)(?:"
    r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b|"
    r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\bAuthorization\s*:\s*Bearer\s+\S+|"
    r"\b(?:api[_-]?key|access[_-]?token|secret[_-]?key)\s*[:=]\s*"
    r"[\"']?(?!false\b|none\b|redacted\b)[A-Za-z0-9_./+=-]{8,}"
    r")"
)
_REVERSIBLE_OUTPUT = re.compile(
    r"(?i)(?:"
    r"\bdeterministic_test_vector\b|"
    r"\boperation\s*[:=]\s*[\"']?unrank\b|"
    r"\breversible_output\s*[:=]\s*(?:true|[\"']true[\"'])\b|"
    r"\bgenerated[_ -]?password\s*[:=]\s*"
    r"(?!false\b|none\b|absent\b)[\"']?[!-~]{4,}"
    r")"
)
_MARKDOWN_LINK = re.compile(r"!?\[[^\]]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+[^)]*)?\)")
_HTML_LINK = re.compile(
    r"""(?is)<(?:a|img)\b[^>]*\b(?:href|src)\s*=\s*["']([^"']+)["']"""
)


class EvidenceValidationError(ValueError):
    """The generated evidence bundle does not match its audited contract."""


def _fail(message: str) -> NoReturn:
    raise EvidenceValidationError(message)


def _mapping(value: object, label: str) -> dict[str, object]:
    if type(value) is not dict:
        _fail(f"{label} must be an object")
    return cast(dict[str, object], value)


def _sequence(value: object, label: str) -> list[object]:
    if type(value) is not list:
        _fail(f"{label} must be an array")
    return cast(list[object], value)


def _string(value: object, label: str) -> str:
    if type(value) is not str or not value:
        _fail(f"{label} must be a nonempty string")
    return value


def _integer(value: object, label: str, *, minimum: int = 0) -> int:
    if type(value) is not int or value < minimum:
        _fail(f"{label} must be an integer of at least {minimum}")
    return value


def _boolean(value: object, label: str) -> bool:
    if type(value) is not bool:
        _fail(f"{label} must be a boolean")
    return value


def _exact_keys(
    mapping: dict[str, object],
    expected: set[str],
    label: str,
) -> None:
    if set(mapping) != expected:
        _fail(f"{label} has an unexpected schema")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_path(root: Path, raw_path: object, label: str) -> tuple[str, Path]:
    path = _string(raw_path, label)
    pure = PurePosixPath(path)
    if (
        path != pure.as_posix()
        or pure.is_absolute()
        or "\\" in path
        or not pure.parts
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        _fail(f"{label} must be a normalized relative POSIX path")

    destination = root.joinpath(*pure.parts)
    try:
        destination.resolve(strict=False).relative_to(root.resolve())
    except ValueError:
        _fail(f"{label} escapes the repository")
    if destination.is_symlink():
        _fail(f"{label} must not be a symbolic link")
    return path, destination


def _load_json(
    path: Path,
    *,
    label: str = "manifest",
) -> tuple[dict[str, object], str]:
    try:
        if not 0 < path.stat().st_size <= 2_000_000:
            _fail(f"{label} has an invalid byte size")
        raw = path.read_bytes()
    except OSError:
        _fail(f"{label} is missing or unreadable")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        _fail(f"{label} must be UTF-8")

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                _fail(f"{label} contains a duplicate object key")
            result[key] = value
        return result

    try:
        value = json.loads(text, object_pairs_hook=reject_duplicates)
    except (json.JSONDecodeError, RecursionError):
        _fail(f"{label} is not valid bounded JSON")
    document = _mapping(value, label)
    canonical = (
        json.dumps(
            document,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if text != canonical:
        _fail(f"{label} is not canonical sorted JSON")
    return document, text


def _validate_safe_text(text: str, label: str) -> None:
    if "\x00" in text:
        _fail(f"{label} contains a NUL byte")
    if _WORKSPACE_PATH.search(text) is not None:
        _fail(f"{label} contains an absolute workspace path")
    if _EMAIL.search(text) is not None:
        _fail(f"{label} contains an email address")
    if _TIMESTAMP.search(text) is not None:
        _fail(f"{label} contains a timestamp or datestamp")
    if _CREDENTIAL.search(text) is not None:
        _fail(f"{label} contains credential-like material")
    if _REVERSIBLE_OUTPUT.search(text) is not None:
        _fail(f"{label} contains reversible candidate output")


def _read_bounded(path: Path, label: str, *, maximum: int = 20_000_000) -> bytes:
    try:
        size = path.stat().st_size
    except OSError:
        _fail(f"{label} is missing or unreadable")
    if not 0 < size <= maximum:
        _fail(f"{label} has an invalid byte size")
    try:
        return path.read_bytes()
    except OSError:
        _fail(f"{label} is unreadable")


def _decompress_png_text(payload: bytes, label: str) -> bytes:
    decompressor = zlib.decompressobj()
    try:
        decoded = decompressor.decompress(payload, 1_000_001)
    except zlib.error:
        _fail(f"{label} has invalid compressed PNG text")
    if (
        len(decoded) > 1_000_000
        or decompressor.unconsumed_tail
        or decompressor.unused_data
        or not decompressor.eof
    ):
        _fail(f"{label} has oversized or malformed compressed PNG text")
    return decoded


def _png_info(data: bytes, label: str) -> tuple[int, int, str]:
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        _fail(f"{label} is not a PNG")
    offset = 8
    width = 0
    height = 0
    text_parts: list[str] = []
    seen_iend = False
    first_chunk = True
    while offset < len(data):
        if offset + 12 > len(data):
            _fail(f"{label} has a truncated PNG chunk")
        length = struct.unpack(">I", data[offset : offset + 4])[0]
        kind = data[offset + 4 : offset + 8]
        end = offset + 12 + length
        if end > len(data):
            _fail(f"{label} has a truncated PNG payload")
        payload = data[offset + 8 : offset + 8 + length]
        expected_crc = struct.unpack(">I", data[offset + 8 + length : end])[0]
        if zlib.crc32(kind + payload) & 0xFFFFFFFF != expected_crc:
            _fail(f"{label} has an invalid PNG checksum")
        if first_chunk:
            if kind != b"IHDR" or length != 13:
                _fail(f"{label} has an invalid PNG header")
            width, height = struct.unpack(">II", payload[:8])
            first_chunk = False
        elif kind == b"tEXt":
            text_parts.append(payload.decode("latin-1"))
        elif kind == b"zTXt":
            separator = payload.find(b"\x00")
            if (
                separator < 0
                or separator + 2 > len(payload)
                or payload[separator + 1] != 0
            ):
                _fail(f"{label} has malformed compressed PNG text")
            text_parts.append(
                b"\x00".join(
                    (
                        payload[:separator],
                        _decompress_png_text(payload[separator + 2 :], label),
                    )
                ).decode("latin-1", errors="replace")
            )
        elif kind == b"iTXt":
            separator = payload.find(b"\x00")
            if separator < 0 or separator + 3 > len(payload):
                _fail(f"{label} has malformed international PNG text")
            keyword = payload[:separator]
            compression_flag = payload[separator + 1]
            compression_method = payload[separator + 2]
            remainder = payload[separator + 3 :]
            fields = remainder.split(b"\x00", 2)
            if (
                len(fields) != 3
                or compression_flag not in {0, 1}
                or compression_method != 0
            ):
                _fail(f"{label} has malformed international PNG text")
            language, translated, encoded_text = fields
            if compression_flag == 1:
                encoded_text = _decompress_png_text(encoded_text, label)
            elif len(encoded_text) > 1_000_000:
                _fail(f"{label} has oversized international PNG text")
            text_parts.append(
                b"\x00".join((keyword, language, translated, encoded_text)).decode(
                    "utf-8",
                    errors="replace",
                )
            )
        elif kind in {b"eXIf", b"iCCP", b"tIME"}:
            _fail(f"{label} contains nondeterministic PNG metadata")
        elif kind == b"IEND":
            if length != 0 or end != len(data):
                _fail(f"{label} has trailing or malformed PNG data")
            seen_iend = True
        offset = end
    if not seen_iend or not 1 <= width <= 20_000 or not 1 <= height <= 20_000:
        _fail(f"{label} has invalid PNG dimensions or terminator")
    return width, height, "\n".join(text_parts)


def _gif_subblocks(data: bytes, offset: int, label: str) -> tuple[int, bytes]:
    parts: list[bytes] = []
    while True:
        if offset >= len(data):
            _fail(f"{label} has a truncated GIF sub-block")
        length = data[offset]
        offset += 1
        if length == 0:
            return offset, b"".join(parts)
        if offset + length > len(data):
            _fail(f"{label} has a truncated GIF sub-block payload")
        parts.append(data[offset : offset + length])
        offset += length


def _gif_info(
    data: bytes,
    label: str,
) -> tuple[int, int, int, tuple[int, ...], str]:
    if len(data) < 14 or data[:6] not in {b"GIF87a", b"GIF89a"}:
        _fail(f"{label} is not a GIF")
    width, height = struct.unpack("<HH", data[6:10])
    packed = data[10]
    offset = 13
    if packed & 0x80:
        offset += 3 * (2 ** ((packed & 0x07) + 1))
    frames = 0
    frame_delays: list[int] = []
    comments: list[str] = []
    pending_delay: int | None = None
    terminated = False
    while offset < len(data):
        marker = data[offset]
        offset += 1
        if marker == 0x3B:
            if offset != len(data):
                _fail(f"{label} has trailing GIF data")
            terminated = True
            break
        if marker == 0x21:
            if offset >= len(data):
                _fail(f"{label} has a truncated GIF extension")
            extension = data[offset]
            offset += 1
            offset, payload = _gif_subblocks(data, offset, label)
            if extension == 0xFE:
                comments.append(payload.decode("latin-1", errors="replace"))
            elif extension == 0xF9:
                if len(payload) != 4 or pending_delay is not None:
                    _fail(f"{label} has a malformed GIF control extension")
                disposal_method = (payload[0] >> 2) & 0x07
                has_transparency = bool(payload[0] & 0x01)
                if disposal_method != 1 or has_transparency:
                    _fail(f"{label} must use opaque full-frame GIF disposal method 1")
                pending_delay = int.from_bytes(payload[1:3], "little") * 10
            elif extension == 0xFF:
                _fail(f"{label} contains a GIF application or loop extension")
            elif extension == 0x01:
                comments.append(payload.decode("latin-1", errors="replace"))
            continue
        if marker != 0x2C or offset + 9 > len(data):
            _fail(f"{label} has an invalid GIF block")
        left, top, frame_width, frame_height = struct.unpack(
            "<HHHH",
            data[offset : offset + 8],
        )
        if left != 0 or top != 0 or frame_width != width or frame_height != height:
            _fail(f"{label} contains a clipped or offset GIF frame descriptor")
        local_packed = data[offset + 8]
        offset += 9
        if local_packed & 0x80:
            offset += 3 * (2 ** ((local_packed & 0x07) + 1))
        if offset >= len(data):
            _fail(f"{label} has a truncated GIF image")
        offset += 1
        offset, _ = _gif_subblocks(data, offset, label)
        frames += 1
        if pending_delay is None:
            _fail(f"{label} has a frame without an explicit duration")
        frame_delays.append(pending_delay)
        pending_delay = None
    if not terminated or width < 1 or height < 1 or frames < 1:
        _fail(f"{label} has invalid GIF dimensions, frames, or terminator")
    if pending_delay is not None:
        _fail(f"{label} has an unused GIF control extension")
    if (
        frames != 3
        or any(delay < 800 for delay in frame_delays)
        or sum(frame_delays) > 5_000
    ):
        _fail(f"{label} violates the bounded accessible animation contract")
    return width, height, frames, tuple(frame_delays), "\n".join(comments)


def _validate_frame_fidelity(
    reference: bytes,
    actual: bytes,
    *,
    width: int,
    height: int,
    label: str,
) -> None:
    expected_size = width * height * 3
    if len(reference) != expected_size or len(actual) != expected_size:
        _fail(f"{label} has an invalid RGB frame size")

    tile_total_error = [0] * (_FIDELITY_COLUMNS * _FIDELITY_ROWS)
    tile_bad_pixels = [0] * (_FIDELITY_COLUMNS * _FIDELITY_ROWS)
    tile_pixels = [0] * (_FIDELITY_COLUMNS * _FIDELITY_ROWS)
    delta_histogram = [0] * 256
    total_error = 0
    bad_pixels = 0
    maximum_delta = 0
    reference_view = memoryview(reference)
    actual_view = memoryview(actual)

    for pixel_index in range(width * height):
        offset = pixel_index * 3
        red = abs(actual_view[offset] - reference_view[offset])
        green = abs(actual_view[offset + 1] - reference_view[offset + 1])
        blue = abs(actual_view[offset + 2] - reference_view[offset + 2])
        channel_error = red + green + blue
        maximum_channel = max(red, green, blue)
        total_error += channel_error
        maximum_delta = max(maximum_delta, maximum_channel)
        delta_histogram[maximum_channel] += 1

        y, x = divmod(pixel_index, width)
        tile_x = min(_FIDELITY_COLUMNS - 1, x * _FIDELITY_COLUMNS // width)
        tile_y = min(_FIDELITY_ROWS - 1, y * _FIDELITY_ROWS // height)
        tile_index = tile_y * _FIDELITY_COLUMNS + tile_x
        tile_total_error[tile_index] += channel_error
        tile_pixels[tile_index] += 1
        if maximum_channel > _FIDELITY_BAD_DELTA:
            bad_pixels += 1
            tile_bad_pixels[tile_index] += 1

    pixel_count = width * height
    global_mae = total_error / (pixel_count * 3)
    global_bad_ratio = bad_pixels / pixel_count
    maximum_tile_mae = max(
        error / (count * 3)
        for error, count in zip(tile_total_error, tile_pixels, strict=True)
    )
    maximum_tile_bad_ratio = max(
        bad / count for bad, count in zip(tile_bad_pixels, tile_pixels, strict=True)
    )

    percentile_rank = (999 * (pixel_count - 1) + 999) // 1_000 + 1
    cumulative = 0
    percentile_delta = 0
    for delta, count in enumerate(delta_histogram):
        cumulative += count
        if cumulative >= percentile_rank:
            percentile_delta = delta
            break

    if (
        global_mae > _FIDELITY_MAX_GLOBAL_MAE
        or global_bad_ratio > _FIDELITY_MAX_GLOBAL_BAD_RATIO
        or maximum_tile_mae > _FIDELITY_MAX_TILE_MAE
        or maximum_tile_bad_ratio > _FIDELITY_MAX_TILE_BAD_RATIO
        or maximum_delta > _FIDELITY_MAX_CHANNEL_DELTA
        or percentile_delta > _FIDELITY_MAX_P999_DELTA
    ):
        _fail(f"{label} fails localized GIF fidelity limits")


def _validate_gif_fidelity(root: Path) -> None:
    reference_path = root / GIF_REFERENCE_PATH
    gif_path = root / "docs/assets/web-validation-demo.gif"
    try:
        with Image.open(reference_path) as reference_image:
            reference = reference_image.convert("RGB")
        with Image.open(gif_path) as gif:
            frame_count = cast(int, getattr(gif, "n_frames", 1))
            if frame_count != 3 or gif.size != (1_080, 900):
                _fail("validation GIF has an invalid decoded frame contract")
            if reference.size != (1_080, 2_700):
                _fail("validation GIF reference must contain three vertical frames")
            for frame_index in range(3):
                gif.seek(frame_index)
                actual = gif.convert("RGB")
                expected = reference.crop(
                    (0, frame_index * 900, 1_080, (frame_index + 1) * 900)
                )
                _validate_frame_fidelity(
                    expected.tobytes(),
                    actual.tobytes(),
                    width=1_080,
                    height=900,
                    label=f"validation GIF frame {frame_index + 1}",
                )
    except EvidenceValidationError:
        raise
    except (OSError, SyntaxError, ValueError):
        _fail("validation GIF or its lossless reference cannot be decoded")


def _svg_info(data: bytes, label: str) -> tuple[str, int, int]:
    lowered = data.lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        _fail(f"{label} contains a forbidden XML declaration")
    try:
        root = ElementTree.fromstring(data)
    except ElementTree.ParseError:
        _fail(f"{label} is not valid SVG XML")
    if not root.tag.endswith("svg"):
        _fail(f"{label} does not have an SVG root")
    try:
        width = int(root.attrib["width"])
        height = int(root.attrib["height"])
    except (KeyError, ValueError):
        _fail(f"{label} must declare integer SVG dimensions")
    if not 1 <= width <= 20_000 or not 1 <= height <= 20_000:
        _fail(f"{label} has invalid SVG dimensions")
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1].lower()
        if local_name in {"foreignobject", "script"}:
            _fail(f"{label} contains executable or foreign content")
        for key, value in element.attrib.items():
            attribute = key.rsplit("}", 1)[-1].lower()
            if attribute == "href" and not value.startswith("#"):
                _fail(f"{label} contains an external reference")
            if "url(" in value.lower() and "url(#" not in value.lower():
                _fail(f"{label} contains an external resource")
    return html.unescape(" ".join(root.itertext())), width, height


def _expected_sweep() -> str:
    lines = [",".join(SWEEP_COLUMNS)]
    for length in range(8, 33):
        report = inspect_policy(visible_ascii_policy(length))
        row = (
            length,
            report.policy_sha256,
            report.valid,
            report.unconstrained,
            report.excluded,
            report.fraction_numerator,
            report.fraction_denominator,
            report.entropy_bits_floor,
            report.entropy_bits_ceiling,
            report.dp_cells_upper_bound,
            report.dp_transitions_upper_bound,
        )
        lines.append(",".join(str(value) for value in row))
    return "\n".join(lines) + "\n"


def _expected_inspection(report: StateSpaceInspection) -> str:
    policy = report.policy
    lines = [
        f"report_schema_version: {REPORT_SCHEMA_VERSION}",
        f"rank_order_version: {RANK_ORDER_VERSION}",
        f"policy_sha256: {report.policy_sha256}",
        f"profile: {VISIBLE_ASCII_PROFILE}",
        f"length: {policy.length}",
        f"alphabet_size: {len(policy.alphabet)}",
        f"minimum_total: {sum(policy.minima)}",
    ]
    lines.extend(
        f"class.{item.name}: size={len(item.symbols)} minimum={item.minimum}"
        for item in policy.classes
    )
    lines.extend(
        (
            f"valid: {report.valid}",
            f"unconstrained: {report.unconstrained}",
            f"excluded: {report.excluded}",
            (
                "satisfying_fraction: "
                f"{report.fraction_numerator}/{report.fraction_denominator}"
            ),
            "rank_minimum: 0",
            f"rank_maximum: {report.valid - 1}",
            f"uniform_candidate_probability: 1/{report.valid}",
            f"entropy_bits_floor: {report.entropy_bits_floor}",
            f"entropy_bits_ceiling: {report.entropy_bits_ceiling}",
            (
                "deficit_vectors_upper_bound_per_layer: "
                f"{report.deficit_vectors_upper_bound_per_layer}"
            ),
            f"dp_cells_upper_bound: {report.dp_cells_upper_bound}",
            f"dp_transitions_upper_bound: {report.dp_transitions_upper_bound}",
        )
    )
    return "\n".join(lines) + "\n"


def _validate_source_files(
    root: Path,
    value: object,
) -> None:
    entries = _sequence(value, "source_files")
    paths: list[str] = []
    for index, raw_entry in enumerate(entries):
        label = f"source_files[{index}]"
        entry = _mapping(raw_entry, label)
        _exact_keys(entry, {"path", "sha256"}, label)
        path, destination = _safe_path(root, entry["path"], f"{label}.path")
        digest = _string(entry["sha256"], f"{label}.sha256")
        if _SHA256.fullmatch(digest) is None:
            _fail(f"{label}.sha256 is not a lowercase SHA-256")
        data = _read_bounded(destination, path)
        if _sha256(data) != digest:
            _fail(f"source digest mismatch: {path}")
        paths.append(path)
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        _fail("source_files paths must be unique and sorted")
    expected = {
        "MANIFEST.in",
        "Makefile",
        "PACKAGE.md",
        "README.md",
        "app.py",
        "pyproject.toml",
    }
    for directory_name in ("scripts", "src", "tests"):
        directory = root / directory_name
        if not directory.is_dir():
            _fail("a required source directory is missing")
        expected.update(
            path.relative_to(root).as_posix()
            for path in directory.rglob("*")
            if path.is_file()
            and not path.is_symlink()
            and path.suffix in {".css", ".html", ".py", ".typed"}
            and "__pycache__" not in path.parts
        )
    if set(paths) != expected:
        _fail("source_files does not match the exact reproducibility input set")


def _validate_runtime(value: object) -> None:
    runtime = _mapping(value, "runtime")
    _exact_keys(
        runtime,
        {
            "chromium",
            "flask",
            "matplotlib",
            "numpy",
            "pillow",
            "platform",
            "playwright",
            "python",
            "waitress",
        },
        "runtime",
    )
    for key, raw_version in runtime.items():
        version = _string(raw_version, f"runtime.{key}")
        _validate_safe_text(version, f"runtime.{key}")
    platform_value = cast(str, runtime["platform"])
    if (
        re.fullmatch(
            r"(?:aix|darwin|freebsd|linux|openbsd|win32)/"
            r"[a-z0-9][a-z0-9._-]{1,31}",
            platform_value,
        )
        is None
    ):
        _fail("runtime.platform must use normalized platform/machine names")


def _validate_string_list(value: object, label: str) -> list[str]:
    values = [
        _string(item, f"{label}[{index}]")
        for index, item in enumerate(_sequence(value, label))
    ]
    if len(values) != len(set(values)):
        _fail(f"{label} contains duplicate entries")
    for item in values:
        _validate_safe_text(item, label)
    return values


def _validate_capture(value: object) -> dict[str, tuple[int, int]]:
    capture = _mapping(value, "capture")
    _exact_keys(
        capture,
        {
            "chromium_launch_args",
            "requests",
            "sampler_calls",
            "sampling_guard",
            "server",
        },
        "capture",
    )
    launch_arguments = _validate_string_list(
        capture["chromium_launch_args"],
        "capture.chromium_launch_args",
    )
    if launch_arguments != ["--num-raster-threads=1"]:
        _fail("capture must pin Chromium to one raster thread")
    server = _string(capture["server"], "capture.server")
    _validate_safe_text(server, "capture.server")
    if server != "waitress":
        _fail("capture.server must record the guarded Waitress server")
    if capture["sampling_guard"] != "raise-on-call":
        _fail("capture.sampling_guard must be raise-on-call")
    if capture["sampler_calls"] != 0:
        _fail("capture.sampler_calls must be zero")

    expected = (
        (
            "docs/assets/web-home.png",
            "GET",
            200,
            {
                "generated-output absent",
                "sampler calls 0",
                "external requests 0",
                "inspection visible",
                "no horizontal overflow",
            },
        ),
        (
            "docs/assets/web-home-mobile.png",
            "GET",
            200,
            {
                "generated-output absent",
                "sampler calls 0",
                "external requests 0",
                "inspection visible",
                "no horizontal overflow",
                "workspace visible at mobile width",
            },
        ),
        (
            "docs/assets/web-invalid-length.png",
            "POST",
            400,
            {
                "generated-output absent",
                "sampler calls 0",
                "external requests 0",
                "invalid length 7 rejected before generation",
                "audit metrics withheld",
                "no horizontal overflow",
            },
        ),
        (
            "docs/assets/web-validation-demo.gif",
            "GET -> POST",
            400,
            {
                "generated-output absent",
                "sampler calls 0",
                "external requests 0",
                "sequence GET 200 -> input 7 -> POST 400",
                "audit metrics withheld",
            },
        ),
    )
    expected_by_artifact = {item[0]: item[1:] for item in expected}
    requests = _sequence(capture["requests"], "capture.requests")
    observed: list[str] = []
    viewports: dict[str, tuple[int, int]] = {}
    for index, raw_request in enumerate(requests):
        label = f"capture.requests[{index}]"
        request = _mapping(raw_request, label)
        _exact_keys(
            request,
            {"artifact", "assertions", "method", "path", "status", "viewport"},
            label,
        )
        artifact = _string(request["artifact"], f"{label}.artifact")
        observed.append(artifact)
        if artifact not in expected_by_artifact:
            _fail(f"{label}.artifact is not a capture artifact")
        method, status, required_assertions = expected_by_artifact[artifact]
        if request["method"] != method or request["path"] != "/":
            _fail(f"{label} records the wrong request")
        if request["status"] != status:
            _fail(f"{label} records the wrong response status")
        viewport = _mapping(request["viewport"], f"{label}.viewport")
        _exact_keys(viewport, {"height", "width"}, f"{label}.viewport")
        width = _integer(
            viewport["width"],
            f"{label}.viewport.width",
            minimum=1,
        )
        height = _integer(
            viewport["height"],
            f"{label}.viewport.height",
            minimum=1,
        )
        if width > 3_840 or height > 2_160:
            _fail(f"{label}.viewport exceeds the bounded capture size")
        if (width, height) != CAPTURE_VIEWPORTS[artifact]:
            _fail(f"{label}.viewport does not match the capture contract")
        assertions = set(
            _validate_string_list(request["assertions"], f"{label}.assertions")
        )
        if not required_assertions.issubset(assertions):
            _fail(f"{label} omits a required DOM or network assertion")
        viewports[artifact] = (width, height)
    if observed != [item[0] for item in expected]:
        _fail("capture.requests must contain every capture in scenario order")
    return viewports


def _validate_evidence_claims(value: object) -> None:
    evidence = _mapping(value, "evidence")
    _exact_keys(
        evidence,
        {"cli_inspect", "diagrams", "quality_gate", "sweep"},
        "evidence",
    )

    sweep = _mapping(evidence["sweep"], "evidence.sweep")
    _exact_keys(
        sweep,
        {
            "class_minima",
            "inclusive_range",
            "profile",
            "rows",
            "source_command",
        },
        "evidence.sweep",
    )
    if sweep["source_command"] != SWEEP_COMMAND:
        _fail("evidence.sweep.source_command is not canonical")
    if sweep["profile"] != VISIBLE_ASCII_PROFILE:
        _fail("evidence.sweep.profile is incorrect")
    inclusive_range = _mapping(
        sweep["inclusive_range"],
        "evidence.sweep.inclusive_range",
    )
    _exact_keys(inclusive_range, {"end", "start"}, "evidence.sweep.inclusive_range")
    if inclusive_range != {"start": 8, "end": 32} or sweep["rows"] != 25:
        _fail("evidence.sweep does not describe the inclusive 8..32 sweep")
    minima = _mapping(sweep["class_minima"], "evidence.sweep.class_minima")
    if minima != {"digits": 1, "lower": 1, "punctuation": 1, "upper": 1}:
        _fail("evidence.sweep.class_minima is incorrect")

    cli_inspect = _mapping(evidence["cli_inspect"], "evidence.cli_inspect")
    _exact_keys(
        cli_inspect,
        {"contains_candidate", "source_command"},
        "evidence.cli_inspect",
    )
    if cli_inspect["source_command"] != INSPECT_COMMAND:
        _fail("evidence.cli_inspect.source_command is not canonical")
    if _boolean(
        cli_inspect["contains_candidate"],
        "evidence.cli_inspect.contains_candidate",
    ):
        _fail("evidence.cli_inspect must not contain a candidate")

    quality = _mapping(evidence["quality_gate"], "evidence.quality_gate")
    _exact_keys(
        quality,
        {"all_passed", "commands"},
        "evidence.quality_gate",
    )
    commands = _validate_string_list(
        quality["commands"],
        "evidence.quality_gate.commands",
    )
    if commands != list(QUALITY_COMMANDS):
        _fail("evidence.quality_gate.commands is not the exact gate")
    if not _boolean(quality["all_passed"], "evidence.quality_gate.all_passed"):
        _fail("evidence.quality_gate must record passing commands")

    diagrams = _mapping(evidence["diagrams"], "evidence.diagrams")
    _exact_keys(
        diagrams,
        {"architecture_ast_verified", "sampling_ast_verified"},
        "evidence.diagrams",
    )
    if not all(_boolean(diagrams[key], f"evidence.diagrams.{key}") for key in diagrams):
        _fail("evidence.diagrams must record successful AST verification")


def _artifact_inventory(root: Path) -> set[str]:
    inventory: set[str] = set()
    for directory in (root / "docs/assets", root / "docs/evidence"):
        if not directory.is_dir():
            _fail("evidence output directories are missing")
        for path in directory.rglob("*"):
            if path.is_symlink():
                _fail("evidence output must not contain symbolic links")
            if path.is_file():
                inventory.add(path.relative_to(root).as_posix())
    return inventory


def _validate_artifacts(
    root: Path,
    value: object,
    viewports: dict[str, tuple[int, int]],
) -> dict[str, str]:
    entries = _sequence(value, "artifacts")
    observed: list[str] = []
    textual: dict[str, str] = {}
    for index, raw_entry in enumerate(entries):
        label = f"artifacts[{index}]"
        entry = _mapping(raw_entry, label)
        required = {"assertions", "bytes", "media_type", "path", "sha256"}
        allowed = required | {"frames", "height", "width"}
        if not required.issubset(entry) or not set(entry).issubset(allowed):
            _fail(f"{label} has an unexpected schema")
        path, destination = _safe_path(root, entry["path"], f"{label}.path")
        observed.append(path)
        if path not in EXPECTED_ARTIFACTS:
            _fail(f"{label}.path is not a required artifact")
        expected_media = MEDIA_TYPES[Path(path).suffix]
        if entry["media_type"] != expected_media:
            _fail(f"{label}.media_type is incorrect")
        digest = _string(entry["sha256"], f"{label}.sha256")
        if _SHA256.fullmatch(digest) is None:
            _fail(f"{label}.sha256 is not a lowercase SHA-256")
        declared_size = _integer(entry["bytes"], f"{label}.bytes", minimum=1)
        assertions = _validate_string_list(
            entry["assertions"],
            f"{label}.assertions",
        )
        if not assertions:
            _fail(f"{label}.assertions must document the artifact provenance")
        if path == GIF_REFERENCE_PATH and (
            "vertical frame order GET 200 -> input 7 -> POST 400" not in assertions
        ):
            _fail(f"{label}.assertions omits the reference frame order")

        data = _read_bounded(destination, path)
        if len(data) != declared_size:
            _fail(f"artifact byte-size mismatch: {path}")
        if _sha256(data) != digest:
            _fail(f"artifact digest mismatch: {path}")

        suffix = Path(path).suffix
        if suffix == ".png":
            width, height, metadata = _png_info(data, path)
            textual[path] = metadata
            if set(entry) != allowed - {"frames"}:
                _fail(f"{label} must record PNG dimensions")
            if entry["width"] != width or entry["height"] != height:
                _fail(f"artifact dimension mismatch: {path}")
            if path == GIF_REFERENCE_PATH and (width, height) != (1_080, 2_700):
                _fail("validation GIF reference dimensions are incorrect")
        elif suffix == ".gif":
            width, height, frames, _, comments = _gif_info(data, path)
            textual[path] = comments
            if set(entry) != allowed:
                _fail(f"{label} must record GIF dimensions and frames")
            if (
                entry["width"] != width
                or entry["height"] != height
                or entry["frames"] != frames
            ):
                _fail(f"artifact GIF metadata mismatch: {path}")
            if len(data) >= 8 * 1024 * 1024:
                _fail(f"GIF exceeds the portfolio size bound: {path}")
        elif suffix == ".svg":
            svg_text, width, height = _svg_info(data, path)
            textual[path] = svg_text
            if set(entry) != allowed - {"frames"}:
                _fail(f"{label} must record SVG dimensions")
            if entry["width"] != width or entry["height"] != height:
                _fail(f"artifact dimension mismatch: {path}")
        else:
            if set(entry) != required:
                _fail(f"{label} has dimensions on a non-image artifact")
            try:
                textual[path] = data.decode("utf-8")
            except UnicodeDecodeError:
                _fail(f"{path} must be UTF-8")

        if path in viewports:
            viewport_width, viewport_height = viewports[path]
            actual_width = _integer(entry["width"], f"{label}.width", minimum=1)
            actual_height = _integer(entry["height"], f"{label}.height", minimum=1)
            if actual_width != viewport_width or actual_height < viewport_height:
                _fail(f"capture viewport is inconsistent with artifact: {path}")
            if (
                path
                in {
                    "docs/assets/web-home-mobile.png",
                    "docs/assets/web-validation-demo.gif",
                }
                and actual_height != viewport_height
            ):
                _fail(f"bounded capture dimensions do not equal its viewport: {path}")

    if observed != sorted(EXPECTED_ARTIFACTS):
        _fail("artifacts paths must contain the exact sorted output set")
    if _artifact_inventory(root) != EXPECTED_ARTIFACTS | {MANIFEST_PATH}:
        _fail("docs contains untracked, missing, or extra evidence output")
    return textual


def _validate_raw_evidence(textual: dict[str, str]) -> None:
    sweep = textual["docs/evidence/state-space-sweep.csv"]
    if sweep != _expected_sweep():
        _fail("state-space sweep does not match the exact core")
    try:
        rows = list(csv.DictReader(io.StringIO(sweep)))
    except csv.Error:
        _fail("state-space sweep is not valid CSV")
    if tuple(rows[0]) != SWEEP_COLUMNS or [int(row["length"]) for row in rows] != list(
        range(8, 33)
    ):
        _fail("state-space sweep columns or lengths are incorrect")

    inspection = textual["docs/evidence/cli-inspect.txt"]
    if inspection != _expected_inspection(inspect_policy(visible_ascii_policy(20))):
        _fail("CLI inspection transcript does not match the exact core")

    quality = textual["docs/evidence/quality-gate.txt"]
    if not quality.endswith("\n") or not quality.strip():
        _fail("quality-gate transcript must be nonempty and newline-terminated")
    command_offsets = [quality.find(command) for command in QUALITY_COMMANDS]
    if any(offset < 0 for offset in command_offsets) or command_offsets != sorted(
        command_offsets
    ):
        _fail("quality-gate transcript omits ordered command headers")


def _distribution_input_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in DISTRIBUTION_INPUTS:
        data = _read_bounded(
            root.joinpath(*relative.split("/")),
            relative,
            maximum=2 * 1024 * 1024,
        )
        encoded_path = relative.encode("ascii")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
    return digest.hexdigest()


def _distribution_sha(value: object, label: str) -> str:
    digest = _string(value, label)
    if _SHA256.fullmatch(digest) is None:
        _fail(f"{label} is not a lowercase SHA-256")
    return digest


def _sdist_inventory_plan() -> tuple[tuple[str, ...], frozenset[str]]:
    directories = {_DISTRIBUTION_ROOT}
    files: set[str] = set()
    for relative in _SDIST_FILES:
        full_name = f"{_DISTRIBUTION_ROOT}/{relative}"
        files.add(full_name)
        components = full_name.split("/")
        for length in range(1, len(components)):
            directories.add("/".join(components[:length]))
    return tuple(sorted(directories | files)), frozenset(directories)


def _validate_distribution_inventory(
    root: Path,
    value: object,
    *,
    kind: str,
) -> None:
    entries = _sequence(value, f"distribution.artifacts.{kind}.inventory")
    expected_names: tuple[str, ...]
    directories: frozenset[str]
    if kind == "wheel":
        expected_names = _WHEEL_MEMBERS
        directories = frozenset()
        source_names = {
            path.removeprefix("src/"): path for path in DISTRIBUTION_INPUTS[3:]
        }
    else:
        expected_names, directories = _sdist_inventory_plan()
        source_names = {
            f"{_DISTRIBUTION_ROOT}/{path}": path for path in DISTRIBUTION_INPUTS
        }
    observed: list[str] = []
    empty_digest = hashlib.sha256(b"").hexdigest()
    for index, raw_entry in enumerate(entries):
        label = f"distribution.artifacts.{kind}.inventory[{index}]"
        entry = _mapping(raw_entry, label)
        _exact_keys(
            entry,
            {"compressed_size", "mode", "mtime", "name", "sha256", "size"},
            label,
        )
        name = _string(entry["name"], f"{label}.name")
        observed.append(name)
        is_directory = name in directories
        expected_mode = "0755" if is_directory else "0644"
        if entry["mode"] != expected_mode:
            _fail(f"{label}.mode is not canonical")
        if entry["mtime"] != _FIXED_DISTRIBUTION_MTIME:
            _fail(f"{label}.mtime is not canonical")
        size = _integer(entry["size"], f"{label}.size")
        digest = _distribution_sha(entry["sha256"], f"{label}.sha256")
        if kind == "wheel":
            _integer(
                entry["compressed_size"],
                f"{label}.compressed_size",
                minimum=1,
            )
        elif entry["compressed_size"] is not None:
            _fail(f"{label}.compressed_size must be null for tar members")
        if is_directory and (size != 0 or digest != empty_digest):
            _fail(f"{label} has invalid canonical directory facts")
        source_path = source_names.get(name)
        if source_path is not None:
            source_data = _read_bounded(
                root.joinpath(*source_path.split("/")),
                source_path,
                maximum=2 * 1024 * 1024,
            )
            if size != len(source_data) or digest != _sha256(source_data):
                _fail(f"{label} does not match its repository source")
    if tuple(observed) != expected_names:
        _fail(f"distribution.artifacts.{kind}.inventory is not exact and ordered")


def _validate_distribution_artifact(
    root: Path,
    value: object,
    *,
    kind: str,
) -> str:
    artifact = _mapping(value, f"distribution.artifacts.{kind}")
    common = {
        "canonical_builds_byte_equal",
        "filename",
        "inventory",
        "member_count",
        "raw_build_count",
        "sha256",
        "size",
    }
    extra = (
        {"raw_builds_byte_equal", "sdist_rebuild_byte_equal"}
        if kind == "wheel"
        else {"raw_builds_byte_equality_claimed"}
    )
    _exact_keys(artifact, common | extra, f"distribution.artifacts.{kind}")
    expected_count = 17 if kind == "wheel" else 29
    expected_filename = (
        "password_policy_state_space-0.1.0-py3-none-any.whl"
        if kind == "wheel"
        else "password_policy_state_space-0.1.0.tar.gz"
    )
    if artifact["filename"] != expected_filename:
        _fail(f"distribution.artifacts.{kind}.filename is incorrect")
    if artifact["member_count"] != expected_count:
        _fail(f"distribution.artifacts.{kind}.member_count is incorrect")
    if artifact["raw_build_count"] != 2:
        _fail(f"distribution.artifacts.{kind}.raw_build_count is incorrect")
    if not _boolean(
        artifact["canonical_builds_byte_equal"],
        f"distribution.artifacts.{kind}.canonical_builds_byte_equal",
    ):
        _fail(f"distribution.artifacts.{kind} canonical builds did not match")
    if kind == "wheel":
        if not _boolean(
            artifact["raw_builds_byte_equal"],
            "distribution.artifacts.wheel.raw_builds_byte_equal",
        ) or not _boolean(
            artifact["sdist_rebuild_byte_equal"],
            "distribution.artifacts.wheel.sdist_rebuild_byte_equal",
        ):
            _fail("distribution wheel equality claims are not proven")
    elif _boolean(
        artifact["raw_builds_byte_equality_claimed"],
        "distribution.artifacts.sdist.raw_builds_byte_equality_claimed",
    ):
        _fail("raw sdist byte equality must remain unclaimed")
    size = _integer(artifact["size"], f"distribution.artifacts.{kind}.size", minimum=1)
    if size > 5 * 1024 * 1024:
        _fail(f"distribution.artifacts.{kind}.size exceeds the contract")
    digest = _distribution_sha(
        artifact["sha256"],
        f"distribution.artifacts.{kind}.sha256",
    )
    _validate_distribution_inventory(root, artifact["inventory"], kind=kind)
    return digest


def _expected_distribution_transcript(document: dict[str, object]) -> str:
    artifacts = _mapping(document["artifacts"], "distribution.artifacts")
    wheel = _mapping(artifacts["wheel"], "distribution.artifacts.wheel")
    sdist = _mapping(artifacts["sdist"], "distribution.artifacts.sdist")
    source = _mapping(document["source"], "distribution.source")
    return (
        "$ python scripts/attest_distribution.py\n"
        "distribution attestation: PASS (unofficial)\n"
        f"source: {source['distribution_input_count']} indexed inputs; "
        f"sha256={source['distribution_input_sha256']}\n"
        f"wheel: sha256={wheel['sha256']}; "
        "two builds and sdist rebuild match\n"
        f"sdist: sha256={sdist['sha256']}; "
        "two canonical builds match (raw equality unclaimed)\n"
        "smoke: deterministic inspect passed; no password sampled\n"
        "boundaries: no license, signature, dependency-integrity, "
        "cross-platform, or arbitrary-archive claim\n"
    )


def _validate_distribution_attestation(
    root: Path,
    document: dict[str, object],
    json_text: str,
    transcript: str,
    diagram: str,
) -> None:
    _exact_keys(
        document,
        {
            "artifacts",
            "build",
            "claim_boundaries",
            "official",
            "schema_version",
            "smoke",
            "source",
            "toolchain",
        },
        "distribution",
    )
    if document["schema_version"] != 1:
        _fail("distribution.schema_version must be 1")
    if _boolean(document["official"], "distribution.official"):
        _fail("distribution attestation must remain unofficial")

    artifacts = _mapping(document["artifacts"], "distribution.artifacts")
    _exact_keys(artifacts, {"sdist", "wheel"}, "distribution.artifacts")
    wheel_sha = _validate_distribution_artifact(
        root,
        artifacts["wheel"],
        kind="wheel",
    )
    sdist_sha = _validate_distribution_artifact(
        root,
        artifacts["sdist"],
        kind="sdist",
    )

    build = _mapping(document["build"], "distribution.build")
    _exact_keys(
        build,
        {
            "build_count",
            "build_isolation",
            "fixed_source_date_epoch",
            "locale",
            "network_package_index_enabled",
            "timezone",
            "umask",
        },
        "distribution.build",
    )
    if (
        build["build_count"] != 2
        or build["fixed_source_date_epoch"] != _FIXED_DISTRIBUTION_MTIME
        or build["locale"] != "C.UTF-8"
        or build["timezone"] != "UTC"
        or build["umask"] != "0022"
        or _boolean(build["build_isolation"], "distribution.build.build_isolation")
        or _boolean(
            build["network_package_index_enabled"],
            "distribution.build.network_package_index_enabled",
        )
    ):
        _fail("distribution.build does not match the reproducible build contract")

    boundaries = _mapping(
        document["claim_boundaries"],
        "distribution.claim_boundaries",
    )
    boundary_keys = {
        "arbitrary_archive_safety",
        "artifact_signature_verified",
        "cross_platform_reproducibility",
        "dependency_integrity_verified",
        "fresh_dependency_environment",
        "license_declared",
    }
    _exact_keys(boundaries, boundary_keys, "distribution.claim_boundaries")
    if any(
        _boolean(boundaries[key], f"distribution.claim_boundaries.{key}")
        for key in boundary_keys
    ):
        _fail("distribution claim boundaries must all remain false")

    source = _mapping(document["source"], "distribution.source")
    _exact_keys(
        source,
        {
            "distribution_input_count",
            "distribution_input_sha256",
            "git_index_stage",
        },
        "distribution.source",
    )
    input_sha = _distribution_sha(
        source["distribution_input_sha256"],
        "distribution.source.distribution_input_sha256",
    )
    if source["distribution_input_count"] != 15 or source["git_index_stage"] != 0:
        _fail("distribution source cardinality or index stage is incorrect")
    if input_sha != _distribution_input_digest(root):
        _fail("distribution input digest does not match repository sources")

    toolchain = _mapping(document["toolchain"], "distribution.toolchain")
    _exact_keys(toolchain, {"build", "python", "setuptools"}, "distribution.toolchain")
    python_version = _string(toolchain["python"], "distribution.toolchain.python")
    if (
        toolchain["build"] != "1.5.0"
        or toolchain["setuptools"] != "83.0.0"
        or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", python_version) is None
    ):
        _fail("distribution.toolchain is not the pinned checker toolchain")

    smoke = _mapping(document["smoke"], "distribution.smoke")
    _exact_keys(
        smoke,
        {
            "command",
            "current_checker_dependencies",
            "dependency_install_mode",
            "deterministic",
            "inspect_sha256",
            "metadata_origin_in_target",
            "package_origin_in_target",
            "pip_compile_bytecode",
            "pip_dependency_resolution",
            "pip_index_enabled",
            "resources_present",
            "sampled_password",
        },
        "distribution.smoke",
    )
    dependencies = _mapping(
        smoke["current_checker_dependencies"],
        "distribution.smoke.current_checker_dependencies",
    )
    if dependencies != {"Flask": "3.1.3", "waitress": "3.0.2"}:
        _fail("distribution smoke dependencies are not the pinned checker versions")
    if (
        smoke["command"] != "inspect --length 20 --format json"
        or smoke["dependency_install_mode"] != "current-pinned-checker-environment"
        or not _boolean(smoke["deterministic"], "distribution.smoke.deterministic")
        or not _boolean(
            smoke["metadata_origin_in_target"],
            "distribution.smoke.metadata_origin_in_target",
        )
        or not _boolean(
            smoke["package_origin_in_target"],
            "distribution.smoke.package_origin_in_target",
        )
        or not _boolean(
            smoke["resources_present"],
            "distribution.smoke.resources_present",
        )
        or _boolean(
            smoke["pip_compile_bytecode"],
            "distribution.smoke.pip_compile_bytecode",
        )
        or _boolean(
            smoke["pip_dependency_resolution"],
            "distribution.smoke.pip_dependency_resolution",
        )
        or _boolean(smoke["pip_index_enabled"], "distribution.smoke.pip_index_enabled")
        or _boolean(smoke["sampled_password"], "distribution.smoke.sampled_password")
    ):
        _fail("distribution smoke facts do not match the installed-target contract")
    _distribution_sha(smoke["inspect_sha256"], "distribution.smoke.inspect_sha256")

    _validate_safe_text(json_text, "distribution attestation")
    if transcript != _expected_distribution_transcript(document):
        _fail("distribution transcript does not agree with its canonical JSON")
    required_diagram_terms = {
        "15 stage-zero git blobs",
        "17 exact members",
        "23 files + 6 directories",
        "installed smoke",
        "official: false",
        input_sha[:16],
        wheel_sha[:16],
        sdist_sha[:16],
    }
    folded_diagram = diagram.casefold()
    if any(term not in folded_diagram for term in required_diagram_terms):
        _fail("distribution diagram omits a measured fact or claim boundary")


def _module_tree(root: Path, module: str) -> ast.Module:
    path = root / "src" / Path(*module.split(".")).with_suffix(".py")
    try:
        return ast.parse(path.read_text(encoding="utf-8"), filename=module)
    except (OSError, UnicodeError, SyntaxError):
        _fail(f"AST source is unavailable or invalid: {module}")


def _import_targets(tree: ast.Module) -> set[str]:
    targets: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            targets.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            targets.add(node.module)
    return targets


def _named_function(
    tree: ast.Module,
    name: str,
    *,
    class_name: str | None = None,
) -> ast.FunctionDef:
    parent: ast.AST = tree
    if class_name is not None:
        classes = [
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef) and node.name == class_name
        ]
        if len(classes) != 1:
            _fail(f"AST claim target is missing: {class_name}")
        parent = classes[0]
    functions = [
        node
        for node in cast(ast.Module | ast.ClassDef, parent).body
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    if len(functions) != 1:
        _fail(f"AST claim target is missing or ambiguous: {name}")
    return functions[0]


def _is_attribute(node: ast.AST, owner: str, attribute: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and node.value.id == owner
        and node.attr == attribute
    )


def _validate_ast_claims(root: Path, textual: dict[str, str]) -> None:
    modules = {
        name: _module_tree(root, name)
        for name in (
            "password_policy_lab.cli",
            "password_policy_lab.inspection",
            "password_policy_lab.space",
            "password_policy_lab.web",
        )
    }
    required_imports = {
        "password_policy_lab.cli": {
            "password_policy_lab.inspection",
            "password_policy_lab.policy",
            "password_policy_lab.profiles",
            "password_policy_lab.space",
        },
        "password_policy_lab.inspection": {
            "password_policy_lab.policy",
            "password_policy_lab.space",
        },
        "password_policy_lab.space": {
            "password_policy_lab.errors",
            "password_policy_lab.policy",
            "secrets",
        },
        "password_policy_lab.web": {
            "password_policy_lab.inspection",
            "password_policy_lab.policy",
            "password_policy_lab.profiles",
            "password_policy_lab.space",
        },
    }
    for module, expected in required_imports.items():
        if not expected.issubset(_import_targets(modules[module])):
            _fail(f"architecture import claim is stale: {module}")

    sample = _named_function(
        modules["password_policy_lab.space"],
        "sample_uniform",
        class_name="PasswordSpace",
    )
    executable = [
        node
        for node in sample.body
        if not (
            isinstance(node, ast.Expr)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        )
    ]
    if len(executable) != 1 or not isinstance(executable[0], ast.Return):
        _fail("sample_uniform no longer has one auditable return")
    returned = executable[0].value
    if (
        not isinstance(returned, ast.Call)
        or not _is_attribute(returned.func, "self", "unrank")
        or len(returned.args) != 1
        or not isinstance(returned.args[0], ast.Call)
        or not _is_attribute(returned.args[0].func, "secrets", "randbelow")
        or len(returned.args[0].args) != 1
        or not _is_attribute(returned.args[0].args[0], "self", "_total")
        or any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(sample))
    ):
        _fail("sampling AST claim no longer matches one randbelow then unrank")

    inspection_tree = modules["password_policy_lab.inspection"]
    if any(
        isinstance(node, ast.Attribute) and node.attr in {"randbelow", "sample_uniform"}
        for node in ast.walk(inspection_tree)
    ):
        _fail("inspection AST unexpectedly consumes entropy")

    cli_execute = _named_function(modules["password_policy_lab.cli"], "_execute")
    if any(
        (
            isinstance(node, ast.Attribute)
            and node.attr in {"randbelow", "sample_uniform"}
        )
        or (isinstance(node, ast.Name) and node.id == "secrets")
        for node in ast.walk(cli_execute)
    ):
        _fail("deterministic CLI architecture unexpectedly consumes entropy")

    web_tree = modules["password_policy_lab.web"]
    generate = next(
        (
            node
            for node in ast.walk(web_tree)
            if isinstance(node, ast.FunctionDef) and node.name == "generate_password"
        ),
        None,
    )
    index = next(
        (
            node
            for node in ast.walk(web_tree)
            if isinstance(node, ast.FunctionDef) and node.name == "index"
        ),
        None,
    )
    if generate is None or index is None:
        _fail("web architecture targets are missing")
    sample_calls = [
        node
        for node in ast.walk(generate)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "sample_uniform"
    ]
    inspect_calls = [
        node
        for node in ast.walk(generate)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "inspect_space"
    ]
    space_calls = [
        node
        for node in ast.walk(generate)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "PasswordSpace"
    ]
    validation_blocks = [node for node in generate.body if isinstance(node, ast.Try)]
    if (
        len(sample_calls) != 1
        or not _is_attribute(sample_calls[0].func, "space", "sample_uniform")
        or len(inspect_calls) != 1
        or len(inspect_calls[0].args) != 1
        or not isinstance(inspect_calls[0].args[0], ast.Name)
        or inspect_calls[0].args[0].id != "space"
        or len(space_calls) != 1
        or len(validation_blocks) != 1
        or not validation_blocks[0].handlers
        or not all(
            any(isinstance(child, ast.Return) for child in ast.walk(handler))
            for handler in validation_blocks[0].handlers
        )
        or cast(int, validation_blocks[0].end_lineno)
        >= min(
            space_calls[0].lineno,
            inspect_calls[0].lineno,
            sample_calls[0].lineno,
        )
        or not (
            space_calls[0].lineno < inspect_calls[0].lineno < sample_calls[0].lineno
        )
        or any(
            isinstance(node, ast.Attribute) and node.attr == "sample_uniform"
            for node in ast.walk(index)
        )
    ):
        _fail("web architecture no longer reuses one inspected space safely")

    index_space_calls = [
        node
        for node in ast.walk(index)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "PasswordSpace"
    ]
    index_inspect_calls = [
        node
        for node in ast.walk(index)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "inspect_space"
    ]
    if (
        len(index_space_calls) != 1
        or len(index_inspect_calls) != 1
        or len(index_inspect_calls[0].args) != 1
        or not isinstance(index_inspect_calls[0].args[0], ast.Name)
        or index_inspect_calls[0].args[0].id != "space"
    ):
        _fail("GET architecture no longer inspects one exact space")

    architecture = textual["docs/assets/architecture.svg"].casefold()
    for term in (
        "cli",
        "invalid web request",
        "inspection",
        "passwordpolicy",
        "passwordspace",
        "web",
    ):
        if term not in architecture:
            _fail("architecture diagram omits an AST-backed component")
    sampling = textual["docs/assets/uniform-sampling-flow.svg"].casefold()
    for term in ("randbelow", "unrank", "uniform"):
        if term not in sampling:
            _fail("sampling diagram omits an AST-backed step")


def _validate_readme(root: Path) -> None:
    path = root / "README.md"
    if not path.exists():
        return
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        _fail("README is unreadable")
    links = {
        (first or second).removeprefix("./").split("#", 1)[0]
        for first, second in _MARKDOWN_LINK.findall(text)
    }
    links.update(
        target.removeprefix("./").split("#", 1)[0]
        for target in _HTML_LINK.findall(text)
    )
    if not EXPECTED_ARTIFACTS.issubset(links):
        _fail("README does not link every generated evidence artifact")


def validate_evidence(root: Path) -> None:
    """Validate the complete evidence bundle rooted at one repository."""

    repository = root.resolve()
    document, manifest_text = _load_json(repository / MANIFEST_PATH)
    _exact_keys(
        document,
        {
            "artifacts",
            "capture",
            "evidence",
            "generator",
            "runtime",
            "schema_version",
            "source_files",
        },
        "manifest",
    )
    if document["schema_version"] != 1:
        _fail("manifest.schema_version must be 1")
    if document["generator"] != GENERATOR_PATH:
        _fail("manifest.generator is incorrect")
    _validate_safe_text(manifest_text, "manifest")
    _validate_source_files(repository, document["source_files"])
    _validate_runtime(document["runtime"])
    viewports = _validate_capture(document["capture"])
    _validate_evidence_claims(document["evidence"])
    textual = _validate_artifacts(repository, document["artifacts"], viewports)
    for artifact, text in textual.items():
        _validate_safe_text(text, artifact)
    distribution_document, distribution_text = _load_json(
        repository / "docs/evidence/distribution-attestation.json",
        label="distribution attestation",
    )
    if textual["docs/evidence/distribution-attestation.json"] != distribution_text:
        _fail("distribution artifact text changed between bounded reads")
    _validate_distribution_attestation(
        repository,
        distribution_document,
        distribution_text,
        textual["docs/evidence/distribution-check.txt"],
        textual["docs/assets/distribution-contract.svg"],
    )
    _validate_raw_evidence(textual)
    _validate_gif_fidelity(repository)
    _validate_ast_claims(repository, textual)
    _validate_readme(repository)


def main(argv: Sequence[str] | None = None) -> int:
    """Command-line entry point with stable, non-sensitive output."""

    parser = argparse.ArgumentParser(
        description="validate the reproducible portfolio evidence bundle",
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help=argparse.SUPPRESS,
    )
    arguments = parser.parse_args(argv)
    try:
        validate_evidence(cast(Path, arguments.root))
    except EvidenceValidationError as error:
        print(f"evidence validation failed: {error}", file=sys.stderr)
        return 1
    print("evidence validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
