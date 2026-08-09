#!/usr/bin/env python3
"""Validate the reproducible, secret-free portfolio evidence bundle."""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import html
import importlib.util
import io
import json
import re
import struct
import sys
import zlib
from collections.abc import Sequence
from functools import lru_cache
from math import prod
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, NoReturn, cast
from xml.etree import ElementTree

from PIL import Image

from password_policy_lab.inspection import (
    RANK_ORDER_VERSION,
    REPORT_SCHEMA_VERSION,
    SENSITIVITY_ANALYSIS,
    SENSITIVITY_SCHEMA_VERSION,
    PolicySensitivity,
    StateSpaceInspection,
    analyze_policy_sensitivity,
    inspect_policy,
)
from password_policy_lab.profiles import (
    VISIBLE_ASCII_PROFILE,
    visible_ascii_policy,
)
from password_policy_lab.space import MAX_DP_CELLS, MAX_DP_TRANSITIONS

MANIFEST_PATH = "docs/evidence/manifest.json"
GENERATOR_PATH = "scripts/generate_evidence.py"
COMPLEXITY_JSON_PATH = "docs/evidence/dp-complexity-profile.json"
COMPLEXITY_TEXT_PATH = "docs/evidence/dp-complexity-profile.txt"
COMPLEXITY_JSON_COMMAND = (
    "PYTHONPATH=src python scripts/profile_complexity.py --format json"
)
COMPLEXITY_TEXT_COMMAND = (
    "PYTHONPATH=src python scripts/profile_complexity.py --format text"
)
COMPLEXITY_PNG_TITLE = "Deterministic DP work profile · six fixed policies"


def _load_local_module(name: str) -> ModuleType:
    """Load one sibling evidence module without relying on caller sys.path."""

    path = Path(__file__).with_name(f"{name}.py")
    spec = importlib.util.spec_from_file_location(
        f"password_policy_evidence_{name}",
        path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"could not load local evidence module: {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


complexity_profiler = cast(Any, _load_local_module("profile_complexity"))

EXPECTED_ASSETS = frozenset(
    {
        "docs/assets/architecture.svg",
        "docs/assets/cli-inspect.png",
        "docs/assets/distribution-check.png",
        "docs/assets/distribution-contract.svg",
        "docs/assets/dp-complexity-cli.png",
        "docs/assets/dp-layer-occupancy.svg",
        "docs/assets/dp-work-counts.svg",
        "docs/assets/policy-sensitivity-cli.png",
        "docs/assets/policy-sensitivity-impact.svg",
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
        COMPLEXITY_JSON_PATH,
        COMPLEXITY_TEXT_PATH,
        "docs/evidence/policy-sensitivity.json",
        "docs/evidence/policy-sensitivity.txt",
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
SENSITIVITY_JSON_COMMAND = "password-policy-lab sensitivity --length 20 --format json"
SENSITIVITY_TEXT_COMMAND = "password-policy-lab sensitivity --length 20 --format text"
SENSITIVITY_PNG_TITLE = "Exact one-step policy sensitivity · length 20"
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

COMPLEXITY_CASE_IDS = (
    "default-visible-ascii-20",
    "balanced-visible-ascii-24",
    "skewed-visible-ascii-24",
    "near-budget-eight-class-32",
    "arbitrary-precision-one-class-256",
    "rejected-eight-class-32",
)
_COMPLEXITY_POLICIES: dict[str, tuple[int, tuple[int, ...], tuple[int, ...]]] = {
    "default-visible-ascii-20": (20, (26, 26, 10, 32), (1, 1, 1, 1)),
    "balanced-visible-ascii-24": (24, (26, 26, 10, 32), (6, 6, 6, 6)),
    "skewed-visible-ascii-24": (24, (26, 26, 10, 32), (21, 1, 1, 1)),
    "near-budget-eight-class-32": (32, (1,) * 8, (2,) * 8),
    "arbitrary-precision-one-class-256": (256, (94,), (256,)),
    "rejected-eight-class-32": (32, (1,) * 8, (3,) * 8),
}
_COMPLEXITY_ACCEPTED_WORK: dict[str, tuple[int, int, int, int, int]] = {
    "default-visible-ascii-20": (304, 1_212, 20, 320, 1_212),
    "balanced-visible-ascii-24": (31_213, 124_848, 24, 57_624, 124_848),
    "skewed-visible-ascii-24": (2_288, 9_148, 24, 4_224, 9_148),
    "near-budget-eight-class-32": (
        164_025,
        1_312_192,
        32,
        209_952,
        1_312_192,
    ),
    "arbitrary-precision-one-class-256": (33_153, 33_152, 256, 65_792, 33_152),
}

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


def _expected_sensitivity_text(report: PolicySensitivity) -> str:
    policy = report.policy
    lines = [
        f"sensitivity_schema_version: {SENSITIVITY_SCHEMA_VERSION}",
        f"analysis: {SENSITIVITY_ANALYSIS}",
        "operation: sensitivity",
        f"rank_order_version: {RANK_ORDER_VERSION}",
        f"profile: {VISIBLE_ASCII_PROFILE}",
        f"policy_sha256: {report.policy_sha256}",
        f"length: {policy.length}",
        f"alphabet_size: {len(policy.alphabet)}",
        f"baseline_valid: {report.baseline_valid}",
        "claim_boundary.one_step_only: true",
        "claim_boundary.effects_are_not_additive: true",
        "claim_boundary.contains_candidate: false",
        "claim_boundary.samples_entropy: false",
    ]
    for row in report.rows:
        prefix = f"class.{row.class_name}"
        lines.extend(
            (
                f"{prefix}.minimum: {row.original_minimum} -> {row.relaxed_minimum}",
                f"{prefix}.relaxation_applied: {str(row.relaxation_applied).lower()}",
                f"{prefix}.relaxed_policy_sha256: {row.relaxed_policy_sha256}",
                f"{prefix}.relaxed_valid: {row.relaxed_valid}",
                f"{prefix}.added_if_relaxed: {row.added_if_relaxed}",
                f"{prefix}.baseline_share_of_relaxed: "
                f"{row.baseline_fraction_numerator}/"
                f"{row.baseline_fraction_denominator}",
            )
        )
    return "
".join(lines) + "
"


def _expected_sensitivity_evidence() -> tuple[dict[str, object], str, str]:
    report = analyze_policy_sensitivity(visible_ascii_policy(20))
    mapping = report.to_mapping()
    del mapping["sensitivity_schema_version"]
    document = {
        "sensitivity_schema_version": SENSITIVITY_SCHEMA_VERSION,
        "operation": "sensitivity",
        "profile": VISIBLE_ASCII_PROFILE,
        **mapping,
    }
    json_text = json.dumps(document, ensure_ascii=True, indent=2) + "
"
    return document, json_text, _expected_sensitivity_text(report)


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
        ".github/workflows/verify.yml",
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


def _validate_complexity_envelope(value: object) -> None:
    envelope = _mapping(value, "evidence.dp_complexity_profile")
    _exact_keys(
        envelope,
        {
            "accepted_scenarios",
            "contains_candidate",
            "counter_contract",
            "json_source_command",
            "rejected_before_enumeration",
            "report_schema_version",
            "scenario_ids",
            "text_source_command",
        },
        "evidence.dp_complexity_profile",
    )
    scenario_ids = _validate_string_list(
        envelope["scenario_ids"],
        "evidence.dp_complexity_profile.scenario_ids",
    )
    if scenario_ids != list(COMPLEXITY_CASE_IDS):
        _fail("complexity envelope has the wrong fixed scenario order")
    if (
        _integer(
            envelope["accepted_scenarios"],
            "evidence.dp_complexity_profile.accepted_scenarios",
        )
        != 5
        or _integer(
            envelope["rejected_before_enumeration"],
            "evidence.dp_complexity_profile.rejected_before_enumeration",
        )
        != 1
        or _integer(
            envelope["report_schema_version"],
            "evidence.dp_complexity_profile.report_schema_version",
        )
        != 1
    ):
        _fail("complexity envelope has the wrong scenario cardinality or schema")
    if _boolean(
        envelope["contains_candidate"],
        "evidence.dp_complexity_profile.contains_candidate",
    ):
        _fail("complexity envelope must not claim candidate output")
    if envelope["counter_contract"] != "logical-dp-operations-v1":
        _fail("complexity envelope has the wrong counter contract")
    if envelope["json_source_command"] != COMPLEXITY_JSON_COMMAND:
        _fail("complexity envelope has the wrong JSON source command")
    if envelope["text_source_command"] != COMPLEXITY_TEXT_COMMAND:
        _fail("complexity envelope has the wrong text source command")


def _validate_evidence_claims(value: object) -> None:
    evidence = _mapping(value, "evidence")
    _exact_keys(
        evidence,
        {
            "cli_inspect",
            "diagrams",
            "dp_complexity_profile",
            "policy_sensitivity",
            "quality_gate",
            "sweep",
        },
        "evidence",
    )

    _validate_complexity_envelope(evidence["dp_complexity_profile"])

    sensitivity = _mapping(
        evidence["policy_sensitivity"],
        "evidence.policy_sensitivity",
    )
    _exact_keys(
        sensitivity,
        {
            "baseline_valid",
            "claim_boundary",
            "json_source_command",
            "rows",
            "text_source_command",
        },
        "evidence.policy_sensitivity",
    )
    expected_sensitivity, _, _ = _expected_sensitivity_evidence()
    if (
        sensitivity["baseline_valid"] != expected_sensitivity["baseline_valid"]
        or sensitivity["claim_boundary"]
        != expected_sensitivity["claim_boundary"]
        or sensitivity["json_source_command"] != SENSITIVITY_JSON_COMMAND
        or sensitivity["text_source_command"] != SENSITIVITY_TEXT_COMMAND
        or sensitivity["rows"] != 4
    ):
        _fail("evidence.policy_sensitivity is not the canonical exact report")

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



def _validate_sensitivity_evidence(textual: dict[str, str]) -> dict[str, object]:
    json_text = textual["docs/evidence/policy-sensitivity.json"]
    text = textual["docs/evidence/policy-sensitivity.txt"]
    try:
        decoded = json.loads(json_text)
    except json.JSONDecodeError as error:
        raise EvidenceValidationError(
            "policy sensitivity JSON cannot be decoded"
        ) from error
    if type(decoded) is not dict:
        _fail("policy sensitivity JSON root is not an object")
    document = cast(dict[str, object], decoded)
    expected_document, expected_json, expected_text = (
        _expected_sensitivity_evidence()
    )
    if document != expected_document or json_text != expected_json:
        _fail("policy sensitivity JSON does not match the exact core")
    if text != expected_text:
        _fail("policy sensitivity text does not match the exact core")
    return document


def _validate_raw_evidence(textual: dict[str, str]) -> dict[str, object]:
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

    sensitivity_document = _validate_sensitivity_evidence(textual)

    quality = textual["docs/evidence/quality-gate.txt"]
    if not quality.endswith("\n") or not quality.strip():
        _fail("quality-gate transcript must be nonempty and newline-terminated")
    command_offsets = [quality.find(command) for command in QUALITY_COMMANDS]
    if any(offset < 0 for offset in command_offsets) or command_offsets != sorted(
        command_offsets
    ):
        _fail("quality-gate transcript omits ordered command headers")
    return sensitivity_document


def _integer_list(value: object, label: str, *, minimum: int = 0) -> list[int]:
    return [
        _integer(item, f"{label}[{index}]", minimum=minimum)
        for index, item in enumerate(_sequence(value, label))
    ]


def _validate_profiled_call_map(value: object, label: str) -> dict[str, int]:
    calls = _mapping(value, label)
    _exact_keys(calls, {"primitive_calls", "total_calls"}, label)
    primitive = _integer(calls["primitive_calls"], f"{label}.primitive_calls")
    total = _integer(calls["total_calls"], f"{label}.total_calls")
    if primitive > total:
        _fail(f"{label} has more primitive calls than total calls")
    return {"primitive_calls": primitive, "total_calls": total}


@lru_cache(maxsize=1)
def _expected_complexity_evidence() -> tuple[dict[str, object], str, str]:
    try:
        report = cast(dict[str, object], complexity_profiler.build_profile())
        json_text = cast(str, complexity_profiler.profile_json(report))
        text = cast(str, complexity_profiler.profile_text(report))
    except Exception as error:
        raise EvidenceValidationError(
            "the deterministic complexity profiler could not rebuild its report"
        ) from error
    transcript = f"$ {COMPLEXITY_TEXT_COMMAND}\n{text}"
    return report, json_text, transcript


def _complexity_transcript(report: dict[str, object]) -> str:
    try:
        text = cast(str, complexity_profiler.profile_text(report))
    except Exception as error:
        raise EvidenceValidationError(
            "the deterministic complexity text renderer rejected its report"
        ) from error
    return f"$ {COMPLEXITY_TEXT_COMMAND}\n{text}"


def _validate_complexity_profile(
    document: dict[str, object],
    json_text: str,
    transcript: str,
) -> None:
    """Validate exact logical DP work without accepting performance claims."""

    _exact_keys(
        document,
        {
            "cases",
            "claim_boundaries",
            "counter_contract",
            "profiler",
            "scenario_set",
            "schema_version",
        },
        "complexity profile",
    )
    if _integer(document["schema_version"], "complexity profile.schema_version") != 1:
        _fail("complexity profile schema version is not supported")
    if document["scenario_set"] != "deterministic-dp-work-v1":
        _fail("complexity profile has the wrong fixed scenario set")
    if document["counter_contract"] != "logical-dp-operations-v1":
        _fail("complexity profile has the wrong counter contract")

    profiler = _mapping(document["profiler"], "complexity profile.profiler")
    _exact_keys(
        profiler,
        {
            "engine",
            "retained_fields",
            "selected_project_functions",
            "timing_fields_retained",
        },
        "complexity profile.profiler",
    )
    if profiler["engine"] != "cProfile":
        _fail("complexity profile uses an unexpected call-count engine")
    if _validate_string_list(
        profiler["selected_project_functions"],
        "complexity profile.profiler.selected_project_functions",
    ) != ["PasswordSpace._build_layers", "_consume"]:
        _fail("complexity profile selects the wrong project functions")
    if _validate_string_list(
        profiler["retained_fields"],
        "complexity profile.profiler.retained_fields",
    ) != ["primitive_calls", "total_calls"]:
        _fail("complexity profile retained fields are not call-count only")
    if _boolean(
        profiler["timing_fields_retained"],
        "complexity profile.profiler.timing_fields_retained",
    ):
        _fail("complexity profile must discard profiler timing fields")

    boundaries = _mapping(
        document["claim_boundaries"],
        "complexity profile.claim_boundaries",
    )
    boundary_keys = {
        "candidate_output_included",
        "entropy_consumed",
        "hardware_performance_claimed",
        "memory_usage_claimed",
        "wall_clock_timing_included",
    }
    _exact_keys(boundaries, boundary_keys, "complexity profile.claim_boundaries")
    if any(
        _boolean(boundaries[key], f"complexity profile.claim_boundaries.{key}")
        for key in boundary_keys
    ):
        _fail("complexity profile claim boundaries must all remain false")

    cases = _sequence(document["cases"], "complexity profile.cases")
    if len(cases) != len(COMPLEXITY_CASE_IDS):
        _fail("complexity profile must contain exactly six fixed cases")
    observed_ids: list[str] = []
    cases_by_id: dict[str, dict[str, object]] = {}
    for index, raw_case in enumerate(cases):
        label = f"complexity profile.cases[{index}]"
        case = _mapping(raw_case, label)
        case_id = _string(case.get("case_id"), f"{label}.case_id")
        observed_ids.append(case_id)
        cases_by_id[case_id] = case
        if case_id not in _COMPLEXITY_POLICIES:
            _fail(f"{label} is not in the fixed scenario set")

        accepted = case_id in _COMPLEXITY_ACCEPTED_WORK
        expected_keys = {
            "bounds",
            "case_id",
            "outcome",
            "policy",
            "profiled_calls",
            "work_counters",
        }
        expected_keys |= (
            {"independent_oracles", "observed"} if accepted else {"rejection"}
        )
        _exact_keys(case, expected_keys, label)

        policy = _mapping(case["policy"], f"{label}.policy")
        _exact_keys(
            policy,
            {"class_count", "class_minima", "class_widths", "length"},
            f"{label}.policy",
        )
        length = _integer(policy["length"], f"{label}.policy.length", minimum=1)
        class_count = _integer(
            policy["class_count"],
            f"{label}.policy.class_count",
            minimum=1,
        )
        widths = _integer_list(
            policy["class_widths"],
            f"{label}.policy.class_widths",
            minimum=1,
        )
        minima = _integer_list(
            policy["class_minima"],
            f"{label}.policy.class_minima",
        )
        expected_length, expected_widths, expected_minima = _COMPLEXITY_POLICIES[
            case_id
        ]
        if (
            length != expected_length
            or class_count != len(widths)
            or len(minima) != class_count
            or tuple(widths) != expected_widths
            or tuple(minima) != expected_minima
            or sum(minima) > length
        ):
            _fail(f"{label} does not match its fixed public policy")

        bounds = _mapping(case["bounds"], f"{label}.bounds")
        bound_keys = {
            "dp_cells_budget",
            "dp_cells_upper_bound",
            "dp_transitions_budget",
            "dp_transitions_upper_bound",
            "state_vectors_upper_bound_per_layer",
        }
        _exact_keys(bounds, bound_keys, f"{label}.bounds")
        vectors = prod(minimum + 1 for minimum in minima)
        cells_upper = (length + 1) * vectors
        transitions_upper = class_count * cells_upper
        if (
            _integer(
                bounds["state_vectors_upper_bound_per_layer"],
                f"{label}.bounds.state_vectors_upper_bound_per_layer",
                minimum=1,
            )
            != vectors
            or _integer(
                bounds["dp_cells_upper_bound"],
                f"{label}.bounds.dp_cells_upper_bound",
                minimum=1,
            )
            != cells_upper
            or _integer(
                bounds["dp_transitions_upper_bound"],
                f"{label}.bounds.dp_transitions_upper_bound",
                minimum=1,
            )
            != transitions_upper
            or bounds["dp_cells_budget"] != MAX_DP_CELLS
            or bounds["dp_transitions_budget"] != MAX_DP_TRANSITIONS
        ):
            _fail(f"{label} bounds do not match the production admission contract")

        profiled = _mapping(case["profiled_calls"], f"{label}.profiled_calls")
        _exact_keys(
            profiled,
            {"build_layers", "consume"},
            f"{label}.profiled_calls",
        )
        build_calls = _validate_profiled_call_map(
            profiled["build_layers"],
            f"{label}.profiled_calls.build_layers",
        )
        consume_calls = _validate_profiled_call_map(
            profiled["consume"],
            f"{label}.profiled_calls.consume",
        )
        work = _mapping(case["work_counters"], f"{label}.work_counters")
        _exact_keys(
            work,
            {"consume_calls", "product_calls", "product_vectors"},
            f"{label}.work_counters",
        )
        product_calls = _integer(
            work["product_calls"],
            f"{label}.work_counters.product_calls",
        )
        product_vectors = _integer(
            work["product_vectors"],
            f"{label}.work_counters.product_vectors",
        )
        observed_consume_calls = _integer(
            work["consume_calls"],
            f"{label}.work_counters.consume_calls",
        )

        if not accepted:
            if (
                case["outcome"] != "rejected-before-enumeration"
                or case["rejection"] != "dynamic-programming-complexity-budget"
            ):
                _fail("rejected complexity case has the wrong failure contract")
            if cells_upper <= MAX_DP_CELLS and transitions_upper <= MAX_DP_TRANSITIONS:
                _fail("rejected complexity case is below both production budgets")
            zero_calls = {"primitive_calls": 0, "total_calls": 0}
            if (
                build_calls != zero_calls
                or consume_calls != zero_calls
                or product_calls != 0
                or product_vectors != 0
                or observed_consume_calls != 0
            ):
                _fail("rejected complexity case performed forbidden enumeration")
            continue

        if case["outcome"] != "accepted":
            _fail(f"{label} unexpectedly records a rejected outcome")
        if cells_upper > MAX_DP_CELLS or transitions_upper > MAX_DP_TRANSITIONS:
            _fail(f"{label} was accepted above a production complexity budget")
        observed = _mapping(case["observed"], f"{label}.observed")
        _exact_keys(
            observed,
            {
                "layer_occupancy",
                "occupied_cells",
                "peak_count_bits",
                "transitions",
                "valid_state_space",
            },
            f"{label}.observed",
        )
        occupancy = _integer_list(
            observed["layer_occupancy"],
            f"{label}.observed.layer_occupancy",
            minimum=1,
        )
        occupied = _integer(
            observed["occupied_cells"],
            f"{label}.observed.occupied_cells",
            minimum=1,
        )
        transitions = _integer(
            observed["transitions"],
            f"{label}.observed.transitions",
        )
        peak_bits = _integer(
            observed["peak_count_bits"],
            f"{label}.observed.peak_count_bits",
            minimum=1,
        )
        valid = _string(
            observed["valid_state_space"],
            f"{label}.observed.valid_state_space",
        )
        if re.fullmatch(r"[1-9][0-9]*", valid) is None:
            _fail(f"{label}.observed.valid_state_space is not canonical decimal")
        if (
            len(occupancy) != length + 1
            or occupancy[0] != 1
            or occupied != sum(occupancy)
            or occupied > cells_upper
            or transitions != class_count * (occupied - 1)
        ):
            _fail(f"{label} has inconsistent occupied cell or transition counts")
        (
            expected_occupied,
            expected_transitions,
            expected_product_calls,
            expected_vectors,
            expected_consume,
        ) = _COMPLEXITY_ACCEPTED_WORK[case_id]
        if (
            occupied != expected_occupied
            or transitions != expected_transitions
            or product_calls != expected_product_calls
            or product_vectors != expected_vectors
            or observed_consume_calls != expected_consume
        ):
            _fail(f"{label} logical work counters changed from the fixed study")
        if (
            build_calls != {"primitive_calls": 1, "total_calls": 1}
            or consume_calls
            != {"primitive_calls": transitions, "total_calls": transitions}
            or product_calls != length
            or product_vectors != length * vectors
            or observed_consume_calls != transitions
        ):
            _fail(f"{label} profiler counters do not match the loop or call contract")
        oracles = _mapping(
            case["independent_oracles"],
            f"{label}.independent_oracles",
        )
        _exact_keys(
            oracles,
            {"occupied_cells", "transitions", "valid_state_space"},
            f"{label}.independent_oracles",
        )
        oracle_occupied = _integer(
            oracles["occupied_cells"],
            f"{label}.independent_oracles.occupied_cells",
            minimum=1,
        )
        oracle_transitions = _integer(
            oracles["transitions"],
            f"{label}.independent_oracles.transitions",
        )
        oracle_valid = _string(
            oracles["valid_state_space"],
            f"{label}.independent_oracles.valid_state_space",
        )
        if (
            oracle_occupied != occupied
            or oracle_transitions != transitions
            or oracle_valid != valid
        ):
            _fail(f"{label} observed work disagrees with an independent oracle")
        del peak_bits

    if observed_ids != list(COMPLEXITY_CASE_IDS) or len(cases_by_id) != len(cases):
        _fail("complexity profile cases are duplicated or out of fixed order")

    balanced = cases_by_id["balanced-visible-ascii-24"]
    skewed = cases_by_id["skewed-visible-ascii-24"]
    balanced_policy = _mapping(balanced["policy"], "balanced policy")
    skewed_policy = _mapping(skewed["policy"], "skewed policy")
    balanced_observed = _mapping(balanced["observed"], "balanced observation")
    skewed_observed = _mapping(skewed["observed"], "skewed observation")
    if (
        balanced_policy["length"] != skewed_policy["length"]
        or balanced_policy["class_widths"] != skewed_policy["class_widths"]
        or sum(cast(list[int], balanced_policy["class_minima"]))
        != sum(cast(list[int], skewed_policy["class_minima"]))
        or _integer(balanced_observed["occupied_cells"], "balanced cells")
        <= _integer(skewed_observed["occupied_cells"], "skewed cells")
        or _integer(balanced_observed["transitions"], "balanced transitions")
        <= _integer(skewed_observed["transitions"], "skewed transitions")
    ):
        _fail("complexity profile lost its balanced-versus-skewed differential")

    _validate_safe_text(json_text, "complexity profile JSON")
    _validate_safe_text(transcript, "complexity profile transcript")
    if (
        not transcript.endswith(
            "Safety: no entropy consumed and no password candidate "
            "constructed or emitted.\n"
        )
        or "no elapsed-time, RSS, hardware, or speed claim" not in transcript
    ):
        _fail("complexity transcript omits its privacy or claim boundaries")

    expected_report, expected_json, expected_transcript = (
        _expected_complexity_evidence()
    )
    if document != expected_report or json_text != expected_json:
        _fail("complexity profile is stale against a fresh deterministic rebuild")
    if transcript != expected_transcript:
        _fail("complexity transcript is not the exact real text representation")


def _validate_complexity_renderings(
    root: Path,
    report: dict[str, object],
    transcript: str,
) -> None:
    """Require and byte-compare every pure complexity renderer."""

    try:
        rendering = _load_local_module("evidence_rendering")
    except (ImportError, OSError, RuntimeError) as error:
        raise EvidenceValidationError(
            "complexity renderers could not be loaded"
        ) from error
    for renderer_name, relative in (
        ("render_dp_layer_occupancy_svg", "docs/assets/dp-layer-occupancy.svg"),
        ("render_dp_work_counts_svg", "docs/assets/dp-work-counts.svg"),
    ):
        renderer = getattr(rendering, renderer_name, None)
        if not callable(renderer):
            _fail(f"required pure complexity renderer is missing: {renderer_name}")
        try:
            rendered = renderer(report)
        except Exception as error:
            raise EvidenceValidationError(
                f"pure complexity renderer failed: {renderer_name}"
            ) from error
        if type(rendered) is str:
            expected = rendered.encode("utf-8")
        elif type(rendered) is bytes:
            expected = rendered
        else:
            _fail(
                f"pure complexity renderer returned an invalid value: {renderer_name}"
            )
        actual = _read_bounded(root / relative, relative)
        if actual != expected:
            _fail(f"complexity visual is stale against its pure renderer: {relative}")

    png_renderer = getattr(rendering, "render_terminal_png_bytes", None)
    if not callable(png_renderer):
        _fail("required pure complexity PNG renderer is missing")
    try:
        rendered_png = png_renderer(
            transcript=transcript,
            title=COMPLEXITY_PNG_TITLE,
        )
    except Exception as error:
        raise EvidenceValidationError("pure complexity PNG renderer failed") from error
    if type(rendered_png) is not bytes:
        _fail("pure complexity PNG renderer returned an invalid value")
    png_relative = "docs/assets/dp-complexity-cli.png"
    actual_png = _read_bounded(root / png_relative, png_relative)
    if actual_png != rendered_png:
        _fail(f"complexity visual is stale against its pure renderer: {png_relative}")



def _validate_sensitivity_renderings(
    root: Path,
    report: dict[str, object],
    transcript_text: str,
) -> None:
    try:
        rendering = _load_local_module("evidence_rendering")
    except (ImportError, OSError, RuntimeError) as error:
        raise EvidenceValidationError(
            "policy sensitivity renderers could not be loaded"
        ) from error
    svg_renderer = getattr(rendering, "render_policy_sensitivity_svg", None)
    png_renderer = getattr(rendering, "render_terminal_png_bytes", None)
    if not callable(svg_renderer) or not callable(png_renderer):
        _fail("required pure policy sensitivity renderer is missing")
    try:
        expected_svg = svg_renderer(report)
        expected_png = png_renderer(
            transcript=f"$ {SENSITIVITY_TEXT_COMMAND}\n{transcript_text}",
            title=SENSITIVITY_PNG_TITLE,
        )
    except Exception as error:
        raise EvidenceValidationError(
            "pure policy sensitivity renderer failed"
        ) from error
    if type(expected_svg) is not str or type(expected_png) is not bytes:
        _fail("pure policy sensitivity renderer returned an invalid value")
    svg_path = "docs/assets/policy-sensitivity-impact.svg"
    png_path = "docs/assets/policy-sensitivity-cli.png"
    if _read_bounded(root / svg_path, svg_path) != expected_svg.encode("utf-8"):
        _fail("policy sensitivity SVG is stale against its pure renderer")
    if _read_bounded(root / png_path, png_path) != expected_png:
        _fail("policy sensitivity terminal image is stale against its transcript")


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
    if document["schema_version"] != 2:
        _fail("manifest.schema_version must be 2")
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
    complexity_document, complexity_text = _load_json(
        repository / COMPLEXITY_JSON_PATH,
        label="complexity profile",
    )
    if textual[COMPLEXITY_JSON_PATH] != complexity_text:
        _fail("complexity profile changed between bounded reads")
    _validate_complexity_profile(
        complexity_document,
        complexity_text,
        textual[COMPLEXITY_TEXT_PATH],
    )
    _validate_complexity_renderings(
        repository,
        complexity_document,
        textual[COMPLEXITY_TEXT_PATH],
    )
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
    sensitivity_document = _validate_raw_evidence(textual)
    _validate_sensitivity_renderings(
        repository,
        sensitivity_document,
        textual["docs/evidence/policy-sensitivity.txt"],
    )
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
