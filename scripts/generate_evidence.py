"""Rebuild real, guarded, reproducible portfolio evidence."""

from __future__ import annotations

import ast
import csv
import hashlib
import importlib
import importlib.metadata
import json
import os
import platform
import re
import subprocess
import sys
import threading
import tomllib
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from io import StringIO
from pathlib import Path
from typing import Any, Protocol, cast
from unittest.mock import patch
from urllib.parse import urlsplit

import attest_distribution as distribution_attester
import profile_complexity as complexity_profiler
from evidence_rendering import (
    GOLD,
    LINE,
    MUTED,
    SURFACE,
    TEAL,
    TEXT,
    recompress_png,
    render_terminal_png,
    write_architecture_svg,
    write_distribution_svg,
    write_dp_layer_occupancy_svg,
    write_dp_work_counts_svg,
    write_gif,
    write_policy_sensitivity_svg,
    write_sampling_svg,
    write_setup_svg,
)
from playwright.sync_api import (
    Browser,
    BrowserContext,
    Page,
    Request,
    Route,
    sync_playwright,
)
from waitress import create_server  # type: ignore[import-untyped]

from password_policy_lab.space import PasswordSpace
from password_policy_lab.web import create_app

ROOT = Path(__file__).resolve().parents[1]
ASSET_DIR = ROOT / "docs" / "assets"
EVIDENCE_DIR = ROOT / "docs" / "evidence"
WORK_DIR = ROOT / ".evidence-work"
PYTHON = Path(sys.executable)

SWEEP_COMMAND = (
    "password-policy-lab sweep --start-length 8 --end-length 32 --format csv"
)
INSPECT_COMMAND = "password-policy-lab inspect --length 20 --format text"
SENSITIVITY_JSON_COMMAND = (
    "password-policy-lab sensitivity --length 20 --format json"
)
SENSITIVITY_TEXT_COMMAND = (
    "password-policy-lab sensitivity --length 20 --format text"
)
SENSITIVITY_PNG_TITLE = "Exact one-step policy sensitivity · length 20"
PROFILE_JSON_COMMAND = (
    "PYTHONPATH=src python scripts/profile_complexity.py --format json"
)
PROFILE_TEXT_COMMAND = (
    "PYTHONPATH=src python scripts/profile_complexity.py --format text"
)
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
CHROMIUM_ARGS = ("--num-raster-threads=1",)

OUTPUT_PATHS = (
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
    "docs/evidence/cli-inspect.txt",
    "docs/evidence/distribution-attestation.json",
    "docs/evidence/distribution-check.txt",
    "docs/evidence/dp-complexity-profile.json",
    "docs/evidence/dp-complexity-profile.txt",
    "docs/evidence/policy-sensitivity.json",
    "docs/evidence/policy-sensitivity.txt",
    "docs/evidence/quality-gate.txt",
    "docs/evidence/state-space-sweep.csv",
    "docs/evidence/web-validation-reference.png",
)

_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9_.-])/(?:home|tmp|usr|opt|var|private|Users)/[^\s:]+"
)
_PYTEST_DURATION = re.compile(
    r"(?m)^(?P<summary>\d+ passed"
    r"(?:, \d+ (?:skipped|deselected|xfailed|xpassed|warnings?))*)"
    r"(?: in \d+(?:\.\d+)?s(?: \(\d+:\d{2}:\d{2}\))?"
    r"| \(\d+:\d{2}:\d{2}\))$"
)


class _WaitressServer(Protocol):
    effective_port: int

    def run(self) -> None: ...

    def close(self) -> None: ...


@dataclass
class _ServerHandle:
    base_url: str
    sampler_calls: list[int]


@dataclass(frozen=True)
class _CaptureResult:
    chromium: str
    requests: list[dict[str, object]]
    sampler_calls: int


@dataclass(frozen=True)
class _SweepRow:
    length: int
    entropy_floor: int
    entropy_ceiling: int
    satisfying_percent: float


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _configure_environment() -> None:
    if Path.cwd().resolve() != ROOT:
        raise RuntimeError("run the evidence generator from the repository root")

    local_paths = {
        "PLAYWRIGHT_BROWSERS_PATH": ROOT / ".playwright-browsers",
        "MPLCONFIGDIR": WORK_DIR / "mplconfig",
        "XDG_CACHE_HOME": WORK_DIR / "xdg",
        "TMPDIR": WORK_DIR / "tmp",
        "TMP": WORK_DIR / "tmp",
        "TEMP": WORK_DIR / "tmp",
    }
    for variable, path in local_paths.items():
        path.mkdir(parents=True, exist_ok=True)
        os.environ[variable] = str(path)

    runtime_libraries = WORK_DIR / "runtime" / "usr" / "lib" / "x86_64-linux-gnu"
    if runtime_libraries.is_dir():
        existing_library_path = os.environ.get("LD_LIBRARY_PATH")
        os.environ["LD_LIBRARY_PATH"] = (
            f"{runtime_libraries}:{existing_library_path}"
            if existing_library_path
            else str(runtime_libraries)
        )
    os.environ.update(
        {
            "COLUMNS": "120",
            "LC_ALL": "C.UTF-8",
            "MPLBACKEND": "Agg",
            "NO_COLOR": "1",
            "PYTHONHASHSEED": "0",
            "TERM": "dumb",
            "TZ": "UTC",
            "PYTHONUTF8": "1",
        }
    )
    ASSET_DIR.mkdir(parents=True, exist_ok=True)
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)


def _command_environment() -> dict[str, str]:
    environment = os.environ.copy()
    environment["PYTHONPATH"] = "src"
    environment["MYPYPATH"] = "src"
    environment["COVERAGE_FILE"] = str(WORK_DIR / "coverage")
    return environment


def _run(
    arguments: Sequence[str],
    *,
    environment: dict[str, str] | None = None,
) -> str:
    completed = subprocess.run(
        list(arguments),
        cwd=ROOT,
        env=environment or _command_environment(),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=180,
    )
    output = completed.stdout + completed.stderr
    if completed.returncode != 0:
        clean = output.replace(str(ROOT), ".")
        raise RuntimeError(
            f"evidence command failed with status {completed.returncode}\n{clean}"
        )
    return output


def _cli_arguments(*arguments: str) -> tuple[str, ...]:
    return (str(PYTHON), "-m", "password_policy_lab", *arguments)


def _write_cli_evidence() -> tuple[list[_SweepRow], dict[str, object]]:
    inspect_output = _run(
        _cli_arguments("inspect", "--length", "20", "--format", "text")
    )
    inspect_transcript = f"$ {INSPECT_COMMAND}\n{inspect_output}"
    if "deterministic_test_vector" in inspect_transcript:
        raise RuntimeError("inspection evidence unexpectedly contains a candidate")
    (EVIDENCE_DIR / "cli-inspect.txt").write_text(
        inspect_output,
        encoding="utf-8",
    )
    render_terminal_png(
        transcript=inspect_transcript,
        title="Exact policy inspection · length 20",
        path=ASSET_DIR / "cli-inspect.png",
    )

    sensitivity_json = _run(
        _cli_arguments("sensitivity", "--length", "20", "--format", "json")
    )
    sensitivity_text = _run(
        _cli_arguments("sensitivity", "--length", "20", "--format", "text")
    )
    try:
        decoded_sensitivity = json.loads(sensitivity_json)
    except json.JSONDecodeError as error:
        raise RuntimeError("sensitivity CLI did not emit valid JSON") from error
    if type(decoded_sensitivity) is not dict:
        raise RuntimeError("sensitivity CLI JSON root is not an object")
    sensitivity_document = cast(dict[str, object], decoded_sensitivity)
    boundary = sensitivity_document.get("claim_boundary")
    if boundary != {
        "contains_candidate": False,
        "effects_are_not_additive": True,
        "one_step_only": True,
        "samples_entropy": False,
    }:
        raise RuntimeError("sensitivity CLI claim boundary is not canonical")
    (EVIDENCE_DIR / "policy-sensitivity.json").write_text(
        sensitivity_json,
        encoding="utf-8",
    )
    (EVIDENCE_DIR / "policy-sensitivity.txt").write_text(
        sensitivity_text,
        encoding="utf-8",
    )
    sensitivity_transcript = f"$ {SENSITIVITY_TEXT_COMMAND}\n{sensitivity_text}"
    render_terminal_png(
        transcript=sensitivity_transcript,
        title=SENSITIVITY_PNG_TITLE,
        path=ASSET_DIR / "policy-sensitivity-cli.png",
    )
    write_policy_sensitivity_svg(
        sensitivity_document,
        ASSET_DIR / "policy-sensitivity-impact.svg",
    )

    sweep_output = _run(
        _cli_arguments(
            "sweep",
            "--start-length",
            "8",
            "--end-length",
            "32",
            "--format",
            "csv",
        )
    )
    (EVIDENCE_DIR / "state-space-sweep.csv").write_text(
        sweep_output,
        encoding="utf-8",
    )
    rows: list[_SweepRow] = []
    parsed = csv.DictReader(StringIO(sweep_output))
    for record in parsed:
        numerator = int(record["fraction_numerator"])
        denominator = int(record["fraction_denominator"])
        rows.append(
            _SweepRow(
                length=int(record["length"]),
                entropy_floor=int(record["entropy_bits_floor"]),
                entropy_ceiling=int(record["entropy_bits_ceiling"]),
                satisfying_percent=100.0 * numerator / denominator,
            )
        )
    if [row.length for row in rows] != list(range(8, 33)):
        raise RuntimeError("CLI sweep did not return the exact inclusive range 8..32")
    return rows, sensitivity_document


def _write_complexity_evidence() -> dict[str, object]:
    report = complexity_profiler.build_profile()
    expected_json = complexity_profiler.profile_json(report)
    expected_text = complexity_profiler.profile_text(report)
    json_output = _run(
        (
            str(PYTHON),
            "scripts/profile_complexity.py",
            "--format",
            "json",
        )
    )
    text_output = _run(
        (
            str(PYTHON),
            "scripts/profile_complexity.py",
            "--format",
            "text",
        )
    )
    if json_output != expected_json or text_output != expected_text:
        raise RuntimeError(
            "complexity CLI output disagrees with the in-process profile"
        )

    (EVIDENCE_DIR / "dp-complexity-profile.json").write_text(
        json_output,
        encoding="utf-8",
    )
    transcript = f"$ {PROFILE_TEXT_COMMAND}\n{text_output}"
    (EVIDENCE_DIR / "dp-complexity-profile.txt").write_text(
        transcript,
        encoding="utf-8",
    )
    render_terminal_png(
        transcript=transcript,
        title="Deterministic DP work profile · six fixed policies",
        path=ASSET_DIR / "dp-complexity-cli.png",
    )
    write_dp_work_counts_svg(report, ASSET_DIR / "dp-work-counts.svg")
    write_dp_layer_occupancy_svg(report, ASSET_DIR / "dp-layer-occupancy.svg")
    return report


def _render_sweep_chart(rows: Sequence[_SweepRow]) -> None:
    matplotlib: Any = importlib.import_module("matplotlib")
    matplotlib.use("Agg")
    pyplot: Any = importlib.import_module("matplotlib.pyplot")
    ticker: Any = importlib.import_module("matplotlib.ticker")

    matplotlib.rcParams.update(
        {
            "axes.edgecolor": LINE,
            "axes.facecolor": SURFACE,
            "axes.labelcolor": TEXT,
            "axes.titlecolor": TEXT,
            "figure.facecolor": "#0a1014",
            "font.family": "DejaVu Sans",
            "font.size": 14,
            "grid.color": LINE,
            "grid.linewidth": 0.8,
            "savefig.facecolor": "#0a1014",
            "text.color": TEXT,
            "xtick.color": MUTED,
            "ytick.color": MUTED,
        }
    )
    lengths = [row.length for row in rows]
    floor = [row.entropy_floor for row in rows]
    ceiling = [row.entropy_ceiling for row in rows]
    percentage = [row.satisfying_percent for row in rows]

    figure, axes = pyplot.subplots(
        2,
        1,
        figsize=(16, 10),
        dpi=100,
        sharex=True,
        gridspec_kw={"height_ratios": [1.15, 1], "hspace": 0.24},
    )
    top, bottom = axes
    top.fill_between(
        lengths,
        floor,
        ceiling,
        color=GOLD,
        alpha=0.18,
        label="integer-bound interval",
    )
    top.plot(
        lengths,
        floor,
        color=TEAL,
        linewidth=2.8,
        marker="o",
        markersize=5,
        label="entropy floor",
    )
    top.plot(
        lengths,
        ceiling,
        color=GOLD,
        linewidth=2.4,
        linestyle="--",
        marker="s",
        markersize=4.5,
        label="entropy ceiling",
    )
    top.set_ylabel("Uniform-draw entropy (bits)")
    top.grid(axis="y", alpha=0.65)
    top.legend(loc="upper left", frameon=False, ncol=3, labelcolor=TEXT)
    top.annotate(
        f"floor {floor[-1]} bits",
        (lengths[-1], floor[-1]),
        xytext=(-10, -24),
        textcoords="offset points",
        color=TEAL,
        ha="right",
        fontsize=12,
    )

    bottom.plot(
        lengths,
        percentage,
        color=TEAL,
        linewidth=2.8,
        marker="o",
        markersize=5,
    )
    bottom.set_ylim(0, 100)
    bottom.set_ylabel("Policy-satisfying share")
    bottom.set_xlabel("Fixed password length (characters)")
    bottom.yaxis.set_major_formatter(ticker.PercentFormatter(xmax=100))
    bottom.set_xticks(list(range(8, 33, 2)))
    bottom.grid(axis="y", alpha=0.65)
    bottom.annotate(
        f"{percentage[-1]:.2f}%",
        (lengths[-1], percentage[-1]),
        xytext=(-10, 12),
        textcoords="offset points",
        color=TEAL,
        ha="right",
        fontsize=12,
    )

    figure.suptitle(
        "Exact policy state space across lengths 8\u201332",
        x=0.08,
        y=0.972,
        ha="left",
        fontsize=25,
        fontweight="bold",
    )
    figure.text(
        0.08,
        0.93,
        (
            "visible-ascii-v1 · minima lower/upper/digits/punctuation = 1 each "
            "· source: exact CLI sweep"
        ),
        color=MUTED,
        fontsize=13,
    )
    figure.text(
        0.08,
        0.902,
        (
            "Entropy grows steadily while the relative cost of the required "
            "minima diminishes."
        ),
        color=GOLD,
        fontsize=13,
    )
    figure.subplots_adjust(left=0.1, right=0.96, bottom=0.09, top=0.86)
    figure.savefig(
        ASSET_DIR / "state-space-sweep.png",
        dpi=100,
        metadata={
            "Software": f"Matplotlib {matplotlib.__version__}",
            "Title": "Exact policy state space across lengths 8\u201332",
        },
    )
    pyplot.close(figure)
    recompress_png(ASSET_DIR / "state-space-sweep.png")


def _call_names(tree: ast.AST) -> set[str]:
    calls: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name):
            calls.add(node.func.id)
        elif isinstance(node.func, ast.Attribute):
            calls.add(node.func.attr)
    return calls


def _verify_architecture_ast() -> bool:
    web_tree = ast.parse(
        (ROOT / "src/password_policy_lab/web.py").read_text(encoding="utf-8")
    )
    cli_tree = ast.parse(
        (ROOT / "src/password_policy_lab/cli.py").read_text(encoding="utf-8")
    )
    web_calls = _call_names(web_tree)
    cli_calls = _call_names(cli_tree)
    required_web = {
        "PasswordSpace",
        "inspect_space",
        "render_template",
        "sample_uniform",
    }
    required_cli = {"PasswordSpace", "inspect_policy", "visible_ascii_policy"}
    if not required_web <= web_calls or not required_cli <= cli_calls:
        raise RuntimeError("production architecture changed; diagram review required")

    def function(tree: ast.AST, name: str) -> ast.FunctionDef:
        candidates = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == name
        ]
        if len(candidates) != 1:
            raise RuntimeError(f"expected exactly one {name} function")
        return candidates[0]

    generate = function(web_tree, "generate_password")
    try_blocks = [node for node in generate.body if isinstance(node, ast.Try)]
    if len(try_blocks) != 1 or not all(
        any(isinstance(statement, ast.Return) for statement in handler.body)
        for handler in try_blocks[0].handlers
    ):
        raise RuntimeError("invalid request paths no longer return from validation")
    named_calls = [
        node
        for node in ast.walk(generate)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id in required_web)
            or (isinstance(node.func, ast.Attribute) and node.func.attr in required_web)
        )
    ]
    call_lines = {
        (
            node.func.id
            if isinstance(node.func, ast.Name)
            else cast(ast.Attribute, node.func).attr
        ): node.lineno
        for node in named_calls
    }
    validation_end = cast(int, try_blocks[0].end_lineno)
    if not (
        validation_end
        < call_lines["PasswordSpace"]
        < call_lines["inspect_space"]
        < call_lines["sample_uniform"]
    ):
        raise RuntimeError(
            "web policy, inspection, and sampling order changed from the diagram"
        )

    default_policy = function(web_tree, "_default_policy")
    if "visible_ascii_policy" not in _call_names(default_policy):
        raise RuntimeError("web route no longer converges through the named profile")
    index = function(web_tree, "index")
    if not {"PasswordSpace", "inspect_space"} <= _call_names(index):
        raise RuntimeError("GET route no longer converges on space and inspection")
    return True


def _verify_sampling_ast() -> bool:
    tree = ast.parse(
        (ROOT / "src/password_policy_lab/space.py").read_text(encoding="utf-8")
    )
    methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "sample_uniform"
    ]
    if len(methods) != 1:
        raise RuntimeError("sample_uniform AST shape is ambiguous")
    method = methods[0]
    executable = list(method.body)
    if (
        executable
        and isinstance(executable[0], ast.Expr)
        and isinstance(executable[0].value, ast.Constant)
        and isinstance(executable[0].value.value, str)
    ):
        executable = executable[1:]
    if len(executable) != 1 or not isinstance(executable[0], ast.Return):
        raise RuntimeError("sample_uniform is no longer one direct return")
    outer = executable[0].value
    if (
        not isinstance(outer, ast.Call)
        or not isinstance(outer.func, ast.Attribute)
        or not isinstance(outer.func.value, ast.Name)
        or outer.func.value.id != "self"
        or outer.func.attr != "unrank"
        or len(outer.args) != 1
    ):
        raise RuntimeError("sample_uniform no longer calls self.unrank directly")
    random_call = outer.args[0]
    if (
        not isinstance(random_call, ast.Call)
        or not isinstance(random_call.func, ast.Attribute)
        or not isinstance(random_call.func.value, ast.Name)
        or random_call.func.value.id != "secrets"
        or random_call.func.attr != "randbelow"
        or len(random_call.args) != 1
    ):
        raise RuntimeError("sample_uniform no longer uses secrets.randbelow")
    total = random_call.args[0]
    if (
        not isinstance(total, ast.Attribute)
        or not isinstance(total.value, ast.Name)
        or total.value.id != "self"
        or total.attr != "_total"
    ):
        raise RuntimeError("sample_uniform no longer draws below self._total")
    if any(isinstance(node, (ast.For, ast.While)) for node in ast.walk(method)):
        raise RuntimeError("sample_uniform contains an unexpected retry loop")
    return True


def _verify_setup_contract() -> None:
    configuration = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = cast(dict[str, object], configuration["project"])
    scripts = cast(dict[str, str], project["scripts"])
    if scripts.get("password-policy-lab") != "password_policy_lab.cli:main":
        raise RuntimeError("console-script setup changed; diagram review required")
    optional = cast(dict[str, list[str]], project["optional-dependencies"])
    development = optional["dev"]
    required = ("matplotlib==", "numpy==", "Pillow==", "playwright==")
    if not all(
        any(item.startswith(prefix) for item in development) for prefix in required
    ):
        raise RuntimeError("evidence dependencies are not pinned in the dev extra")
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    required_make_contract = (
        "check: lint typecheck test dependencies distribution-check evidence-check",
        "distribution-check:",
        "scripts/attest_distribution.py",
        "evidence:",
        "scripts/generate_evidence.py",
        "evidence-check:",
        "scripts/check_evidence.py",
        "PLAYWRIGHT_BROWSERS_PATH",
        "MPLCONFIGDIR",
        "XDG_CACHE_HOME",
    )
    if not all(fragment in makefile for fragment in required_make_contract):
        raise RuntimeError(
            "Makefile evidence workflow changed; diagram review required"
        )


@contextmanager
def _guarded_server() -> Iterator[_ServerHandle]:
    sampler_calls = [0]

    def abort_sampling(space: PasswordSpace) -> str:
        del space
        sampler_calls[0] += 1
        raise AssertionError("evidence capture must never sample a password")

    with patch.object(PasswordSpace, "sample_uniform", abort_sampling):
        server = cast(
            _WaitressServer,
            create_server(create_app(), host="127.0.0.1", port=0, threads=2),
        )
        thread = threading.Thread(
            target=server.run,
            name="guarded-evidence-waitress",
            daemon=True,
        )
        thread.start()
        try:
            yield _ServerHandle(
                base_url=f"http://127.0.0.1:{server.effective_port}",
                sampler_calls=sampler_calls,
            )
        finally:
            server.close()
            thread.join(timeout=5)
            if thread.is_alive():
                raise RuntimeError("Waitress evidence server did not stop")


def _assert_no_output(page: Page) -> None:
    if page.locator("#generated-password").count() != 0:
        raise RuntimeError("browser evidence contains generated output")
    if page.locator(".result-card").count() != 0:
        raise RuntimeError("browser evidence contains a result card")


def _assert_no_overflow(page: Page) -> None:
    dimensions = cast(
        dict[str, int],
        page.evaluate(
            """() => ({
              client: document.documentElement.clientWidth,
              scroll: document.documentElement.scrollWidth
            })"""
        ),
    )
    if dimensions["scroll"] > dimensions["client"]:
        raise RuntimeError("captured page has horizontal overflow")


def _local_request_router(
    *,
    base_url: str,
    external_requests: list[str],
) -> Callable[[Route, Request], None]:
    expected = urlsplit(base_url)

    def handle(route: Route, request: Request) -> None:
        actual = urlsplit(request.url)
        if (
            actual.scheme == expected.scheme
            and actual.hostname == expected.hostname
            and actual.port == expected.port
        ):
            route.continue_()
            return
        external_requests.append(request.url)
        route.abort()

    return handle


def _new_context(
    browser: Browser,
    *,
    width: int,
    height: int,
) -> BrowserContext:
    return browser.new_context(
        viewport={"width": width, "height": height},
        color_scheme="dark",
        device_scale_factor=1,
        locale="en-US",
        reduced_motion="reduce",
        service_workers="block",
        timezone_id="UTC",
    )


def _goto(page: Page, url: str, expected_status: int) -> None:
    response = page.goto(url, wait_until="networkidle")
    if response is None or response.status != expected_status:
        actual = None if response is None else response.status
        raise RuntimeError(f"expected HTTP {expected_status}, received {actual}")
    _assert_no_output(page)


def _settle_rendering(page: Page) -> None:
    page.evaluate(
        """async () => {
          await document.fonts.ready;
          for (const animation of document.getAnimations()) {
            try {
              animation.finish();
            } catch {
              animation.cancel();
            }
          }
          await new Promise((resolve) => {
            requestAnimationFrame(() => requestAnimationFrame(resolve));
          });
        }"""
    )


def _capture_full_document(
    page: Page,
    *,
    path: Path,
    width: int,
    viewport_height: int,
) -> None:
    if page.viewport_size != {"width": width, "height": viewport_height}:
        raise RuntimeError("full-document capture started from an invalid viewport")
    _settle_rendering(page)
    scroll_height = cast(
        int,
        page.evaluate("() => Math.ceil(document.documentElement.scrollHeight)"),
    )
    if not 1 <= scroll_height <= 16_000:
        raise RuntimeError("document height is outside the screenshot safety bound")
    page.evaluate("() => window.scrollTo(0, 0)")
    page.screenshot(path=path, animations="disabled", full_page=True)
    recompress_png(path)


def _capture_web_evidence() -> _CaptureResult:
    requests: list[dict[str, object]] = []
    external_requests: list[str] = []
    with _guarded_server() as server:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(
                headless=True,
                args=list(CHROMIUM_ARGS),
            )
            chromium_version = browser.version

            desktop = _new_context(browser, width=1440, height=960)
            desktop.route(
                "**/*",
                _local_request_router(
                    base_url=server.base_url,
                    external_requests=external_requests,
                ),
            )
            page = desktop.new_page()
            _goto(page, server.base_url, 200)
            _assert_no_overflow(page)
            metric_label = page.locator(".metric-wide dt").text_content()
            if metric_label is None or metric_label.strip() != (
                "Uniform-draw entropy bounds"
            ):
                raise RuntimeError("exact inspection is absent from the GET response")
            page.locator("details > summary").click()
            _capture_full_document(
                page,
                path=ASSET_DIR / "web-home.png",
                width=1440,
                viewport_height=960,
            )
            requests.append(
                {
                    "artifact": "docs/assets/web-home.png",
                    "method": "GET",
                    "path": "/",
                    "status": 200,
                    "viewport": {"height": 960, "width": 1440},
                    "assertions": [
                        "generated-output absent",
                        "sampler calls 0",
                        "external requests 0",
                        "inspection visible",
                        "no horizontal overflow",
                    ],
                }
            )

            page.set_viewport_size({"width": 390, "height": 844})
            _goto(page, server.base_url, 200)
            _assert_no_overflow(page)
            page.evaluate(
                "() => window.scrollTo(0, "
                "document.querySelector('.workspace').offsetTop - 12)"
            )
            _settle_rendering(page)
            page.screenshot(
                path=ASSET_DIR / "web-home-mobile.png",
                animations="disabled",
            )
            recompress_png(ASSET_DIR / "web-home-mobile.png")
            requests.append(
                {
                    "artifact": "docs/assets/web-home-mobile.png",
                    "method": "GET",
                    "path": "/",
                    "status": 200,
                    "viewport": {"height": 844, "width": 390},
                    "assertions": [
                        "generated-output absent",
                        "sampler calls 0",
                        "external requests 0",
                        "inspection visible",
                        "no horizontal overflow",
                        "workspace visible at mobile width",
                    ],
                }
            )

            page.set_viewport_size({"width": 1440, "height": 960})
            _goto(page, server.base_url, 200)
            page.locator("#length").fill("7")
            with page.expect_navigation(wait_until="networkidle") as navigation:
                page.locator("form").evaluate(
                    "(form) => HTMLFormElement.prototype.submit.call(form)"
                )
            invalid_response = navigation.value
            if invalid_response is None or invalid_response.status != 400:
                raise RuntimeError("invalid length did not produce HTTP 400")
            _assert_no_output(page)
            _assert_no_overflow(page)
            if page.locator("#length").get_attribute("aria-invalid") != "true":
                raise RuntimeError("invalid response lacks field error semantics")
            if (
                "Audit metrics are shown only"
                not in page.locator(".audit-withheld").inner_text()
            ):
                raise RuntimeError("invalid response did not withhold audit metrics")
            _capture_full_document(
                page,
                path=ASSET_DIR / "web-invalid-length.png",
                width=1440,
                viewport_height=960,
            )
            requests.append(
                {
                    "artifact": "docs/assets/web-invalid-length.png",
                    "method": "POST",
                    "path": "/",
                    "status": 400,
                    "viewport": {"height": 960, "width": 1440},
                    "assertions": [
                        "generated-output absent",
                        "sampler calls 0",
                        "external requests 0",
                        "invalid length 7 rejected before generation",
                        "audit metrics withheld",
                        "no horizontal overflow",
                    ],
                }
            )
            desktop.close()

            demo = _new_context(browser, width=1080, height=900)
            demo.route(
                "**/*",
                _local_request_router(
                    base_url=server.base_url,
                    external_requests=external_requests,
                ),
            )
            page = demo.new_page()
            _goto(page, server.base_url, 200)
            _assert_no_overflow(page)
            page.evaluate(
                "() => window.scrollTo(0, "
                "document.querySelector('.workspace').offsetTop - 12)"
            )
            _settle_rendering(page)
            frames = [page.screenshot(animations="disabled")]
            page.locator("#length").fill("7")
            page.locator("#length").evaluate("(element) => element.blur()")
            _settle_rendering(page)
            frames.append(page.screenshot(animations="disabled"))
            with page.expect_navigation(wait_until="networkidle") as navigation:
                page.locator("form").evaluate(
                    "(form) => HTMLFormElement.prototype.submit.call(form)"
                )
            demo_response = navigation.value
            if demo_response is None or demo_response.status != 400:
                raise RuntimeError("GIF validation sequence did not finish at HTTP 400")
            _assert_no_output(page)
            _assert_no_overflow(page)
            page.evaluate(
                "() => window.scrollTo(0, "
                "document.querySelector('.workspace').offsetTop - 12)"
            )
            _settle_rendering(page)
            frames.append(page.screenshot(animations="disabled"))
            fidelity = write_gif(
                frames=frames,
                path=ASSET_DIR / "web-validation-demo.gif",
                reference_path=(EVIDENCE_DIR / "web-validation-reference.png"),
            )
            if fidelity.frame_count != 3:
                raise RuntimeError("validation GIF must contain exactly three frames")
            requests.append(
                {
                    "artifact": "docs/assets/web-validation-demo.gif",
                    "method": "GET -> POST",
                    "path": "/",
                    "status": 400,
                    "viewport": {"height": 900, "width": 1080},
                    "assertions": [
                        "generated-output absent",
                        "sampler calls 0",
                        "external requests 0",
                        "sequence GET 200 -> input 7 -> POST 400",
                        "audit metrics withheld",
                        "no flashing; two transitions remain below 3 Hz",
                        "decoded GIF frames preserve full viewport composition",
                        "vertical frame order GET 200 -> input 7 -> POST 400",
                        "GIF frames pass independent 17x15 localized fidelity checks",
                        "GIF frames are opaque full-canvas images with disposal 1",
                    ],
                }
            )
            demo.close()
            browser.close()

        if external_requests:
            raise RuntimeError("browser capture attempted an external request")
        if server.sampler_calls[0] != 0:
            raise RuntimeError("browser evidence invoked the guarded sampler")
        return _CaptureResult(
            chromium=chromium_version,
            requests=requests,
            sampler_calls=server.sampler_calls[0],
        )


def _distribution_mapping(value: object, label: str) -> Mapping[str, object]:
    if type(value) is not dict:
        raise RuntimeError(f"distribution report field is not an object: {label}")
    return cast(dict[str, object], value)


def _distribution_digest(value: object, label: str) -> str:
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise RuntimeError(f"distribution report digest is invalid: {label}")
    return value


def _write_distribution_evidence() -> None:
    """Run one real attestation and render every derivative from that result."""

    document = distribution_attester.attest(ROOT)
    artifacts = _distribution_mapping(document.get("artifacts"), "artifacts")
    wheel = _distribution_mapping(artifacts.get("wheel"), "artifacts.wheel")
    sdist = _distribution_mapping(artifacts.get("sdist"), "artifacts.sdist")
    source = _distribution_mapping(document.get("source"), "source")
    input_sha256 = _distribution_digest(
        source.get("distribution_input_sha256"),
        "source.distribution_input_sha256",
    )
    wheel_sha256 = _distribution_digest(wheel.get("sha256"), "wheel.sha256")
    sdist_sha256 = _distribution_digest(sdist.get("sha256"), "sdist.sha256")

    json_text = distribution_attester._canonical_json(document)
    transcript = (
        "$ python scripts/attest_distribution.py\n"
        + distribution_attester._text_report(document)
    )
    if _ABSOLUTE_PATH.search(json_text) or _ABSOLUTE_PATH.search(transcript):
        raise RuntimeError("distribution evidence contains an absolute machine path")
    (EVIDENCE_DIR / "distribution-attestation.json").write_text(
        json_text,
        encoding="utf-8",
    )
    (EVIDENCE_DIR / "distribution-check.txt").write_text(
        transcript,
        encoding="utf-8",
    )
    render_terminal_png(
        transcript=transcript,
        title="Distribution attestation · canonical archives verified",
        path=ASSET_DIR / "distribution-check.png",
    )
    write_distribution_svg(
        ASSET_DIR / "distribution-contract.svg",
        input_sha256=input_sha256,
        wheel_sha256=wheel_sha256,
        sdist_sha256=sdist_sha256,
    )


def _normalize_quality_output(output: str) -> str:
    normalized = output.replace("\r\n", "\n").replace(str(ROOT), ".")
    normalized = _PYTEST_DURATION.sub(r"\g<summary>", normalized)
    if _ABSOLUTE_PATH.search(normalized):
        raise RuntimeError("quality output contains an absolute machine path")
    return normalized.rstrip() + "\n"


def _quality_invocations() -> tuple[tuple[str, ...], ...]:
    return (
        (str(PYTHON), "-m", "ruff", "check", "app.py", "scripts", "src", "tests"),
        (
            str(PYTHON),
            "-m",
            "ruff",
            "format",
            "--check",
            "app.py",
            "scripts",
            "src",
            "tests",
        ),
        (
            str(PYTHON),
            "-m",
            "mypy",
            "--strict",
            "app.py",
            "scripts",
            "src",
            "tests",
        ),
        (
            str(PYTHON),
            "-m",
            "pytest",
            "--cov=password_policy_lab",
            "--cov-branch",
            "--cov-report=term-missing",
            "-q",
        ),
        (str(PYTHON), "scripts/attest_distribution.py"),
        (str(PYTHON), "-m", "pip", "check"),
    )


def _run_quality_gate() -> str:
    sections: list[str] = []
    for label, invocation in zip(
        QUALITY_COMMANDS,
        _quality_invocations(),
        strict=True,
    ):
        output = _run(invocation)
        sections.append(f"$ {label}\n{_normalize_quality_output(output)}")
    return "\n".join(sections)


def _write_quality_evidence(transcript: str) -> None:
    (EVIDENCE_DIR / "quality-gate.txt").write_text(
        transcript,
        encoding="utf-8",
    )
    render_terminal_png(
        transcript=transcript,
        title="Project quality gate · all checks passed",
        path=ASSET_DIR / "quality-gate.png",
    )


def _source_paths() -> list[Path]:
    paths = [
        ROOT / ".github/workflows/verify.yml",
        ROOT / "MANIFEST.in",
        ROOT / "Makefile",
        ROOT / "PACKAGE.md",
        ROOT / "README.md",
        ROOT / "app.py",
        ROOT / "pyproject.toml",
    ]
    for directory in ("scripts", "src", "tests"):
        paths.extend(
            path
            for path in (ROOT / directory).rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and path.suffix in {".css", ".html", ".py", ".typed"}
        )
    return sorted(set(paths))


def _source_manifest() -> list[dict[str, object]]:
    return [
        {
            "path": path.relative_to(ROOT).as_posix(),
            "sha256": _sha256(path),
        }
        for path in _source_paths()
    ]


def _image_metadata(path: Path) -> dict[str, int]:
    image_module: Any = importlib.import_module("PIL.Image")
    with image_module.open(path) as image:
        metadata = {"height": int(image.height), "width": int(image.width)}
        if path.suffix == ".gif":
            metadata["frames"] = int(image.n_frames)
            if image.info.get("loop") is not None:
                raise RuntimeError("GIF evidence must not contain a loop extension")
    return metadata


def _svg_metadata(path: Path) -> dict[str, int]:
    root = ElementTree.parse(path).getroot()
    return {"height": int(root.attrib["height"]), "width": int(root.attrib["width"])}


def _artifact_assertions() -> dict[str, list[str]]:
    return {
        "docs/assets/architecture.svg": [
            "architecture imports and calls verified from AST",
            "web and CLI converge on one exact core",
        ],
        "docs/assets/cli-inspect.png": [
            "rendered from exact deterministic CLI transcript",
            "sampled candidate absent",
        ],
        "docs/assets/distribution-check.png": [
            "rendered from the real distribution attestation transcript",
            "canonical wheel, sdist rebuild, and installed smoke passed",
        ],
        "docs/assets/distribution-contract.svg": [
            "rendered from measured distribution hashes and member counts",
            "claim boundaries remain explicit",
        ],
        "docs/assets/dp-complexity-cli.png": [
            "deterministic profiler output with selected cProfile call counts",
            "timing, hardware, memory, entropy, and candidate output absent",
        ],
        "docs/assets/dp-layer-occupancy.svg": [
            "rendered from every observed accepted DP layer",
            "rejected policy has no invented occupancy curve",
        ],
        "docs/assets/dp-work-counts.svg": [
            "exact product-vector, materialized-cell, and transition counts",
            "balanced and skewed policies are directly comparable",
        ],
        "docs/assets/policy-sensitivity-cli.png": [
            "rendered from the real deterministic sensitivity transcript",
            "candidate and entropy output explicitly absent",
        ],
        "docs/assets/policy-sensitivity-impact.svg": [
            "rendered from the exact canonical sensitivity JSON",
            "one-step non-additive claim boundary is explicit",
        ],
        "docs/assets/quality-gate.png": [
            "rendered from normalized real gate transcript",
            "all commands exited zero",
        ],
        "docs/assets/setup-workflow.svg": [
            "commands verified against package metadata",
            "repository-local evidence workflow",
        ],
        "docs/assets/state-space-sweep.png": [
            "two aligned panels from 25 exact CLI rows",
            "satisfying share uses a linear 0-100 percent scale",
        ],
        "docs/assets/uniform-sampling-flow.svg": [
            "sample_uniform call shape verified from AST",
            "one randbelow call flows directly into unrank",
        ],
        "docs/assets/web-home-mobile.png": [
            "real Waitress GET response",
            "390 pixel viewport without horizontal overflow",
        ],
        "docs/assets/web-home.png": [
            "real Waitress GET response",
            "exact policy details expanded",
        ],
        "docs/assets/web-invalid-length.png": [
            "real Waitress POST response",
            "invalid length rejected with HTTP 400 before sampling",
        ],
        "docs/assets/web-validation-demo.gif": [
            "three real browser frames",
            "GET 200 to invalid POST 400 with no sampler call",
            "plays once with no flashing sequence",
            "decoded frames preserve the complete browser viewport",
        ],
        "docs/evidence/cli-inspect.txt": [
            "real CLI output",
            "timestamp and absolute path absent",
        ],
        "docs/evidence/distribution-attestation.json": [
            "canonical path-free report from two real builds",
            "exact archive inventories and honest claim boundaries",
        ],
        "docs/evidence/distribution-check.txt": [
            "real normalized attestation output",
            "no password sampled",
        ],
        "docs/evidence/dp-complexity-profile.json": [
            "canonical report from six real instrumented constructions",
            "independent occupancy and exact-count oracles agree",
        ],
        "docs/evidence/dp-complexity-profile.txt": [
            "real concise profiler command output",
            "no timing, hardware, memory, entropy, or candidate claim",
        ],
        "docs/evidence/policy-sensitivity.json": [
            "real canonical CLI JSON",
            "exact baseline, relaxed totals, additions, and reduced fractions",
        ],
        "docs/evidence/policy-sensitivity.txt": [
            "real deterministic CLI text",
            "one-step scope and non-additivity warning retained",
        ],
        "docs/evidence/quality-gate.txt": [
            "real normalized command output",
            "timing and absolute path absent",
        ],
        "docs/evidence/state-space-sweep.csv": [
            "real CLI output",
            "inclusive lengths 8 through 32",
        ],
        "docs/evidence/web-validation-reference.png": [
            "lossless full-resolution browser frame reference",
            "vertical frame order GET 200 -> input 7 -> POST 400",
            "three 1080 by 900 frames without gutters or captions",
        ],
    }


def _media_type(path: Path) -> str:
    return {
        ".csv": "text/csv",
        ".gif": "image/gif",
        ".json": "application/json",
        ".png": "image/png",
        ".svg": "image/svg+xml",
        ".txt": "text/plain",
    }[path.suffix]


def _artifact_manifest() -> list[dict[str, object]]:
    assertions = _artifact_assertions()
    artifacts: list[dict[str, object]] = []
    for relative in OUTPUT_PATHS:
        path = ROOT / relative
        if not path.is_file():
            raise RuntimeError(f"expected evidence artifact is missing: {relative}")
        entry: dict[str, object] = {
            "assertions": assertions[relative],
            "bytes": path.stat().st_size,
            "media_type": _media_type(path),
            "path": relative,
            "sha256": _sha256(path),
        }
        if path.suffix in {".gif", ".png"}:
            entry.update(_image_metadata(path))
        elif path.suffix == ".svg":
            entry.update(_svg_metadata(path))
        artifacts.append(entry)
    gif_size = (ROOT / "docs/assets/web-validation-demo.gif").stat().st_size
    if gif_size >= 8 * 1024 * 1024:
        raise RuntimeError("validation GIF exceeds the 8 MiB portfolio limit")
    return artifacts


def _runtime_manifest(chromium: str) -> dict[str, str]:
    machine = platform.machine().lower()
    normalized_machine = "x86_64" if machine in {"amd64", "x86_64"} else machine
    return {
        "chromium": chromium,
        "flask": importlib.metadata.version("Flask"),
        "matplotlib": importlib.metadata.version("matplotlib"),
        "numpy": importlib.metadata.version("numpy"),
        "pillow": importlib.metadata.version("Pillow"),
        "platform": f"{sys.platform}/{normalized_machine}",
        "playwright": importlib.metadata.version("playwright"),
        "python": platform.python_version(),
        "waitress": importlib.metadata.version("waitress"),
    }


def _manifest(
    *,
    capture: _CaptureResult,
    architecture_verified: bool,
    sampling_verified: bool,
    complexity_report: dict[str, object],
    sensitivity_report: dict[str, object],
) -> dict[str, object]:
    complexity_cases = cast(list[dict[str, object]], complexity_report["cases"])
    return {
        "artifacts": _artifact_manifest(),
        "capture": {
            "chromium_launch_args": list(CHROMIUM_ARGS),
            "requests": capture.requests,
            "sampler_calls": capture.sampler_calls,
            "sampling_guard": "raise-on-call",
            "server": "waitress",
        },
        "evidence": {
            "cli_inspect": {
                "contains_candidate": False,
                "source_command": INSPECT_COMMAND,
            },
            "diagrams": {
                "architecture_ast_verified": architecture_verified,
                "sampling_ast_verified": sampling_verified,
            },
            "dp_complexity_profile": {
                "accepted_scenarios": sum(
                    case["outcome"] == "accepted" for case in complexity_cases
                ),
                "contains_candidate": False,
                "counter_contract": complexity_report["counter_contract"],
                "json_source_command": PROFILE_JSON_COMMAND,
                "rejected_before_enumeration": sum(
                    case["outcome"] == "rejected-before-enumeration"
                    for case in complexity_cases
                ),
                "report_schema_version": complexity_report["schema_version"],
                "scenario_ids": [case["case_id"] for case in complexity_cases],
                "text_source_command": PROFILE_TEXT_COMMAND,
            },
            "policy_sensitivity": {
                "baseline_valid": sensitivity_report["baseline_valid"],
                "claim_boundary": sensitivity_report["claim_boundary"],
                "json_source_command": SENSITIVITY_JSON_COMMAND,
                "rows": len(cast(list[object], sensitivity_report["rows"])),
                "text_source_command": SENSITIVITY_TEXT_COMMAND,
            },
            "quality_gate": {
                "all_passed": True,
                "commands": list(QUALITY_COMMANDS),
            },
            "sweep": {
                "class_minima": {
                    "digits": 1,
                    "lower": 1,
                    "punctuation": 1,
                    "upper": 1,
                },
                "inclusive_range": {"end": 32, "start": 8},
                "profile": "visible-ascii-v1",
                "rows": 25,
                "source_command": SWEEP_COMMAND,
            },
        },
        "generator": "scripts/generate_evidence.py",
        "runtime": _runtime_manifest(capture.chromium),
        "schema_version": 2,
        "source_files": _source_manifest(),
    }


def _write_manifest(manifest: dict[str, object]) -> None:
    payload = json.dumps(
        manifest,
        ensure_ascii=True,
        indent=2,
        sort_keys=True,
    )
    if str(ROOT) in payload or _ABSOLUTE_PATH.search(payload):
        raise RuntimeError("manifest contains an absolute machine path")
    (EVIDENCE_DIR / "manifest.json").write_text(
        payload + "\n",
        encoding="utf-8",
    )


def _provisional_quality_transcript() -> str:
    existing = EVIDENCE_DIR / "quality-gate.txt"
    if existing.is_file() and (ASSET_DIR / "quality-gate.png").is_file():
        transcript = existing.read_text(encoding="utf-8")
        offsets = [transcript.find(command) for command in QUALITY_COMMANDS]
        if all(offset >= 0 for offset in offsets) and offsets == sorted(offsets):
            return transcript
    return (
        "\n".join(
            f"$ {command}\nprovisional evidence graph ready"
            for command in QUALITY_COMMANDS
        )
        + "\n"
    )


def main() -> int:
    """Generate all raw and visual evidence, then prove a stable gate fixed point."""

    _configure_environment()
    architecture_verified = _verify_architecture_ast()
    sampling_verified = _verify_sampling_ast()
    _verify_setup_contract()
    write_architecture_svg(ASSET_DIR / "architecture.svg")
    write_sampling_svg(ASSET_DIR / "uniform-sampling-flow.svg")
    write_setup_svg(ASSET_DIR / "setup-workflow.svg")
    _write_distribution_evidence()
    complexity_report = _write_complexity_evidence()

    sweep_rows, sensitivity_report = _write_cli_evidence()
    _render_sweep_chart(sweep_rows)
    capture = _capture_web_evidence()

    _write_quality_evidence(_provisional_quality_transcript())
    _write_manifest(
        _manifest(
            capture=capture,
            architecture_verified=architecture_verified,
            sampling_verified=sampling_verified,
            complexity_report=complexity_report,
            sensitivity_report=sensitivity_report,
        )
    )

    try:
        first_gate = _run_quality_gate()
        _write_quality_evidence(first_gate)
        _write_manifest(
            _manifest(
                capture=capture,
                architecture_verified=architecture_verified,
                sampling_verified=sampling_verified,
                complexity_report=complexity_report,
                sensitivity_report=sensitivity_report,
            )
        )
        second_gate = _run_quality_gate()
    except Exception:
        (EVIDENCE_DIR / "manifest.json").unlink(missing_ok=True)
        raise

    if first_gate.encode() != second_gate.encode():
        raise RuntimeError("normalized quality gate did not reach a fixed point")
    if (EVIDENCE_DIR / "quality-gate.txt").read_text(encoding="utf-8") != second_gate:
        raise RuntimeError("committed quality transcript differs from verified gate")
    print(
        f"Evidence rebuilt and verified: {len(OUTPUT_PATHS)} artifacts + "
        "canonical manifest."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
