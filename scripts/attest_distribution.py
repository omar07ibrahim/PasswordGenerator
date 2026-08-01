#!/usr/bin/env python3
"""Produce a bounded, source-bound distribution attestation.

The attestation is intentionally project-specific.  It builds only the exact
release inputs stored in Git's stage-zero index, normalizes archive container
metadata, proves the two normalized builds equal, rebuilds the wheel from the
canonical source distribution, and performs an offline target install.  It is
not a package signature or a general-purpose archive scanner.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
import tomllib
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal, Never, NoReturn, TextIO, cast

from distribution_contract import (
    DIST_INFO,
    FIXED_MTIME,
    SDIST_ROOT,
    ArtifactRecord,
    DistributionContractError,
    MemberRecord,
    ProjectPayloads,
    build_expected_metadata,
    canonicalize_sdist,
    canonicalize_wheel,
    inspect_sdist,
    inspect_wheel,
    materialize_canonical_sdist,
)

SCHEMA_VERSION = 1
PROJECT_NAME = "password-policy-state-space"
PROJECT_VERSION = "0.1.0"
NORMALIZED_NAME = "password_policy_state_space"
WHEEL_FILENAME = f"{NORMALIZED_NAME}-{PROJECT_VERSION}-py3-none-any.whl"
SDIST_FILENAME = f"{NORMALIZED_NAME}-{PROJECT_VERSION}.tar.gz"
DEFAULT_WORK_ROOT = ".evidence-work/distribution"

BUILD_VERSION = "1.5.0"
SETUPTOOLS_VERSION = "83.0.0"
FLASK_VERSION = "3.1.3"
WAITRESS_VERSION = "3.0.2"

COMMAND_TIMEOUT_SECONDS = 240.0
MAX_COMMAND_OUTPUT = 2 * 1024 * 1024
MAX_SOURCE_FILE = 2 * 1024 * 1024
MAX_PACKAGE_WORKTREE_ENTRIES = 256
_READ_CHUNK = 64 * 1024
_OBJECT_ID = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")

PACKAGE_INPUTS = (
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
DISTRIBUTION_INPUTS = tuple(
    sorted(("MANIFEST.in", "PACKAGE.md", "pyproject.toml", *PACKAGE_INPUTS))
)

# Setuptools emits Python modules before package-data files in wheels.
WHEEL_MEMBERS = (
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
    f"{DIST_INFO}/METADATA",
    f"{DIST_INFO}/WHEEL",
    f"{DIST_INFO}/entry_points.txt",
    f"{DIST_INFO}/top_level.txt",
    f"{DIST_INFO}/RECORD",
)

_EGG_INFO = "src/password_policy_state_space.egg-info"
SDIST_FILES = tuple(
    sorted(
        {
            "MANIFEST.in",
            "PACKAGE.md",
            "PKG-INFO",
            "pyproject.toml",
            "setup.cfg",
            *PACKAGE_INPUTS,
            f"{_EGG_INFO}/PKG-INFO",
            f"{_EGG_INFO}/SOURCES.txt",
            f"{_EGG_INFO}/dependency_links.txt",
            f"{_EGG_INFO}/entry_points.txt",
            f"{_EGG_INFO}/requires.txt",
            f"{_EGG_INFO}/top_level.txt",
        }
    )
)

_DEV_DEPENDENCIES = (
    "build==1.5.0",
    "matplotlib==3.11.1",
    "mypy==2.3.0",
    "numpy==2.3.5",
    "Pillow==12.3.0",
    "playwright==1.61.0",
    "pytest==9.1.1",
    "pytest-cov==7.1.0",
    "ruff==0.16.0",
    "setuptools==83.0.0",
)
_SETUP_CFG = b"[egg_info]\ntag_build = \ntag_date = 0\n\n"
_DEPENDENCY_LINKS = b"\n"
_REQUIRES = (
    b"Flask==3.1.3\n"
    b"waitress==3.0.2\n"
    b"\n"
    b"[dev]\n" + "\n".join(_DEV_DEPENDENCIES).encode("ascii") + b"\n"
)
_SOURCES = "\n".join(
    (
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
        "src/password_policy_lab/web.py",
        "src/password_policy_lab/static/styles.css",
        "src/password_policy_lab/templates/index.html",
        f"{_EGG_INFO}/PKG-INFO",
        f"{_EGG_INFO}/SOURCES.txt",
        f"{_EGG_INFO}/dependency_links.txt",
        f"{_EGG_INFO}/entry_points.txt",
        f"{_EGG_INFO}/requires.txt",
        f"{_EGG_INFO}/top_level.txt",
    )
).encode("ascii")

AttestationCode = Literal[
    "arguments-invalid",
    "archive-contract",
    "artifact-mismatch",
    "build-failed",
    "build-output-invalid",
    "index-invalid",
    "internal-io",
    "repository-invalid",
    "smoke-failed",
    "source-dirty",
    "source-payload-mismatch",
    "subprocess-output",
    "subprocess-timeout",
    "toolchain-invalid",
    "work-root-invalid",
]


class AttestationError(ValueError):
    """A value-free, stable attestation failure."""

    __slots__ = ("code",)

    def __init__(self, code: AttestationCode) -> None:
        self.code = code
        super().__init__(f"distribution attestation rejected: {code}")


@dataclass(frozen=True, slots=True)
class IndexEntry:
    """One regular stage-zero Git index entry."""

    path: str
    object_id: str


@dataclass(frozen=True, slots=True)
class SourceFile:
    """Trusted content read from a stage-zero Git blob."""

    path: str
    data: bytes
    sha256: str


@dataclass(frozen=True, slots=True)
class SourceState:
    """The exact source inputs and their Git provenance."""

    files: tuple[SourceFile, ...]
    input_sha256: str
    tree: str
    revision: str | None

    def payload(self, path: str) -> bytes:
        for source_file in self.files:
            if source_file.path == path:
                return source_file.data
        raise AttestationError("index-invalid")


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Bounded subprocess output."""

    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class BuiltArtifacts:
    """The exact two artifacts accepted from one build invocation."""

    wheel: Path
    sdist: Path


@dataclass(frozen=True, slots=True)
class Toolchain:
    """Versions explicitly required by the attestation."""

    python: str
    build: str
    setuptools: str
    flask: str
    waitress: str


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> Never:
        del message
        raise AttestationError("arguments-invalid")


class _StoreOnce(argparse.Action):
    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: object,
        option_string: str | None = None,
    ) -> None:
        marker = f"_seen_{self.dest}"
        if getattr(namespace, marker, False):
            parser.error(f"{option_string} may be specified only once")
        setattr(namespace, marker, True)
        setattr(namespace, self.dest, values)


def _reject(code: AttestationCode) -> NoReturn:
    raise AttestationError(code)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_index_entries(raw: bytes) -> tuple[IndexEntry, ...]:
    """Parse ``git ls-files --stage -z`` without accepting quoted paths."""

    if not raw:
        return ()
    records = raw.split(b"\0")
    if records[-1] != b"":
        _reject("index-invalid")
    result: list[IndexEntry] = []
    observed: set[str] = set()
    for raw_record in records[:-1]:
        try:
            header, raw_path = raw_record.split(b"\t", 1)
            mode, object_id, stage = header.decode("ascii").split(" ")
            path = raw_path.decode("ascii")
        except (UnicodeError, ValueError):
            _reject("index-invalid")
        if (
            mode != "100644"
            or stage != "0"
            or _OBJECT_ID.fullmatch(object_id) is None
            or path in observed
            or path != PurePosixPath(path).as_posix()
            or PurePosixPath(path).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
        ):
            _reject("index-invalid")
        observed.add(path)
        result.append(IndexEntry(path, object_id))
    return tuple(result)


def _parse_tree_entries(raw: bytes) -> tuple[IndexEntry, ...]:
    """Parse regular blobs from ``git ls-tree -r -z``."""

    if not raw:
        return ()
    records = raw.split(b"\0")
    if records[-1] != b"":
        _reject("repository-invalid")
    result: list[IndexEntry] = []
    observed: set[str] = set()
    for raw_record in records[:-1]:
        try:
            header, raw_path = raw_record.split(b"\t", 1)
            mode, object_type, object_id = header.decode("ascii").split(" ")
            path = raw_path.decode("ascii")
        except (UnicodeError, ValueError):
            _reject("repository-invalid")
        if (
            mode != "100644"
            or object_type != "blob"
            or _OBJECT_ID.fullmatch(object_id) is None
            or path in observed
            or path != PurePosixPath(path).as_posix()
            or PurePosixPath(path).is_absolute()
            or any(part in {"", ".", ".."} for part in PurePosixPath(path).parts)
        ):
            _reject("repository-invalid")
        observed.add(path)
        result.append(IndexEntry(path, object_id))
    return tuple(result)


def _matching_inputs_revision(
    index_entries: Sequence[IndexEntry],
    head_entries: Sequence[IndexEntry],
    revision: str,
) -> str | None:
    """Return HEAD only when it contains every exact distribution input blob."""

    if _OBJECT_ID.fullmatch(revision) is None:
        _reject("repository-invalid")
    indexed = {entry.path: entry.object_id for entry in index_entries}
    committed = {entry.path: entry.object_id for entry in head_entries}
    if (
        len(indexed) != len(index_entries)
        or len(committed) != len(head_entries)
        or set(indexed) != set(DISTRIBUTION_INPUTS)
    ):
        _reject("repository-invalid")
    return revision if committed == indexed else None


def _canonical_input_digest(files: Sequence[tuple[str, bytes]]) -> str:
    """Hash a length-framed, lexicographically ordered source payload."""

    digest = hashlib.sha256()
    previous: str | None = None
    for path, data in sorted(files):
        if previous == path or path not in DISTRIBUTION_INPUTS:
            _reject("index-invalid")
        encoded_path = path.encode("ascii")
        digest.update(len(encoded_path).to_bytes(4, "big"))
        digest.update(encoded_path)
        digest.update(len(data).to_bytes(8, "big"))
        digest.update(data)
        previous = path
    if previous is None or len(files) != len(DISTRIBUTION_INPUTS):
        _reject("index-invalid")
    return digest.hexdigest()


def _process_environment(
    temporary_root: Path,
    *,
    python_path: Path | None = None,
) -> dict[str, str]:
    """Return a fixed allowlisted environment, never an inherited copy."""

    executable_directory = str(Path(sys.executable).resolve().parent)
    environment = {
        "HOME": str(temporary_root / "home"),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": os.pathsep.join((executable_directory, "/usr/bin", "/bin")),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": str(FIXED_MTIME),
        "TMPDIR": str(temporary_root / "tmp"),
        "TZ": "UTC",
    }
    if python_path is not None:
        environment["PYTHONPATH"] = str(python_path)
    return environment


def _prepare_environment_directories(environment: Mapping[str, str]) -> None:
    for key in ("HOME", "TMPDIR"):
        directory = Path(environment[key])
        directory.mkdir(parents=True, mode=0o700, exist_ok=False)


def _child_setup() -> None:
    os.umask(0o022)
    os.setsid()


def _terminate(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    if process.poll() is None:
        process.wait()


def _run_command(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    failure_code: AttestationCode,
    timeout: float = COMMAND_TIMEOUT_SECONDS,
    maximum_output: int = MAX_COMMAND_OUTPUT,
) -> CommandResult:
    """Run one process with bounded time, combined output, and a fixed umask."""

    if not command or timeout <= 0 or maximum_output <= 0:
        _reject(failure_code)
    try:
        process = subprocess.Popen(
            tuple(command),
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=_child_setup,
        )
    except OSError:
        _reject(failure_code)

    if process.stdout is None or process.stderr is None:
        _terminate(process)
        _reject(failure_code)
    output = {"stdout": bytearray(), "stderr": bytearray()}
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ, "stdout")
    selector.register(process.stderr, selectors.EVENT_READ, "stderr")
    deadline = time.monotonic() + timeout
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate(process)
                _reject("subprocess-timeout")
            for key, _ in selector.select(min(remaining, 0.1)):
                chunk = os.read(key.fd, _READ_CHUNK)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                channel = cast(Literal["stdout", "stderr"], key.data)
                output[channel].extend(chunk)
                if len(output["stdout"]) + len(output["stderr"]) > maximum_output:
                    _terminate(process)
                    _reject("subprocess-output")
        return_code = process.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        _terminate(process)
        _reject("subprocess-timeout")
    finally:
        selector.close()
        process.stdout.close()
        process.stderr.close()
    if return_code != 0:
        _reject(failure_code)
    return CommandResult(bytes(output["stdout"]), bytes(output["stderr"]))


def _git(
    repository: Path,
    arguments: Sequence[str],
    *,
    maximum_output: int = MAX_COMMAND_OUTPUT,
) -> bytes:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "/usr/bin:/bin",
        "TZ": "UTC",
    }
    result = _run_command(
        ("git", "-c", "core.quotepath=false", *arguments),
        cwd=repository,
        environment=environment,
        failure_code="repository-invalid",
        timeout=30.0,
        maximum_output=maximum_output,
    )
    if result.stderr:
        _reject("repository-invalid")
    return result.stdout


def _validate_project_configuration(raw: bytes) -> None:
    try:
        document = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError):
        _reject("source-payload-mismatch")
    build_system = document.get("build-system")
    project = document.get("project")
    if not isinstance(build_system, dict) or not isinstance(project, dict):
        _reject("source-payload-mismatch")
    if build_system != {
        "requires": [f"setuptools=={SETUPTOOLS_VERSION}"],
        "build-backend": "setuptools.build_meta",
    }:
        _reject("source-payload-mismatch")
    if (
        project.get("name") != PROJECT_NAME
        or project.get("version") != PROJECT_VERSION
        or project.get("requires-python") != ">=3.11"
        or project.get("dependencies")
        != [f"Flask=={FLASK_VERSION}", f"waitress=={WAITRESS_VERSION}"]
        or project.get("readme")
        != {"file": "PACKAGE.md", "content-type": "text/markdown"}
        or project.get("license") is not None
        or project.get("scripts")
        != {"password-policy-lab": "password_policy_lab.cli:main"}
    ):
        _reject("source-payload-mismatch")
    optional = project.get("optional-dependencies")
    if not isinstance(optional, dict) or optional != {"dev": list(_DEV_DEPENDENCIES)}:
        _reject("source-payload-mismatch")


def _validate_working_package_inventory(repository: Path) -> None:
    """Reject ignored as well as visible unexpected package-tree files."""

    package_root = repository / "src/password_policy_lab"
    expected_files = set(PACKAGE_INPUTS)
    expected_directories = {
        str(PurePosixPath(path).parent)
        for path in PACKAGE_INPUTS
        if str(PurePosixPath(path).parent) != "src/password_policy_lab"
    }
    entry_count = 0
    try:
        for item in package_root.rglob("*"):
            entry_count += 1
            if entry_count > MAX_PACKAGE_WORKTREE_ENTRIES:
                _reject("index-invalid")
            metadata = item.lstat()
            relative = item.relative_to(repository).as_posix()
            package_relative = item.relative_to(package_root)
            cache_parts = package_relative.parts
            if "__pycache__" in cache_parts:
                if item.is_symlink() or (
                    stat.S_ISREG(metadata.st_mode) and item.suffix != ".pyc"
                ):
                    _reject("index-invalid")
                if not (
                    stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)
                ):
                    _reject("index-invalid")
                continue
            if item.is_symlink():
                _reject("source-dirty")
            if stat.S_ISDIR(metadata.st_mode):
                if relative not in expected_directories:
                    _reject("index-invalid")
            elif not stat.S_ISREG(metadata.st_mode) or relative not in expected_files:
                _reject("index-invalid")
    except OSError:
        _reject("source-dirty")


def _validate_worktree_payloads(
    repository: Path,
    source_files: Sequence[SourceFile],
) -> None:
    if {item.path for item in source_files} != set(DISTRIBUTION_INPUTS):
        _reject("index-invalid")
    untracked_package = _git(
        repository,
        (
            "ls-files",
            "--others",
            "--exclude-standard",
            "-z",
            "--",
            "src/password_policy_lab",
        ),
    )
    if untracked_package:
        _reject("index-invalid")
    _validate_working_package_inventory(repository)
    for source_file in source_files:
        destination = repository.joinpath(*source_file.path.split("/"))
        try:
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode):
                _reject("source-dirty")
            working_data = destination.read_bytes()
        except OSError:
            _reject("source-dirty")
        if working_data != source_file.data:
            _reject("source-dirty")


def _collect_source(repository: Path) -> SourceState:
    """Read the exact distribution payload from Git's stage-zero index."""

    try:
        root = repository.resolve(strict=True)
        metadata = root.stat()
    except OSError:
        _reject("repository-invalid")
    if not stat.S_ISDIR(metadata.st_mode) or (root / ".git").is_symlink():
        _reject("repository-invalid")
    top_level = _git(root, ("rev-parse", "--show-toplevel")).decode("utf-8").strip()
    try:
        if Path(top_level).resolve(strict=True) != root:
            _reject("repository-invalid")
    except OSError:
        _reject("repository-invalid")

    source_tree = _git(root, ("write-tree",)).decode("ascii").strip()
    if _OBJECT_ID.fullmatch(source_tree) is None:
        _reject("repository-invalid")
    entries = _parse_tree_entries(
        _git(
            root,
            (
                "ls-tree",
                "-r",
                "-z",
                source_tree,
                "--",
                "MANIFEST.in",
                "PACKAGE.md",
                "pyproject.toml",
                "src/password_policy_lab",
            ),
        )
    )
    by_path = {entry.path: entry for entry in entries}
    if set(by_path) != set(DISTRIBUTION_INPUTS):
        _reject("index-invalid")

    source_files: list[SourceFile] = []
    for path in DISTRIBUTION_INPUTS:
        entry = by_path[path]
        indexed_data = _git(
            root,
            ("cat-file", "blob", entry.object_id),
            maximum_output=MAX_SOURCE_FILE + 1,
        )
        if len(indexed_data) > MAX_SOURCE_FILE:
            _reject("index-invalid")
        source_files.append(SourceFile(path, indexed_data, _sha256(indexed_data)))

    _validate_worktree_payloads(root, source_files)
    _validate_project_configuration(
        next(item.data for item in source_files if item.path == "pyproject.toml")
    )
    candidate_revision = (
        _git(
            root,
            ("rev-parse", "--verify", "HEAD"),
        )
        .decode("ascii")
        .strip()
    )
    if _OBJECT_ID.fullmatch(candidate_revision) is None:
        _reject("repository-invalid")
    head_entries = _parse_tree_entries(
        _git(
            root,
            (
                "ls-tree",
                "-r",
                "-z",
                candidate_revision,
                "--",
                "MANIFEST.in",
                "PACKAGE.md",
                "pyproject.toml",
                "src/password_policy_lab",
            ),
        )
    )
    revision = _matching_inputs_revision(entries, head_entries, candidate_revision)
    final_tree = _git(root, ("write-tree",)).decode("ascii").strip()
    if final_tree != source_tree:
        _reject("source-dirty")
    _validate_worktree_payloads(root, source_files)
    pairs = tuple((item.path, item.data) for item in source_files)
    return SourceState(
        tuple(source_files),
        _canonical_input_digest(pairs),
        source_tree,
        revision,
    )


def _validate_work_root(repository: Path, raw_path: str) -> Path:
    pure = PurePosixPath(raw_path)
    if (
        not raw_path
        or raw_path != pure.as_posix()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        _reject("work-root-invalid")
    candidate = (
        Path(raw_path) if pure.is_absolute() else repository.joinpath(*pure.parts)
    )
    try:
        resolved_repository = repository.resolve(strict=True)
        lexical_relative = candidate.relative_to(resolved_repository)
        if not lexical_relative.parts:
            _reject("work-root-invalid")
        candidate.resolve(strict=False).relative_to(resolved_repository)
        current = repository
        for component in lexical_relative.parts:
            current /= component
            if current.exists() and current.is_symlink():
                _reject("work-root-invalid")
        candidate.mkdir(parents=True, mode=0o700, exist_ok=True)
        if not candidate.is_dir() or candidate.is_symlink():
            _reject("work-root-invalid")
    except (OSError, ValueError):
        _reject("work-root-invalid")
    return candidate


def _repository_argument(raw_path: str) -> Path:
    pure = PurePosixPath(raw_path)
    if (
        not raw_path
        or raw_path != pure.as_posix()
        or not pure.is_absolute()
        or any(part in {"", ".", ".."} for part in pure.parts)
    ):
        _reject("arguments-invalid")
    candidate = Path(raw_path)
    try:
        if candidate.is_symlink() or candidate.resolve(strict=True) != candidate:
            _reject("arguments-invalid")
    except OSError:
        _reject("arguments-invalid")
    return candidate


def _materialize_snapshot(destination: Path, source: SourceState) -> None:
    try:
        destination.mkdir(mode=0o755, exist_ok=False)
        for source_file in source.files:
            output = destination.joinpath(*source_file.path.split("/"))
            output.parent.mkdir(parents=True, mode=0o755, exist_ok=True)
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o644,
            )
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                stream.write(source_file.data)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(output, 0o644, follow_symlinks=False)
            os.utime(
                output,
                (FIXED_MTIME, FIXED_MTIME),
                follow_symlinks=False,
            )
        directories = [
            destination,
            *[item for item in destination.rglob("*") if item.is_dir()],
        ]
        for directory in sorted(
            directories,
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            os.chmod(directory, 0o755, follow_symlinks=False)
            os.utime(
                directory,
                (FIXED_MTIME, FIXED_MTIME),
                follow_symlinks=False,
            )
    except OSError:
        _reject("internal-io")


def _check_toolchain() -> Toolchain:
    running_version = (sys.version_info.major, sys.version_info.minor)
    if running_version < (3, 11):
        _reject("toolchain-invalid")
    expected = {
        "build": BUILD_VERSION,
        "setuptools": SETUPTOOLS_VERSION,
        "Flask": FLASK_VERSION,
        "waitress": WAITRESS_VERSION,
    }
    observed: dict[str, str] = {}
    try:
        for package, version in expected.items():
            observed[package] = importlib.metadata.version(package)
            if observed[package] != version:
                _reject("toolchain-invalid")
    except importlib.metadata.PackageNotFoundError:
        _reject("toolchain-invalid")
    return Toolchain(
        python=".".join(str(part) for part in sys.version_info[:3]),
        build=observed["build"],
        setuptools=observed["setuptools"],
        flask=observed["Flask"],
        waitress=observed["waitress"],
    )


def _build(
    snapshot: Path,
    output: Path,
    environment_root: Path,
    *,
    wheel_only: bool = False,
) -> BuiltArtifacts | Path:
    output.mkdir(mode=0o755, exist_ok=False)
    environment = _process_environment(environment_root)
    _prepare_environment_directories(environment)
    command = [
        sys.executable,
        "-m",
        "build",
        "--no-isolation",
    ]
    if wheel_only:
        command.append("--wheel")
    command.extend(("--outdir", str(output), "."))
    _run_command(
        command,
        cwd=snapshot,
        environment=environment,
        failure_code="build-failed",
    )
    try:
        observed = tuple(sorted(item.name for item in output.iterdir()))
        if any(item.is_symlink() or not item.is_file() for item in output.iterdir()):
            _reject("build-output-invalid")
    except OSError:
        _reject("build-output-invalid")
    if wheel_only:
        if observed != (WHEEL_FILENAME,):
            _reject("build-output-invalid")
        return output / WHEEL_FILENAME
    if observed != tuple(sorted((WHEEL_FILENAME, SDIST_FILENAME))):
        _reject("build-output-invalid")
    return BuiltArtifacts(output / WHEEL_FILENAME, output / SDIST_FILENAME)


def _files_equal(first: Path, second: Path) -> bool:
    try:
        if first.stat().st_size != second.stat().st_size:
            return False
        with first.open("rb") as left, second.open("rb") as right:
            while True:
                left_chunk = left.read(_READ_CHUNK)
                right_chunk = right.read(_READ_CHUNK)
                if left_chunk != right_chunk:
                    return False
                if not left_chunk:
                    return True
    except OSError:
        _reject("internal-io")


def _member_map(record: ArtifactRecord) -> dict[str, MemberRecord]:
    result = {member.name: member for member in record.members}
    if len(result) != len(record.members):
        _reject("source-payload-mismatch")
    return result


def _require_member(
    members: Mapping[str, MemberRecord],
    name: str,
    data: bytes,
) -> None:
    member = members.get(name)
    if member is None or member.size != len(data) or member.sha256 != _sha256(data):
        _reject("source-payload-mismatch")


def _verify_wheel_payloads(
    record: ArtifactRecord,
    source: SourceState,
    payloads: ProjectPayloads,
) -> None:
    members = _member_map(record)
    for path in PACKAGE_INPUTS:
        _require_member(members, path.removeprefix("src/"), source.payload(path))
    _require_member(members, f"{DIST_INFO}/METADATA", payloads.metadata)
    _require_member(members, f"{DIST_INFO}/WHEEL", payloads.wheel)
    _require_member(
        members,
        f"{DIST_INFO}/entry_points.txt",
        payloads.entry_points,
    )
    _require_member(members, f"{DIST_INFO}/top_level.txt", payloads.top_level)


def _verify_sdist_payloads(
    record: ArtifactRecord,
    source: SourceState,
    payloads: ProjectPayloads,
) -> None:
    members = _member_map(record)
    for path in DISTRIBUTION_INPUTS:
        _require_member(members, f"{SDIST_ROOT}/{path}", source.payload(path))
    generated = {
        "PKG-INFO": payloads.metadata,
        "setup.cfg": _SETUP_CFG,
        f"{_EGG_INFO}/PKG-INFO": payloads.metadata,
        f"{_EGG_INFO}/SOURCES.txt": _SOURCES,
        f"{_EGG_INFO}/dependency_links.txt": _DEPENDENCY_LINKS,
        f"{_EGG_INFO}/entry_points.txt": payloads.entry_points,
        f"{_EGG_INFO}/requires.txt": _REQUIRES,
        f"{_EGG_INFO}/top_level.txt": payloads.top_level,
    }
    for path, data in generated.items():
        _require_member(members, f"{SDIST_ROOT}/{path}", data)


_SMOKE_PROGRAM = r"""
import hashlib
import importlib.metadata
import io
import json
import os
import sys
from pathlib import Path

target = Path(os.environ["ATTEST_TARGET"]).resolve(strict=True)
sys.path.insert(0, str(target))
import password_policy_lab
from password_policy_lab.cli import run

module_path = Path(password_policy_lab.__file__).resolve(strict=True)
if not module_path.is_relative_to(target):
    raise SystemExit(21)
distribution = importlib.metadata.distribution("password-policy-state-space")
metadata_root = Path(distribution.locate_file("")).resolve(strict=True)
if not metadata_root.is_relative_to(target):
    raise SystemExit(22)
if distribution.version != "0.1.0":
    raise SystemExit(23)
if not (target / "password_policy_state_space-0.1.0.dist-info/METADATA").is_file():
    raise SystemExit(29)
entry_points = {
    (item.group, item.name, item.value) for item in distribution.entry_points
}
if entry_points != {
    ("console_scripts", "password-policy-lab", "password_policy_lab.cli:main")
}:
    raise SystemExit(24)
for relative in (
    "password_policy_lab/static/styles.css",
    "password_policy_lab/templates/index.html",
):
    if not (target / relative).is_file():
        raise SystemExit(25)

def invoke():
    stdout = io.StringIO()
    stderr = io.StringIO()
    status = run(
        ["inspect", "--length", "20", "--format", "json"],
        stdin=io.StringIO(""),
        stdout=stdout,
        stderr=stderr,
    )
    if status != 0 or stderr.getvalue():
        raise SystemExit(26)
    return stdout.getvalue()

first = invoke()
second = invoke()
if first != second:
    raise SystemExit(27)
payload = json.loads(first)

def object_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from object_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from object_keys(child)

if not isinstance(payload, dict) or payload.get("operation") != "inspect":
    raise SystemExit(28)
forbidden_keys = {
    "candidate",
    "generated_password",
    "password",
    "sample",
    "sampled_password",
    "secret",
}
if forbidden_keys.intersection(object_keys(payload)):
    raise SystemExit(29)
print(json.dumps({
    "inspect_sha256": hashlib.sha256(first.encode("utf-8")).hexdigest(),
    "metadata_origin_in_target": True,
    "package_origin_in_target": True,
    "resources_present": True,
}, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
"""


def _smoke_install(
    wheel: Path,
    run_root: Path,
) -> dict[str, object]:
    target = run_root / "smoke-target"
    cwd = run_root / "smoke-cwd"
    cwd.mkdir(mode=0o755, exist_ok=False)
    install_environment = _process_environment(run_root / "pip-environment")
    _prepare_environment_directories(install_environment)
    _run_command(
        (
            sys.executable,
            "-m",
            "pip",
            "install",
            "--isolated",
            "--no-index",
            "--no-deps",
            "--no-compile",
            "--target",
            str(target),
            str(wheel),
        ),
        cwd=cwd,
        environment=install_environment,
        failure_code="smoke-failed",
    )
    smoke_environment = _process_environment(
        run_root / "smoke-environment",
        python_path=target,
    )
    smoke_environment["ATTEST_TARGET"] = str(target)
    _prepare_environment_directories(smoke_environment)
    result = _run_command(
        (sys.executable, "-I", "-c", _SMOKE_PROGRAM),
        cwd=cwd,
        environment=smoke_environment,
        failure_code="smoke-failed",
        timeout=60.0,
        maximum_output=16 * 1024,
    )
    if result.stderr or not result.stdout.endswith(b"\n"):
        _reject("smoke-failed")
    try:
        document = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError):
        _reject("smoke-failed")
    if not isinstance(document, dict) or set(document) != {
        "inspect_sha256",
        "metadata_origin_in_target",
        "package_origin_in_target",
        "resources_present",
    }:
        _reject("smoke-failed")
    digest = document.get("inspect_sha256")
    if (
        not isinstance(digest, str)
        or re.fullmatch(r"[0-9a-f]{64}", digest) is None
        or document.get("metadata_origin_in_target") is not True
        or document.get("package_origin_in_target") is not True
        or document.get("resources_present") is not True
    ):
        _reject("smoke-failed")
    return cast(dict[str, object], document)


def _member_document(member: MemberRecord) -> dict[str, object]:
    return {
        "compressed_size": member.compressed_size,
        "mode": f"{member.mode & 0o7777:04o}",
        "mtime": member.mtime,
        "name": member.name,
        "sha256": member.sha256,
        "size": member.size,
    }


def _artifact_document(record: ArtifactRecord) -> dict[str, object]:
    return {
        "inventory": [_member_document(member) for member in record.members],
        "member_count": len(record.members),
        "sha256": record.sha256,
        "size": record.size,
    }


def _validate_claim_guards(
    *,
    raw_wheels_equal: bool,
    canonical_wheels_equal: bool,
    canonical_sdists_equal: bool,
    rebuilt_wheel_equal: bool,
    smoke_passed: bool,
) -> None:
    if not (
        raw_wheels_equal
        and canonical_wheels_equal
        and canonical_sdists_equal
        and rebuilt_wheel_equal
    ):
        _reject("artifact-mismatch")
    if not smoke_passed:
        _reject("smoke-failed")


def _build_report(
    *,
    source: SourceState,
    toolchain: Toolchain,
    raw_wheels: tuple[ArtifactRecord, ArtifactRecord],
    raw_sdists: tuple[ArtifactRecord, ArtifactRecord],
    wheel: ArtifactRecord,
    sdist: ArtifactRecord,
    smoke: Mapping[str, object],
    raw_wheels_equal: bool,
    canonical_wheels_equal: bool,
    canonical_sdists_equal: bool,
    rebuilt_wheel_equal: bool,
    smoke_passed: bool,
) -> dict[str, object]:
    """Create the path-free claim document from already verified facts."""

    _validate_claim_guards(
        raw_wheels_equal=raw_wheels_equal,
        canonical_wheels_equal=canonical_wheels_equal,
        canonical_sdists_equal=canonical_sdists_equal,
        rebuilt_wheel_equal=rebuilt_wheel_equal,
        smoke_passed=smoke_passed,
    )
    wheel_document = _artifact_document(wheel)
    wheel_document.update(
        {
            "canonical_builds_byte_equal": canonical_wheels_equal,
            "filename": WHEEL_FILENAME,
            "raw_build_count": len(raw_wheels),
            "raw_builds_byte_equal": raw_wheels_equal,
            "sdist_rebuild_byte_equal": rebuilt_wheel_equal,
        }
    )
    sdist_document = _artifact_document(sdist)
    sdist_document.update(
        {
            "canonical_builds_byte_equal": canonical_sdists_equal,
            "filename": SDIST_FILENAME,
            "raw_build_count": len(raw_sdists),
            "raw_builds_byte_equality_claimed": False,
        }
    )
    return {
        "artifacts": {"sdist": sdist_document, "wheel": wheel_document},
        "build": {
            "build_count": 2,
            "build_isolation": False,
            "fixed_source_date_epoch": FIXED_MTIME,
            "locale": "C.UTF-8",
            "network_package_index_enabled": False,
            "timezone": "UTC",
            "umask": "0022",
        },
        "claim_boundaries": {
            "arbitrary_archive_safety": False,
            "artifact_signature_verified": False,
            "cross_platform_reproducibility": False,
            "dependency_integrity_verified": False,
            "fresh_dependency_environment": False,
            "license_declared": False,
        },
        "official": False,
        "schema_version": SCHEMA_VERSION,
        "smoke": {
            "command": "inspect --length 20 --format json",
            "current_checker_dependencies": {
                "Flask": toolchain.flask,
                "waitress": toolchain.waitress,
            },
            "dependency_install_mode": "current-pinned-checker-environment",
            "deterministic": smoke_passed,
            "inspect_sha256": smoke["inspect_sha256"],
            "metadata_origin_in_target": True,
            "package_origin_in_target": True,
            "pip_compile_bytecode": False,
            "pip_dependency_resolution": False,
            "pip_index_enabled": False,
            "resources_present": True,
            "sampled_password": False,
        },
        "source": {
            "distribution_input_count": len(source.files),
            "distribution_input_sha256": source.input_sha256,
            "distribution_inputs_revision": source.revision,
            "git_index_stage": 0,
            "git_index_tree": source.tree,
        },
        "toolchain": {
            "build": toolchain.build,
            "python": toolchain.python,
            "setuptools": toolchain.setuptools,
        },
    }


def _canonical_json(document: Mapping[str, object]) -> str:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
            separators=(",", ": "),
        )
        + "\n"
    )


def _text_report(document: Mapping[str, object]) -> str:
    artifacts = cast(dict[str, dict[str, object]], document["artifacts"])
    source = cast(dict[str, object], document["source"])
    return (
        "distribution attestation: PASS (unofficial)\n"
        f"source: {source['distribution_input_count']} indexed inputs; "
        f"sha256={source['distribution_input_sha256']}\n"
        f"wheel: sha256={artifacts['wheel']['sha256']}; "
        "two builds and sdist rebuild match\n"
        f"sdist: sha256={artifacts['sdist']['sha256']}; "
        "two canonical builds match (raw equality unclaimed)\n"
        "smoke: deterministic inspect passed; no password sampled\n"
        "boundaries: no license, signature, dependency-integrity, "
        "cross-platform, or arbitrary-archive claim\n"
    )


def attest(
    repository: Path,
    *,
    work_root: str = DEFAULT_WORK_ROOT,
) -> dict[str, object]:
    """Run the complete attestation and return its deterministic document."""

    toolchain = _check_toolchain()
    source = _collect_source(repository)
    trusted_payloads = ProjectPayloads(
        metadata=build_expected_metadata(source.payload("PACKAGE.md"))
    )
    local_work_root = _validate_work_root(repository.resolve(), work_root)
    try:
        with tempfile.TemporaryDirectory(
            prefix="attestation-",
            dir=local_work_root,
        ) as temporary_name:
            run_root = Path(temporary_name)
            snapshot_a = run_root / "source-a"
            snapshot_b = run_root / "source-b"
            _materialize_snapshot(snapshot_a, source)
            _materialize_snapshot(snapshot_b, source)
            built_a = cast(
                BuiltArtifacts,
                _build(
                    snapshot_a,
                    run_root / "dist-a",
                    run_root / "environment-a",
                ),
            )
            built_b = cast(
                BuiltArtifacts,
                _build(
                    snapshot_b,
                    run_root / "dist-b",
                    run_root / "environment-b",
                ),
            )

            raw_wheel_a = inspect_wheel(
                built_a.wheel,
                WHEEL_MEMBERS,
                trusted_payloads,
                require_canonical=False,
            )
            raw_wheel_b = inspect_wheel(
                built_b.wheel,
                WHEEL_MEMBERS,
                trusted_payloads,
                require_canonical=False,
            )
            raw_sdist_a = inspect_sdist(
                built_a.sdist,
                SDIST_FILES,
                trusted_payloads,
                require_canonical=False,
            )
            raw_sdist_b = inspect_sdist(
                built_b.sdist,
                SDIST_FILES,
                trusted_payloads,
                require_canonical=False,
            )
            for record in (raw_wheel_a, raw_wheel_b):
                _verify_wheel_payloads(record, source, trusted_payloads)
            for record in (raw_sdist_a, raw_sdist_b):
                _verify_sdist_payloads(record, source, trusted_payloads)
            raw_wheels_equal = _files_equal(built_a.wheel, built_b.wheel)
            if not raw_wheels_equal:
                _reject("artifact-mismatch")

            canonical_wheel_a_path = run_root / "canonical-a" / WHEEL_FILENAME
            canonical_wheel_b_path = run_root / "canonical-b" / WHEEL_FILENAME
            canonical_sdist_a_path = run_root / "canonical-a" / SDIST_FILENAME
            canonical_sdist_b_path = run_root / "canonical-b" / SDIST_FILENAME
            canonical_wheel_a = canonicalize_wheel(
                built_a.wheel,
                canonical_wheel_a_path,
                WHEEL_MEMBERS,
                trusted_payloads,
            )
            canonical_wheel_b = canonicalize_wheel(
                built_b.wheel,
                canonical_wheel_b_path,
                WHEEL_MEMBERS,
                trusted_payloads,
            )
            canonical_sdist_a = canonicalize_sdist(
                built_a.sdist,
                canonical_sdist_a_path,
                SDIST_FILES,
                trusted_payloads,
            )
            canonical_sdist_b = canonicalize_sdist(
                built_b.sdist,
                canonical_sdist_b_path,
                SDIST_FILES,
                trusted_payloads,
            )
            canonical_wheels_equal = _files_equal(
                canonical_wheel_a_path,
                canonical_wheel_b_path,
            )
            if not canonical_wheels_equal:
                _reject("artifact-mismatch")
            canonical_sdists_equal = _files_equal(
                canonical_sdist_a_path,
                canonical_sdist_b_path,
            )
            if not canonical_sdists_equal:
                _reject("artifact-mismatch")
            _verify_wheel_payloads(canonical_wheel_a, source, trusted_payloads)
            _verify_wheel_payloads(canonical_wheel_b, source, trusted_payloads)
            _verify_sdist_payloads(canonical_sdist_a, source, trusted_payloads)
            _verify_sdist_payloads(canonical_sdist_b, source, trusted_payloads)

            rebuilt_source = run_root / "sdist-source"
            materialize_canonical_sdist(
                canonical_sdist_a_path,
                rebuilt_source,
                SDIST_FILES,
                trusted_payloads,
            )
            rebuilt_raw_wheel = cast(
                Path,
                _build(
                    rebuilt_source,
                    run_root / "sdist-wheel",
                    run_root / "environment-sdist",
                    wheel_only=True,
                ),
            )
            rebuilt_canonical_path = run_root / "sdist-canonical" / WHEEL_FILENAME
            rebuilt_canonical = canonicalize_wheel(
                rebuilt_raw_wheel,
                rebuilt_canonical_path,
                WHEEL_MEMBERS,
                trusted_payloads,
            )
            _verify_wheel_payloads(rebuilt_canonical, source, trusted_payloads)
            rebuilt_wheel_equal = _files_equal(
                canonical_wheel_a_path,
                rebuilt_canonical_path,
            )
            if not rebuilt_wheel_equal:
                _reject("artifact-mismatch")

            smoke = _smoke_install(canonical_wheel_a_path, run_root)
            smoke_passed = True
            return _build_report(
                source=source,
                toolchain=toolchain,
                raw_wheels=(raw_wheel_a, raw_wheel_b),
                raw_sdists=(raw_sdist_a, raw_sdist_b),
                wheel=canonical_wheel_a,
                sdist=canonical_sdist_a,
                smoke=smoke,
                raw_wheels_equal=raw_wheels_equal,
                canonical_wheels_equal=canonical_wheels_equal,
                canonical_sdists_equal=canonical_sdists_equal,
                rebuilt_wheel_equal=rebuilt_wheel_equal,
                smoke_passed=smoke_passed,
            )
    except DistributionContractError:
        _reject("archive-contract")
    except OSError:
        _reject("internal-io")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="attest-distribution",
        description="Build and verify the project distribution without sampling.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        action=_StoreOnce,
    )
    parser.add_argument(
        "--work-root",
        default=DEFAULT_WORK_ROOT,
        action=_StoreOnce,
    )
    parser.add_argument(
        "--root",
        default=None,
        action=_StoreOnce,
    )
    return parser


def run(
    argv: Sequence[str],
    *,
    stdout: TextIO,
    stderr: TextIO,
    repository: Path | None = None,
) -> int:
    try:
        arguments = _parser().parse_args(argv)
        supplied_root = cast(str | None, arguments.root)
        if repository is not None and supplied_root is not None:
            _reject("arguments-invalid")
        root = (
            repository
            if repository is not None
            else (
                Path(__file__).resolve().parents[1]
                if supplied_root is None
                else _repository_argument(supplied_root)
            )
        )
        document = attest(root, work_root=cast(str, arguments.work_root))
        output_format = cast(str, arguments.format)
        stdout.write(
            _canonical_json(document)
            if output_format == "json"
            else _text_report(document)
        )
        return 0
    except AttestationError as error:
        stderr.write(f"error: distribution attestation rejected: {error.code}\n")
        return 1
    except DistributionContractError:
        stderr.write("error: distribution attestation rejected: archive-contract\n")
        return 1
    except OSError:
        stderr.write("error: distribution attestation rejected: internal-io\n")
        return 1


def main(argv: Sequence[str] | None = None) -> int:
    return run(
        sys.argv[1:] if argv is None else argv,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )


if __name__ == "__main__":
    raise SystemExit(main())
