from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Protocol, cast

import pytest


class _IndexEntry(Protocol):
    path: str
    object_id: str


class _SourceState(Protocol):
    tree: str


class _Attester(Protocol):
    AttestationError: type[ValueError]
    DISTRIBUTION_INPUTS: tuple[str, ...]
    PACKAGE_INPUTS: tuple[str, ...]
    SDIST_FILES: tuple[str, ...]
    WHEEL_MEMBERS: tuple[str, ...]

    def _parse_index_entries(self, raw: bytes) -> tuple[_IndexEntry, ...]: ...

    def _parse_tree_entries(self, raw: bytes) -> tuple[_IndexEntry, ...]: ...

    def _canonical_input_digest(
        self,
        files: Sequence[tuple[str, bytes]],
    ) -> str: ...

    def _process_environment(
        self,
        temporary_root: Path,
        *,
        python_path: Path | None = None,
    ) -> dict[str, str]: ...

    def _prepare_environment_directories(
        self,
        environment: Mapping[str, str],
    ) -> None: ...

    def _validate_work_root(self, repository: Path, raw_path: str) -> Path: ...

    def _repository_argument(self, raw_path: str) -> Path: ...

    def _validate_working_package_inventory(self, repository: Path) -> None: ...

    def _collect_source(self, repository: Path) -> _SourceState: ...

    def _artifact_document(self, record: object) -> dict[str, object]: ...

    def _validate_claim_guards(
        self,
        *,
        raw_wheels_equal: bool,
        canonical_wheels_equal: bool,
        canonical_sdists_equal: bool,
        rebuilt_wheel_equal: bool,
        smoke_passed: bool,
    ) -> None: ...

    def _canonical_json(self, document: Mapping[str, object]) -> str: ...

    def run(
        self,
        argv: Sequence[str],
        *,
        stdout: io.StringIO,
        stderr: io.StringIO,
        repository: Path | None = None,
    ) -> int: ...


def _load_attester() -> _Attester:
    script_directory = Path(__file__).resolve().parents[1] / "scripts"
    script_path = script_directory / "attest_distribution.py"
    spec = importlib.util.spec_from_file_location(
        "portfolio_distribution_attester",
        script_path,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the distribution attester")
    inserted = str(script_directory)
    sys.path.insert(0, inserted)
    try:
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(inserted)
    return cast(_Attester, module)


attest_distribution = _load_attester()


def _index_record(path: str, *, mode: str = "100644", stage: str = "0") -> bytes:
    return f"{mode} {'a' * 40} {stage}\t{path}".encode("ascii") + b"\0"


def _tree_record(path: str, *, object_id: str | None = None) -> bytes:
    digest = "a" * 40 if object_id is None else object_id
    return f"100644 blob {digest}\t{path}".encode("ascii") + b"\0"


def _prepare_source_fixture(repository: Path) -> dict[str, bytes]:
    source_root = Path(__file__).resolve().parents[1]
    (repository / ".git").mkdir()
    payloads: dict[str, bytes] = {}
    for relative in attest_distribution.DISTRIBUTION_INPUTS:
        data = source_root.joinpath(*relative.split("/")).read_bytes()
        destination = repository.joinpath(*relative.split("/"))
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)
        payloads[relative] = data
    return payloads


def _git_blob_id(data: bytes) -> str:
    header = f"blob {len(data)}\0".encode("ascii")
    return hashlib.sha1(header + data, usedforsecurity=False).hexdigest()


def test_static_release_contract_has_exact_bounded_inventories() -> None:
    assert len(attest_distribution.DISTRIBUTION_INPUTS) == 15
    assert len(attest_distribution.PACKAGE_INPUTS) == 12
    assert len(attest_distribution.WHEEL_MEMBERS) == 17
    assert len(attest_distribution.SDIST_FILES) == 23
    assert set(attest_distribution.PACKAGE_INPUTS).issubset(
        attest_distribution.DISTRIBUTION_INPUTS
    )
    assert len(set(attest_distribution.WHEEL_MEMBERS)) == 17
    assert len(set(attest_distribution.SDIST_FILES)) == 23


def test_index_parser_accepts_only_regular_stage_zero_ascii_entries() -> None:
    raw = _index_record("MANIFEST.in") + _index_record("PACKAGE.md")

    entries = attest_distribution._parse_index_entries(raw)

    assert [(entry.path, entry.object_id) for entry in entries] == [
        ("MANIFEST.in", "a" * 40),
        ("PACKAGE.md", "a" * 40),
    ]


@pytest.mark.parametrize(
    "raw",
    [
        _index_record("MANIFEST.in", mode="100755"),
        _index_record("MANIFEST.in", stage="2"),
        _index_record("../MANIFEST.in"),
        _index_record("MANIFEST.in") + _index_record("MANIFEST.in"),
        b"100644 not-an-object 0\tMANIFEST.in\0",
        b"100644 " + (b"a" * 40) + b" 0\tPACKAGE-\xff.md\0",
        _index_record("MANIFEST.in")[:-1],
    ],
)
def test_index_parser_rejects_ambiguous_or_nonregular_entries(raw: bytes) -> None:
    with pytest.raises(attest_distribution.AttestationError, match="index-invalid"):
        attest_distribution._parse_index_entries(raw)


def test_source_collection_rejects_index_movement_after_immutable_snapshot(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = _prepare_source_fixture(tmp_path)
    object_ids = {path: _git_blob_id(data) for path, data in payloads.items()}
    by_object_id = {object_ids[path]: data for path, data in payloads.items()}
    tree_document = b"".join(
        _tree_record(path, object_id=object_ids[path])
        for path in attest_distribution.DISTRIBUTION_INPUTS
    )
    source_tree = "1" * 40
    moved_tree = "2" * 40
    write_tree_calls = 0
    cat_file_targets: list[str] = []

    def fake_git(
        repository: Path,
        arguments: Sequence[str],
        *,
        maximum_output: int = 2 * 1024 * 1024,
    ) -> bytes:
        nonlocal write_tree_calls
        del maximum_output
        assert repository == tmp_path
        command = tuple(arguments)
        if command == ("rev-parse", "--show-toplevel"):
            return f"{tmp_path}\n".encode()
        if command == ("write-tree",):
            write_tree_calls += 1
            tree = source_tree if write_tree_calls == 1 else moved_tree
            return f"{tree}\n".encode("ascii")
        if command[:4] == ("ls-tree", "-r", "-z", source_tree):
            return tree_document
        if command[:2] == ("cat-file", "blob"):
            cat_file_targets.append(command[2])
            return by_object_id[command[2]]
        if command[:3] == ("ls-files", "--others", "--exclude-standard"):
            return b""
        raise AssertionError(f"unexpected Git command: {command!r}")

    monkeypatch.setattr("portfolio_distribution_attester._git", fake_git)

    with pytest.raises(
        attest_distribution.AttestationError,
        match="source-dirty",
    ):
        attest_distribution._collect_source(tmp_path)

    assert write_tree_calls == 2
    assert set(cat_file_targets) == set(by_object_id)
    assert all(not target.startswith(":") for target in cat_file_targets)


def test_source_collection_reads_only_the_immutable_index_tree(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payloads = _prepare_source_fixture(tmp_path)
    object_ids = {path: _git_blob_id(data) for path, data in payloads.items()}
    by_object_id = {object_ids[path]: data for path, data in payloads.items()}
    tree_document = b"".join(
        _tree_record(path, object_id=object_ids[path])
        for path in attest_distribution.DISTRIBUTION_INPUTS
    )
    source_tree = "4" * 40
    tree_targets: list[str] = []

    def fake_git(
        repository: Path,
        arguments: Sequence[str],
        *,
        maximum_output: int = 2 * 1024 * 1024,
    ) -> bytes:
        del maximum_output
        assert repository == tmp_path
        command = tuple(arguments)
        if command == ("rev-parse", "--show-toplevel"):
            return f"{tmp_path}\n".encode()
        if command == ("write-tree",):
            return f"{source_tree}\n".encode("ascii")
        if command[:3] == ("ls-tree", "-r", "-z"):
            tree_targets.append(command[3])
            if command[3] != source_tree:
                raise AssertionError("tree lookup used a mutable ref")
            return tree_document
        if command[:2] == ("cat-file", "blob"):
            return by_object_id[command[2]]
        if command[:3] == ("ls-files", "--others", "--exclude-standard"):
            return b""
        raise AssertionError(f"unexpected Git command: {command!r}")

    monkeypatch.setattr("portfolio_distribution_attester._git", fake_git)

    source = attest_distribution._collect_source(tmp_path)

    assert source.tree == source_tree
    assert tree_targets == [source_tree]


def test_input_digest_is_order_independent_but_boundary_sensitive() -> None:
    files = [
        (path, f"payload:{path}".encode())
        for path in attest_distribution.DISTRIBUTION_INPUTS
    ]

    forward = attest_distribution._canonical_input_digest(files)
    reversed_order = attest_distribution._canonical_input_digest(list(reversed(files)))
    changed = list(files)
    path, payload = changed[4]
    changed[4] = (path, payload + b"\x00")

    assert forward == reversed_order
    assert forward != attest_distribution._canonical_input_digest(changed)
    assert len(forward) == 64


def test_input_digest_rejects_missing_duplicate_and_unknown_inputs() -> None:
    files = [(path, b"x") for path in attest_distribution.DISTRIBUTION_INPUTS]
    invalid = (
        files[:-1],
        [*files[:-1], files[0]],
        [*files[:-1], ("src/password_policy_lab/extra.py", b"x")],
    )

    for candidate in invalid:
        with pytest.raises(
            attest_distribution.AttestationError,
            match="index-invalid",
        ):
            attest_distribution._canonical_input_digest(candidate)


def test_subprocess_environment_is_allowlisted_and_prepares_private_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "must-not-survive")
    monkeypatch.setenv("PYTHONPATH", "/host/source")
    monkeypatch.setenv("HOME", "/host/home")
    environment_root = tmp_path / "environment"
    target = tmp_path / "target"

    environment = attest_distribution._process_environment(
        environment_root,
        python_path=target,
    )
    attest_distribution._prepare_environment_directories(environment)

    assert "GITHUB_TOKEN" not in environment
    assert environment["PYTHONPATH"] == str(target)
    assert environment["PIP_NO_INDEX"] == "1"
    assert environment["PYTHONHASHSEED"] == "0"
    assert environment["SOURCE_DATE_EPOCH"].isascii()
    assert environment["TZ"] == "UTC"
    assert set(environment) == {
        "HOME",
        "LANG",
        "LC_ALL",
        "PATH",
        "PIP_CONFIG_FILE",
        "PIP_DISABLE_PIP_VERSION_CHECK",
        "PIP_NO_INDEX",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONHASHSEED",
        "PYTHONNOUSERSITE",
        "PYTHONPATH",
        "SOURCE_DATE_EPOCH",
        "TMPDIR",
        "TZ",
    }
    assert Path(environment["HOME"]).stat().st_mode & 0o777 == 0o700
    assert Path(environment["TMPDIR"]).stat().st_mode & 0o777 == 0o700


def test_work_root_accepts_repo_local_relative_and_absolute_paths(
    tmp_path: Path,
) -> None:
    relative = attest_distribution._validate_work_root(tmp_path, "relative/work")
    absolute_path = tmp_path / "absolute" / "work"
    absolute = attest_distribution._validate_work_root(
        tmp_path,
        absolute_path.as_posix(),
    )

    assert relative == tmp_path / "relative" / "work"
    assert absolute == absolute_path
    assert relative.is_dir()
    assert absolute.is_dir()


def test_work_root_rejects_escape_and_existing_symlink(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(target, target_is_directory=True)

    with pytest.raises(
        attest_distribution.AttestationError,
        match="work-root-invalid",
    ):
        attest_distribution._validate_work_root(
            tmp_path,
            (tmp_path.parent / "outside").as_posix(),
        )
    with pytest.raises(
        attest_distribution.AttestationError,
        match="work-root-invalid",
    ):
        attest_distribution._validate_work_root(
            tmp_path,
            (linked / "child").as_posix(),
        )


def test_repository_argument_requires_canonical_absolute_nonsymlink_path(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    linked = tmp_path / "repository-link"
    linked.symlink_to(repository, target_is_directory=True)

    assert attest_distribution._repository_argument(repository.as_posix()) == repository
    with pytest.raises(
        attest_distribution.AttestationError,
        match="arguments-invalid",
    ):
        attest_distribution._repository_argument("relative/repository")
    with pytest.raises(
        attest_distribution.AttestationError,
        match="arguments-invalid",
    ):
        attest_distribution._repository_argument(linked.as_posix())


def test_working_package_inventory_allows_only_exact_sources_and_bytecode_cache(
    tmp_path: Path,
) -> None:
    for relative in attest_distribution.PACKAGE_INPUTS:
        path = tmp_path.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"fixture")
    cache = tmp_path / "src/password_policy_lab/__pycache__"
    cache.mkdir()
    (cache / "cli.cpython-312.pyc").write_bytes(b"cache")

    attest_distribution._validate_working_package_inventory(tmp_path)

    unexpected = tmp_path / "src/password_policy_lab/ignored_extra.py"
    unexpected.write_bytes(b"unexpected")
    with pytest.raises(
        attest_distribution.AttestationError,
        match="index-invalid",
    ):
        attest_distribution._validate_working_package_inventory(tmp_path)


def test_artifact_inventory_document_is_path_free_and_exact() -> None:
    member = SimpleNamespace(
        name="password_policy_lab/__init__.py",
        size=7,
        sha256="a" * 64,
        compressed_size=9,
        mode=0o100644,
        mtime=1_704_067_200,
    )
    record = SimpleNamespace(
        kind="wheel",
        size=123,
        sha256="b" * 64,
        members=(member,),
    )

    document = attest_distribution._artifact_document(record)
    encoded = attest_distribution._canonical_json(document)

    assert document == {
        "inventory": [
            {
                "compressed_size": 9,
                "mode": "0644",
                "mtime": 1_704_067_200,
                "name": "password_policy_lab/__init__.py",
                "sha256": "a" * 64,
                "size": 7,
            }
        ],
        "member_count": 1,
        "sha256": "b" * 64,
        "size": 123,
    }
    assert encoded.endswith("\n")
    assert "/home/" not in encoded
    assert list(json.loads(encoded)) == [
        "inventory",
        "member_count",
        "sha256",
        "size",
    ]


@pytest.mark.parametrize(
    (
        "raw_wheels_equal",
        "canonical_wheels_equal",
        "canonical_sdists_equal",
        "rebuilt_wheel_equal",
        "smoke_passed",
        "failure_code",
    ),
    [
        (False, True, True, True, True, "artifact-mismatch"),
        (True, False, True, True, True, "artifact-mismatch"),
        (True, True, False, True, True, "artifact-mismatch"),
        (True, True, True, False, True, "artifact-mismatch"),
        (True, True, True, True, False, "smoke-failed"),
    ],
)
def test_claim_guards_reject_unproven_positive_report_flags(
    raw_wheels_equal: bool,
    canonical_wheels_equal: bool,
    canonical_sdists_equal: bool,
    rebuilt_wheel_equal: bool,
    smoke_passed: bool,
    failure_code: str,
) -> None:
    with pytest.raises(
        attest_distribution.AttestationError,
        match=failure_code,
    ):
        attest_distribution._validate_claim_guards(
            raw_wheels_equal=raw_wheels_equal,
            canonical_wheels_equal=canonical_wheels_equal,
            canonical_sdists_equal=canonical_sdists_equal,
            rebuilt_wheel_equal=rebuilt_wheel_equal,
            smoke_passed=smoke_passed,
        )


def test_json_cli_emits_canonical_unofficial_claim_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    report: dict[str, object] = {
        "claim_boundaries": {
            "arbitrary_archive_safety": False,
            "artifact_signature_verified": False,
            "cross_platform_reproducibility": False,
            "dependency_integrity_verified": False,
            "fresh_dependency_environment": False,
            "license_declared": False,
        },
        "official": False,
        "schema_version": 1,
    }

    def fake_attest(repository: Path, *, work_root: str) -> dict[str, object]:
        assert repository == tmp_path
        assert work_root == ".evidence-work/distribution"
        return report

    monkeypatch.setattr(
        "portfolio_distribution_attester.attest",
        fake_attest,
    )
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = attest_distribution.run(
        ["--format", "json"],
        stdout=stdout,
        stderr=stderr,
        repository=tmp_path,
    )

    assert status == 0
    assert stderr.getvalue() == ""
    assert stdout.getvalue() == attest_distribution._canonical_json(report)
    payload = json.loads(stdout.getvalue())
    assert payload["official"] is False
    assert not any(payload["claim_boundaries"].values())


@pytest.mark.parametrize(
    ("arguments", "expected_code"),
    [
        (["--format", "yaml"], "arguments-invalid"),
        (["--format", "json", "--format", "text"], "arguments-invalid"),
        (["--root", "/tmp/elsewhere"], "arguments-invalid"),
        (["--root", "/tmp/a", "--root", "/tmp/b"], "arguments-invalid"),
    ],
)
def test_cli_returns_stable_argument_failure_codes(
    tmp_path: Path,
    arguments: list[str],
    expected_code: str,
) -> None:
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = attest_distribution.run(
        arguments,
        stdout=stdout,
        stderr=stderr,
        repository=tmp_path,
    )

    assert status == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        f"error: distribution attestation rejected: {expected_code}\n"
    )


def test_cli_maps_attestation_failure_without_leaking_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def failed_attest(repository: Path, *, work_root: str) -> dict[str, object]:
        del repository, work_root
        raise attest_distribution.AttestationError("build-failed")

    monkeypatch.setattr(
        "portfolio_distribution_attester.attest",
        failed_attest,
    )
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = attest_distribution.run(
        [],
        stdout=stdout,
        stderr=stderr,
        repository=tmp_path,
    )

    assert status == 1
    assert stdout.getvalue() == ""
    assert stderr.getvalue() == (
        "error: distribution attestation rejected: build-failed\n"
    )
    assert str(tmp_path) not in stderr.getvalue()
