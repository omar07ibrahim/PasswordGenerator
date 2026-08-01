from __future__ import annotations

import base64
import gzip
import hashlib
import importlib.util
import io
import stat
import struct
import sys
import tarfile
import zipfile
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Any, Protocol, cast

import pytest


class _ContractError(Protocol):
    code: str


def _load_contract() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/distribution_contract.py"
    spec = importlib.util.spec_from_file_location(
        "distribution_contract_for_tests", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load distribution contract")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


contract = cast(Any, _load_contract())

DESCRIPTION = b"# Installable package\n\nA compact package description.\n"
PAYLOADS = contract.ProjectPayloads(contract.build_expected_metadata(DESCRIPTION))
WHEEL_FILES = (
    "password_policy_lab/__init__.py",
    f"{contract.DIST_INFO}/METADATA",
    f"{contract.DIST_INFO}/WHEEL",
    f"{contract.DIST_INFO}/entry_points.txt",
    f"{contract.DIST_INFO}/top_level.txt",
    f"{contract.DIST_INFO}/RECORD",
)
SDIST_FILES = (
    "PACKAGE.md",
    "PKG-INFO",
    "src/password_policy_lab/__init__.py",
)


def _wheel_payloads(
    replacements: Mapping[str, bytes] | None = None,
) -> dict[str, bytes]:
    result = {
        "password_policy_lab/__init__.py": b'__version__ = "0.1.0"\n',
        f"{contract.DIST_INFO}/METADATA": PAYLOADS.metadata,
        f"{contract.DIST_INFO}/WHEEL": PAYLOADS.wheel,
        f"{contract.DIST_INFO}/entry_points.txt": PAYLOADS.entry_points,
        f"{contract.DIST_INFO}/top_level.txt": PAYLOADS.top_level,
    }
    if replacements is not None:
        result.update(replacements)
    return result


def _record(order: Sequence[str], payloads: Mapping[str, bytes]) -> bytes:
    rows: list[str] = []
    for name in order:
        if name == f"{contract.DIST_INFO}/RECORD":
            rows.append(f"{name},,\n")
            continue
        data = payloads[name]
        digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=")
        rows.append(f"{name},sha256={digest.decode('ascii')},{len(data)}\n")
    return "".join(rows).encode("ascii")


def _write_wheel(
    path: Path,
    *,
    order: Sequence[str] = WHEEL_FILES,
    replacements: Mapping[str, bytes] | None = None,
    canonical: bool = True,
    mode: int = stat.S_IFREG | 0o644,
    compression: int = zipfile.ZIP_DEFLATED,
    extra: bytes = b"",
    member_comment: bytes = b"",
    archive_comment: bytes = b"",
    record_override: bytes | None = None,
) -> None:
    payloads = _wheel_payloads(replacements)
    payloads[f"{contract.DIST_INFO}/RECORD"] = (
        _record(order, payloads) if record_override is None else record_override
    )
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        archive.comment = archive_comment
        for name in order:
            info = zipfile.ZipInfo(
                name,
                date_time=(
                    contract.FIXED_ZIP_TIME if canonical else (2025, 2, 2, 2, 2, 2)
                ),
            )
            info.create_system = 3
            info.external_attr = mode << 16
            info.compress_type = compression
            info.extra = extra
            info.comment = member_comment
            archive.writestr(info, payloads[name], compresslevel=9)


def _sdist_plan(files: Sequence[str] = SDIST_FILES) -> tuple[tuple[str, bool], ...]:
    directories = {contract.SDIST_ROOT}
    regular = {f"{contract.SDIST_ROOT}/{name}" for name in files}
    for name in regular:
        parts = name.split("/")
        directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
    return tuple((name, name in directories) for name in sorted(directories | regular))


def _sdist_payloads(
    replacements: Mapping[str, bytes] | None = None,
) -> dict[str, bytes]:
    result = {
        f"{contract.SDIST_ROOT}/PACKAGE.md": DESCRIPTION,
        f"{contract.SDIST_ROOT}/PKG-INFO": PAYLOADS.metadata,
        f"{contract.SDIST_ROOT}/src/password_policy_lab/__init__.py": (
            b'__version__ = "0.1.0"\n'
        ),
    }
    if replacements is not None:
        result.update(replacements)
    return result


TarMutator = Callable[[tarfile.TarInfo, bool], None]


def _write_sdist(
    path: Path,
    *,
    files: Sequence[str] = SDIST_FILES,
    replacements: Mapping[str, bytes] | None = None,
    canonical: bool = True,
    plan: Sequence[tuple[str, bool]] | None = None,
    mutate: TarMutator | None = None,
    tar_format: int = tarfile.USTAR_FORMAT,
    gzip_name: str = "",
    global_pax: Mapping[str, str] | None = None,
) -> None:
    payloads = _sdist_payloads(replacements)
    selected_plan = _sdist_plan(files) if plan is None else tuple(plan)
    with (
        path.open("wb") as output,
        gzip.GzipFile(
            filename=gzip_name,
            fileobj=output,
            mode="wb",
            compresslevel=9,
            mtime=contract.FIXED_MTIME if canonical else 1_700_000_000,
        ) as compressed,
        tarfile.open(
            fileobj=compressed,
            mode="w",
            format=tar_format,
            pax_headers={} if global_pax is None else dict(global_pax),
        ) as archive,
    ):
        for name, is_directory in selected_plan:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE if is_directory else tarfile.REGTYPE
            info.mode = (0o755 if is_directory else 0o644) if canonical else 0o600
            info.uid = 0 if canonical else 1000
            info.gid = 0 if canonical else 1000
            info.uname = "" if canonical else "builder"
            info.gname = "" if canonical else "builder"
            info.mtime = contract.FIXED_MTIME if canonical else 1_700_000_000
            data = b"" if is_directory else payloads[name]
            info.size = len(data)
            if mutate is not None:
                mutate(info, is_directory)
            archive.addfile(info, None if info.isdir() else io.BytesIO(data))


def _assert_rejected(
    operation: Callable[[], object], code: str | None = None
) -> _ContractError:
    with pytest.raises(contract.DistributionContractError) as captured:
        operation()
    error = cast(_ContractError, captured.value)
    if code is not None:
        assert error.code == code
    assert str(error) == f"distribution contract rejected: {error.code}"
    assert "tmp" not in str(error).lower()
    return error


def _inspect_fixture_wheel(path: Path) -> None:
    contract.inspect_wheel(path, WHEEL_FILES, PAYLOADS)


def _inspect_fixture_sdist_noncanonical(path: Path) -> None:
    contract.inspect_sdist(path, SDIST_FILES, PAYLOADS, require_canonical=False)


@contextmanager
def _patched_constant(name: str, value: int) -> Iterator[None]:
    original = getattr(contract, name)
    setattr(contract, name, value)
    try:
        yield
    finally:
        setattr(contract, name, original)


def test_canonical_wheel_inspection_records_streamed_facts(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel)

    result = contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS)

    assert result.kind == "wheel"
    assert result.size == wheel.stat().st_size
    assert result.sha256 == hashlib.sha256(wheel.read_bytes()).hexdigest()
    assert tuple(member.name for member in result.members) == WHEEL_FILES
    assert all(member.mode == stat.S_IFREG | 0o644 for member in result.members)
    assert all(member.mtime == contract.FIXED_MTIME for member in result.members)


@pytest.mark.parametrize(
    "unsafe",
    (
        "../escape.py",
        "/absolute.py",
        "nested\\windows.py",
        "nested//empty.py",
        "nested/./dot.py",
        "nested/../parent.py",
        "nul\x00suffix.py",
        "caf\N{LATIN SMALL LETTER E WITH ACUTE}.py",
        "NUL.txt",
        "trailing./file.py",
    ),
)
def test_path_contract_rejects_nonportable_names(tmp_path: Path, unsafe: str) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel)
    names = (unsafe, *WHEEL_FILES[1:])

    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, names, PAYLOADS), "path-invalid"
    )


def test_path_contract_rejects_duplicates_and_case_aliases(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel)
    duplicate = (*WHEEL_FILES[:-1], WHEEL_FILES[0])
    alias = (
        WHEEL_FILES[0],
        WHEEL_FILES[0].upper(),
        *WHEEL_FILES[1:],
    )

    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, duplicate, PAYLOADS),
        "allowlist-invalid",
    )
    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, alias, PAYLOADS), "allowlist-invalid"
    )


def test_zip_nul_name_is_rejected_even_when_zipfile_truncates_it(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel)
    data = wheel.read_bytes()
    original = WHEEL_FILES[0].encode("ascii")
    corrupted = original.replace(b"_", b"\x00", 1)
    assert len(corrupted) == len(original)
    wheel.write_bytes(data.replace(original, corrupted))

    _assert_rejected(lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS))


@pytest.mark.parametrize(
    ("variant", "code"),
    (
        ("link", "member-invalid"),
        ("extra", "member-invalid"),
        ("member-comment", "member-invalid"),
        ("archive-comment", "canonical-metadata-invalid"),
        ("compression", "member-invalid"),
    ),
)
def test_wheel_rejects_links_extras_comments_and_unsupported_compression(
    tmp_path: Path, variant: str, code: str
) -> None:
    wheel = tmp_path / "package.whl"
    if variant == "link":
        _write_wheel(wheel, mode=stat.S_IFLNK | 0o777)
    elif variant == "extra":
        _write_wheel(wheel, extra=b"\x01\x00\x00\x00")
    elif variant == "member-comment":
        _write_wheel(wheel, member_comment=b"comment")
    elif variant == "archive-comment":
        _write_wheel(wheel, archive_comment=b"comment")
    else:
        _write_wheel(wheel, compression=zipfile.ZIP_BZIP2)

    _assert_rejected(lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS), code)


def test_wheel_rejects_encryption_flag_before_reading(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel)
    data = bytearray(wheel.read_bytes())
    local = data.index(b"PK\x03\x04")
    central = data.index(b"PK\x01\x02")
    struct.pack_into(
        "<H", data, local + 6, struct.unpack_from("<H", data, local + 6)[0] | 1
    )
    struct.pack_into(
        "<H", data, central + 8, struct.unpack_from("<H", data, central + 8)[0] | 1
    )
    wheel.write_bytes(data)

    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS), "member-invalid"
    )


def test_wheel_enforces_small_member_and_ratio_budgets_without_a_bomb(
    tmp_path: Path,
) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel, replacements={"password_policy_lab/__init__.py": b"aaaa"})
    with _patched_constant("MAX_MEMBER_SIZE", 3):
        _assert_rejected(
            lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS),
            "member-limit-exceeded",
        )
    with _patched_constant("MAX_COMPRESSION_RATIO", 1):
        _assert_rejected(
            lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS),
            "compression-invalid",
        )


def test_outer_file_must_be_small_regular_and_not_a_symlink(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel)
    link = tmp_path / "linked.whl"
    link.symlink_to(wheel.name)
    directory = tmp_path / "archive-directory"
    directory.mkdir()

    _assert_rejected(lambda: contract.inspect_wheel(link, WHEEL_FILES, PAYLOADS))
    _assert_rejected(lambda: contract.inspect_wheel(directory, WHEEL_FILES, PAYLOADS))
    with _patched_constant("MAX_OUTER_SIZE", wheel.stat().st_size - 1):
        _assert_rejected(
            lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS),
            "archive-too-large",
        )


def test_wheel_requires_exact_member_order(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    changed_order = (WHEEL_FILES[1], WHEEL_FILES[0], *WHEEL_FILES[2:])
    _write_wheel(wheel, order=changed_order)

    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS),
        "allowlist-invalid",
    )


@pytest.mark.parametrize(
    "record",
    (
        b"",
        b"password_policy_lab/__init__.py,sha256=bad,1\n",
        b"password_policy_lab/__init__.py,,\n",
    ),
)
def test_wheel_rejects_malformed_or_incomplete_record(
    tmp_path: Path, record: bytes
) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel, record_override=record)

    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS), "record-invalid"
    )


def test_wheel_rejects_record_digest_size_and_self_hash_corruption(
    tmp_path: Path,
) -> None:
    good = _wheel_payloads()
    good_record = _record(WHEEL_FILES, good)
    lines = good_record.splitlines(keepends=True)
    first_path, first_digest, first_size = lines[0].removesuffix(b"\n").split(b",")
    wrong_size = (
        b",".join((first_path, first_digest, str(int(first_size) + 1).encode("ascii")))
        + b"\n"
        + b"".join(lines[1:])
    )
    replacement = b"A" if first_digest[-1:] != b"A" else b"B"
    wrong_digest = (
        b",".join((first_path, first_digest[:-1] + replacement, first_size))
        + b"\n"
        + b"".join(lines[1:])
    )
    mutations = (
        wrong_size,
        wrong_digest,
        good_record.replace(b"RECORD,,", b"RECORD,sha256=bad,1"),
    )
    for index, mutation in enumerate(mutations):
        wheel = tmp_path / f"package-{index}.whl"
        _write_wheel(wheel, record_override=mutation)

        _assert_rejected(
            partial(_inspect_fixture_wheel, wheel),
            "record-invalid",
        )


def test_wheel_rejects_noncanonical_base64url_record_digest(tmp_path: Path) -> None:
    wheel = tmp_path / "package.whl"
    good_record = _record(WHEEL_FILES, _wheel_payloads())
    lines = good_record.splitlines(keepends=True)
    first_path, first_digest, first_size = lines[0].removesuffix(b"\n").split(b",")
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    encoded = bytearray(first_digest.removeprefix(b"sha256="))
    last_index = alphabet.index(encoded[-1])
    encoded[-1] = alphabet[(last_index & 0b110000) | ((last_index + 1) & 0b001111)]
    assert (
        base64.urlsafe_b64decode(encoded + b"=")
        == hashlib.sha256(_wheel_payloads()[WHEEL_FILES[0]]).digest()
    )
    mutation = (
        b",".join((first_path, b"sha256=" + encoded, first_size))
        + b"\n"
        + b"".join(lines[1:])
    )
    _write_wheel(wheel, record_override=mutation)

    _assert_rejected(partial(_inspect_fixture_wheel, wheel), "record-invalid")


@pytest.mark.parametrize(
    "name",
    (
        f"{contract.DIST_INFO}/METADATA",
        f"{contract.DIST_INFO}/WHEEL",
        f"{contract.DIST_INFO}/entry_points.txt",
        f"{contract.DIST_INFO}/top_level.txt",
    ),
)
def test_wheel_rejects_project_metadata_corruption(tmp_path: Path, name: str) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel, replacements={name: b"corrupted\n"})

    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS),
        "metadata-invalid",
    )


def test_wheel_canonicalization_is_deterministic(tmp_path: Path) -> None:
    first_raw = tmp_path / "first-raw.whl"
    second_raw = tmp_path / "second-raw.whl"
    _write_wheel(first_raw, canonical=False)
    _write_wheel(second_raw, canonical=False, mode=stat.S_IFREG | 0o600)
    first = tmp_path / "first.whl"
    second = tmp_path / "second.whl"

    first_record = contract.canonicalize_wheel(first_raw, first, WHEEL_FILES, PAYLOADS)
    second_record = contract.canonicalize_wheel(
        second_raw, second, WHEEL_FILES, PAYLOADS
    )

    assert first.read_bytes() == second.read_bytes()
    assert first_record.sha256 == second_record.sha256
    assert contract.inspect_wheel(first, WHEEL_FILES, PAYLOADS) == first_record


@pytest.mark.parametrize("mutation", ("prefix", "suffix", "local-time"))
def test_canonical_wheel_rejects_bytes_outside_its_exact_container_profile(
    tmp_path: Path, mutation: str
) -> None:
    wheel = tmp_path / "package.whl"
    _write_wheel(wheel)
    data = bytearray(wheel.read_bytes())
    if mutation == "prefix":
        data[:0] = b"self-extracting-prefix"
    elif mutation == "suffix":
        data.extend(b"trailing-junk")
    else:
        local = data.index(b"PK\x03\x04")
        struct.pack_into("<H", data, local + 10, 0x1234)
        struct.pack_into("<H", data, local + 12, 0x5678)
    wheel.write_bytes(data)

    contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS, require_canonical=False)
    _assert_rejected(
        lambda: contract.inspect_wheel(wheel, WHEEL_FILES, PAYLOADS),
        "canonical-metadata-invalid",
    )


def test_canonical_sdist_inspection_records_modes_owners_time_and_order(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw.tar.gz"
    canonical = tmp_path / "canonical.tar.gz"
    _write_sdist(raw, canonical=False, gzip_name="raw-name")
    result = contract.canonicalize_sdist(raw, canonical, SDIST_FILES, PAYLOADS)

    assert result.kind == "sdist"
    assert tuple(member.name for member in result.members) == tuple(
        name for name, _ in _sdist_plan()
    )
    with tarfile.open(canonical, "r:gz") as archive:
        members = archive.getmembers()
    assert all(member.uid == member.gid == 0 for member in members)
    assert all(member.uname == member.gname == "" for member in members)
    assert all(member.mtime == contract.FIXED_MTIME for member in members)
    assert all(
        member.mode == (0o755 if member.isdir() else 0o644) for member in members
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("mode", 0o600),
        ("uid", 1),
        ("gid", 1),
        ("uname", "builder"),
        ("gname", "builder"),
        ("mtime", contract.FIXED_MTIME + 1),
    ),
)
def test_sdist_rejects_noncanonical_member_metadata(
    tmp_path: Path, field: str, value: object
) -> None:
    archive = tmp_path / "package.tar.gz"

    def mutate(info: tarfile.TarInfo, is_directory: bool) -> None:
        if not is_directory and info.name.endswith("PACKAGE.md"):
            setattr(info, field, value)

    _write_sdist(archive, mutate=mutate)

    _assert_rejected(
        lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
        "canonical-metadata-invalid",
    )


def test_sdist_requires_sorted_exact_rooted_plan(tmp_path: Path) -> None:
    archive = tmp_path / "package.tar.gz"
    reversed_plan = tuple(reversed(_sdist_plan()))
    _write_sdist(archive, plan=reversed_plan)

    _assert_rejected(
        lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
        "allowlist-invalid",
    )


@pytest.mark.parametrize("member_type", (tarfile.SYMTYPE, tarfile.CHRTYPE))
def test_sdist_rejects_links_and_devices(tmp_path: Path, member_type: bytes) -> None:
    archive = tmp_path / "package.tar.gz"

    def mutate(info: tarfile.TarInfo, is_directory: bool) -> None:
        if not is_directory and info.name.endswith("__init__.py"):
            info.type = member_type
            if member_type == tarfile.SYMTYPE:
                info.linkname = "../../escape"
                info.size = 0
            else:
                info.devmajor = 1
                info.devminor = 3
                info.size = 0

    _write_sdist(archive, mutate=mutate)

    _assert_rejected(
        lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
        "member-invalid",
    )


def test_sdist_rejects_pax_path_overrides(tmp_path: Path) -> None:
    archive = tmp_path / "package.tar.gz"

    def mutate(info: tarfile.TarInfo, is_directory: bool) -> None:
        if not is_directory and info.name.endswith("PACKAGE.md"):
            info.pax_headers = {"path": info.name}

    _write_sdist(archive, mutate=mutate, tar_format=tarfile.PAX_FORMAT)

    _assert_rejected(
        lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
        "member-invalid",
    )


def test_raw_sdist_accepts_backend_pax_mtime_then_canonicalizes(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw.tar.gz"
    canonical = tmp_path / "canonical.tar.gz"

    def add_backend_mtime(info: tarfile.TarInfo, is_directory: bool) -> None:
        value = "1700000000.0" if is_directory else "1700000000.125"
        info.pax_headers = {"mtime": value}

    _write_sdist(
        raw,
        canonical=False,
        mutate=add_backend_mtime,
        tar_format=tarfile.PAX_FORMAT,
    )

    raw_result = contract.inspect_sdist(
        raw, SDIST_FILES, PAYLOADS, require_canonical=False
    )
    canonical_result = contract.canonicalize_sdist(
        raw, canonical, SDIST_FILES, PAYLOADS
    )

    assert raw_result.kind == canonical_result.kind == "sdist"
    assert raw_result.sha256 != canonical_result.sha256
    with tarfile.open(canonical, "r:gz") as accepted:
        assert all(not member.pax_headers for member in accepted)
    assert contract.inspect_sdist(canonical, SDIST_FILES, PAYLOADS) == canonical_result


def test_canonical_sdist_still_rejects_an_otherwise_valid_pax_mtime(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "package.tar.gz"

    def add_mtime(info: tarfile.TarInfo, is_directory: bool) -> None:
        del is_directory
        info.pax_headers = {"mtime": f"{contract.FIXED_MTIME}.0"}

    _write_sdist(archive, mutate=add_mtime, tar_format=tarfile.PAX_FORMAT)

    contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS, require_canonical=False)
    _assert_rejected(
        lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
        "canonical-metadata-invalid",
    )


@pytest.mark.parametrize(
    "value",
    (
        "01700000000.0",
        "+1700000000.0",
        "1700000000.00",
        "1700000000.",
        "1700000000e0",
        "NaN",
        "Infinity",
        "-1",
        "4102444801",
        "1700000000.123456789",
    ),
)
def test_raw_sdist_rejects_noncanonical_or_unbounded_pax_mtime(
    tmp_path: Path, value: str
) -> None:
    archive = tmp_path / "package.tar.gz"

    def add_mtime(info: tarfile.TarInfo, is_directory: bool) -> None:
        if not is_directory and info.name.endswith("PACKAGE.md"):
            info.pax_headers = {"mtime": value}

    _write_sdist(archive, mutate=add_mtime, tar_format=tarfile.PAX_FORMAT)

    _assert_rejected(
        lambda: contract.inspect_sdist(
            archive, SDIST_FILES, PAYLOADS, require_canonical=False
        )
    )


def test_raw_sdist_rejects_extra_and_global_pax_keys(tmp_path: Path) -> None:
    member_archive = tmp_path / "member.tar.gz"
    global_archive = tmp_path / "global.tar.gz"

    def add_extra_key(info: tarfile.TarInfo, is_directory: bool) -> None:
        if not is_directory and info.name.endswith("PACKAGE.md"):
            info.pax_headers = {
                "mtime": "1700000000.0",
                "atime": "1700000000.0",
            }

    _write_sdist(member_archive, mutate=add_extra_key, tar_format=tarfile.PAX_FORMAT)
    _write_sdist(
        global_archive,
        tar_format=tarfile.PAX_FORMAT,
        global_pax={"comment": "unexpected"},
    )

    for archive in (member_archive, global_archive):
        _assert_rejected(partial(_inspect_fixture_sdist_noncanonical, archive))


def test_sdist_rejects_gnu_sparse_metadata(tmp_path: Path) -> None:
    archive = tmp_path / "package.tar.gz"

    def mutate(info: tarfile.TarInfo, is_directory: bool) -> None:
        if not is_directory and info.name.endswith("PACKAGE.md"):
            info.pax_headers = {
                "GNU.sparse.map": f"0,{info.size}",
                "GNU.sparse.size": str(info.size),
            }

    _write_sdist(archive, mutate=mutate, tar_format=tarfile.PAX_FORMAT)

    _assert_rejected(
        lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
        "member-invalid",
    )


def test_sdist_enforces_member_and_payload_limits_with_tiny_files(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "package.tar.gz"
    _write_sdist(archive)
    with _patched_constant("MAX_MEMBER_SIZE", len(PAYLOADS.metadata) - 1):
        _assert_rejected(
            lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
            "member-limit-exceeded",
        )
    with _patched_constant("MAX_SDIST_PAYLOAD", len(PAYLOADS.metadata)):
        _assert_rejected(
            lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
            "member-limit-exceeded",
        )


def test_sdist_rejects_an_oversized_header_before_advancing_past_its_body(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "oversized-header.tar.gz"
    root = tarfile.TarInfo(contract.SDIST_ROOT)
    root.type = tarfile.DIRTYPE
    root.mode = 0o755
    root.size = 0
    oversized = tarfile.TarInfo(f"{contract.SDIST_ROOT}/PACKAGE.md")
    oversized.type = tarfile.REGTYPE
    oversized.mode = 0o644
    oversized.size = contract.MAX_MEMBER_SIZE + 1
    headers_only = root.tobuf(format=tarfile.USTAR_FORMAT) + oversized.tobuf(
        format=tarfile.USTAR_FORMAT
    )
    archive.write_bytes(gzip.compress(headers_only, mtime=contract.FIXED_MTIME))

    _assert_rejected(
        lambda: contract.inspect_sdist(
            archive, SDIST_FILES, PAYLOADS, require_canonical=False
        ),
        "member-limit-exceeded",
    )


def test_sdist_rejects_pkg_info_corruption(tmp_path: Path) -> None:
    archive = tmp_path / "package.tar.gz"
    _write_sdist(
        archive,
        replacements={f"{contract.SDIST_ROOT}/PKG-INFO": b"corrupted\n"},
    )

    _assert_rejected(
        lambda: contract.inspect_sdist(archive, SDIST_FILES, PAYLOADS),
        "metadata-invalid",
    )


def test_sdist_canonicalization_is_deterministic_and_has_no_gzip_name(
    tmp_path: Path,
) -> None:
    first_raw = tmp_path / "first-raw.tar.gz"
    second_raw = tmp_path / "second-raw.tar.gz"
    _write_sdist(first_raw, canonical=False, gzip_name="first-source")
    _write_sdist(second_raw, canonical=False, gzip_name="second-source")
    first = tmp_path / "first.tar.gz"
    second = tmp_path / "second.tar.gz"

    first_record = contract.canonicalize_sdist(first_raw, first, SDIST_FILES, PAYLOADS)
    second_record = contract.canonicalize_sdist(
        second_raw, second, SDIST_FILES, PAYLOADS
    )

    assert first.read_bytes() == second.read_bytes()
    assert first_record.sha256 == second_record.sha256
    header = first.read_bytes()[:10]
    assert header[3] == 0
    assert int.from_bytes(header[4:8], "little") == contract.FIXED_MTIME


@pytest.mark.parametrize("mutation", ("crc", "size", "suffix"))
def test_sdist_rejects_invalid_or_trailing_gzip_container_bytes(
    tmp_path: Path, mutation: str
) -> None:
    archive = tmp_path / "package.tar.gz"
    _write_sdist(archive)
    data = bytearray(archive.read_bytes())
    if mutation == "crc":
        data[-8] ^= 1
    elif mutation == "size":
        data[-1] ^= 1
    else:
        data.extend(b"trailing-junk")
    archive.write_bytes(data)

    _assert_rejected(
        lambda: contract.inspect_sdist(
            archive, SDIST_FILES, PAYLOADS, require_canonical=False
        ),
        "archive-invalid",
    )


def test_materialize_canonical_sdist_writes_only_prevalidated_regular_files(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw.tar.gz"
    archive = tmp_path / "package.tar.gz"
    destination = tmp_path / "materialized"
    _write_sdist(raw, canonical=False)
    expected = contract.canonicalize_sdist(raw, archive, SDIST_FILES, PAYLOADS)

    result = contract.materialize_canonical_sdist(
        archive, destination, SDIST_FILES, PAYLOADS
    )

    assert result == expected
    assert (destination / "PACKAGE.md").read_bytes() == DESCRIPTION
    assert (destination / "PKG-INFO").read_bytes() == PAYLOADS.metadata
    assert (
        destination / "src/password_policy_lab/__init__.py"
    ).read_bytes() == b'__version__ = "0.1.0"\n'
    assert all(
        stat.S_IMODE(path.stat().st_mode) == (0o755 if path.is_dir() else 0o644)
        for path in destination.rglob("*")
    )
    _assert_rejected(
        lambda: contract.materialize_canonical_sdist(
            archive, destination, SDIST_FILES, PAYLOADS
        ),
        "output-invalid",
    )


def test_materialize_canonical_sdist_never_replaces_an_empty_destination(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "raw.tar.gz"
    archive = tmp_path / "package.tar.gz"
    destination = tmp_path / "reserved"
    _write_sdist(raw, canonical=False)
    contract.canonicalize_sdist(raw, archive, SDIST_FILES, PAYLOADS)
    destination.mkdir()

    _assert_rejected(
        lambda: contract.materialize_canonical_sdist(
            archive, destination, SDIST_FILES, PAYLOADS
        ),
        "output-invalid",
    )
    assert destination.is_dir()
    assert not tuple(destination.iterdir())


def test_expected_metadata_builder_is_bounded_and_rejects_nul() -> None:
    assert contract.build_expected_metadata(DESCRIPTION) == PAYLOADS.metadata
    _assert_rejected(
        lambda: contract.build_expected_metadata(b"bad\x00description"),
        "metadata-invalid",
    )
    with _patched_constant("MAX_MEMBER_SIZE", len(contract.EXPECTED_METADATA_PREFIX)):
        _assert_rejected(
            lambda: contract.build_expected_metadata(b"x"), "metadata-invalid"
        )
