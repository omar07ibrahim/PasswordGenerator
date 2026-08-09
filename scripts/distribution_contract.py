"""Bounded, project-specific contracts for release archives.

This module deliberately implements the archive profile used by this project; it
is not a generic hostile-archive sandbox.  Callers supply the exact member
allowlists and the expected project metadata derived from trusted source files.
"""

from __future__ import annotations

import base64
import csv
import decimal
import gzip
import hashlib
import hmac
import io
import os
import re
import shutil
import stat
import tarfile
import tempfile
import zipfile
import zlib
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import IO, BinaryIO, Literal, NoReturn

PROJECT_NAME = "password-policy-state-space"
PROJECT_VERSION = "0.1.0"
NORMALIZED_NAME = "password_policy_state_space"
DIST_INFO = f"{NORMALIZED_NAME}-{PROJECT_VERSION}.dist-info"
SDIST_ROOT = f"{NORMALIZED_NAME}-{PROJECT_VERSION}"

# 2024-01-01 00:00:00 UTC.  ZIP timestamps have two-second resolution.
FIXED_MTIME = 1_704_067_200
FIXED_ZIP_TIME = (2024, 1, 1, 0, 0, 0)

MAX_OUTER_SIZE = 5 * 1024 * 1024
MAX_MEMBER_SIZE = 2 * 1024 * 1024
MAX_WHEEL_MEMBERS = 128
MAX_WHEEL_PAYLOAD = 10 * 1024 * 1024
MAX_SDIST_MEMBERS = 256
MAX_SDIST_PAYLOAD = 20 * 1024 * 1024
MAX_SDIST_STREAM = 24 * 1024 * 1024
MAX_COMPRESSION_RATIO = 100
MAX_RAW_MTIME = 4_102_444_800
_CHUNK_SIZE = 64 * 1024

EXPECTED_WHEEL = (
    b"Wheel-Version: 1.0\n"
    b"Generator: setuptools (83.0.0)\n"
    b"Root-Is-Purelib: true\n"
    b"Tag: py3-none-any\n"
    b"\n"
)
EXPECTED_ENTRY_POINTS = (
    b"[console_scripts]\npassword-policy-lab = password_policy_lab.cli:main\n"
)
EXPECTED_TOP_LEVEL = b"password_policy_lab\n"
EXPECTED_METADATA_PREFIX = (
    b"Metadata-Version: 2.4\n"
    b"Name: password-policy-state-space\n"
    b"Version: 0.1.0\n"
    b"Summary: Exact counting and uniform sampling for constrained password policies\n"
    b"Author: Omar Ibrahim\n"
    b"Project-URL: Repository, https://github.com/omar07ibrahim/PasswordGenerator\n"
    b"Project-URL: Issues, https://github.com/omar07ibrahim/PasswordGenerator/issues\n"
    b"Requires-Python: >=3.11\n"
    b"Description-Content-Type: text/markdown\n"
    b"Requires-Dist: Flask==3.1.3\n"
    b"Requires-Dist: waitress==3.0.2\n"
    b"Provides-Extra: dev\n"
    b'Requires-Dist: build==1.5.0; extra == "dev"\n'
    b'Requires-Dist: matplotlib==3.11.1; extra == "dev"\n'
    b'Requires-Dist: mypy==2.3.0; extra == "dev"\n'
    b'Requires-Dist: numpy==2.4.6; extra == "dev"\n'
    b'Requires-Dist: Pillow==12.3.0; extra == "dev"\n'
    b'Requires-Dist: playwright==1.62.0; extra == "dev"\n'
    b'Requires-Dist: pytest==9.1.1; extra == "dev"\n'
    b'Requires-Dist: pytest-cov==7.1.0; extra == "dev"\n'
    b'Requires-Dist: ruff==0.16.1; extra == "dev"\n'
    b'Requires-Dist: setuptools==83.0.0; extra == "dev"\n'
    b"\n"
)

_SAFE_COMPONENT = re.compile(r"[A-Za-z0-9_.-]+\Z")
_RECORD_DIGEST = re.compile(r"sha256=([A-Za-z0-9_-]{43})\Z")
_PAX_MTIME = re.compile(r"(?:0|[1-9][0-9]{0,9})(?:\.(?:0|[0-9]{0,8}[1-9]))?\Z")
_WINDOWS_RESERVED = frozenset(
    {"CON", "PRN", "AUX", "NUL"}
    | {f"COM{number}" for number in range(1, 10)}
    | {f"LPT{number}" for number in range(1, 10)}
)

ErrorCode = Literal[
    "allowlist-invalid",
    "archive-invalid",
    "archive-too-large",
    "canonical-metadata-invalid",
    "compression-invalid",
    "member-invalid",
    "member-limit-exceeded",
    "metadata-invalid",
    "output-invalid",
    "path-invalid",
    "record-invalid",
]


class DistributionContractError(ValueError):
    """A stable rejection whose message never includes untrusted details."""

    __slots__ = ("code",)

    def __init__(self, code: ErrorCode) -> None:
        self.code = code
        super().__init__(f"distribution contract rejected: {code}")


@dataclass(frozen=True, slots=True)
class ProjectPayloads:
    """Exact trusted payloads expected in project metadata members."""

    metadata: bytes
    wheel: bytes = EXPECTED_WHEEL
    entry_points: bytes = EXPECTED_ENTRY_POINTS
    top_level: bytes = EXPECTED_TOP_LEVEL

    def __post_init__(self) -> None:
        if (
            not isinstance(self.metadata, bytes)
            or len(self.metadata) > MAX_MEMBER_SIZE
            or self.wheel != EXPECTED_WHEEL
            or self.entry_points != EXPECTED_ENTRY_POINTS
            or self.top_level != EXPECTED_TOP_LEVEL
        ):
            _reject("metadata-invalid")


@dataclass(frozen=True, slots=True)
class MemberRecord:
    """Immutable facts measured while streaming one archive member."""

    name: str
    size: int
    sha256: str
    compressed_size: int | None
    mode: int
    mtime: int


@dataclass(frozen=True, slots=True)
class ArtifactRecord:
    """Immutable facts measured for a complete accepted artifact."""

    kind: Literal["wheel", "sdist"]
    size: int
    sha256: str
    members: tuple[MemberRecord, ...]


@dataclass(frozen=True, slots=True)
class _Inspection:
    record: ArtifactRecord
    payloads: Mapping[str, bytes]


def build_expected_metadata(description: bytes) -> bytes:
    """Bind trusted ``PACKAGE.md`` bytes to the exact project metadata header."""

    if (
        not isinstance(description, bytes)
        or len(description) > MAX_MEMBER_SIZE - len(EXPECTED_METADATA_PREFIX)
        or b"\x00" in description
    ):
        _reject("metadata-invalid")
    return EXPECTED_METADATA_PREFIX + description


def inspect_wheel(
    path: str | os.PathLike[str],
    allowed_members: Sequence[str],
    payloads: ProjectPayloads,
    *,
    require_canonical: bool = True,
) -> ArtifactRecord:
    """Inspect one wheel against an exact ordered, project-specific contract."""

    return _public_inspect_wheel(
        path, allowed_members, payloads, require_canonical=require_canonical
    ).record


def canonicalize_wheel(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    allowed_members: Sequence[str],
    payloads: ProjectPayloads,
) -> ArtifactRecord:
    """Rewrite a validated wheel with fixed ZIP container metadata."""

    inspected = _public_inspect_wheel(
        source, allowed_members, payloads, require_canonical=False
    )
    expected = tuple(allowed_members)
    output = Path(destination)

    _atomic_output(
        output,
        lambda stream: _write_canonical_wheel(stream, expected, inspected.payloads),
    )
    return inspect_wheel(output, expected, payloads)


def inspect_sdist(
    path: str | os.PathLike[str],
    allowed_files: Sequence[str],
    payloads: ProjectPayloads,
    *,
    require_canonical: bool = True,
) -> ArtifactRecord:
    """Inspect one source distribution with an exact regular-file allowlist."""

    return _public_inspect_sdist(
        path, allowed_files, payloads, require_canonical=require_canonical
    ).record


def canonicalize_sdist(
    source: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    allowed_files: Sequence[str],
    payloads: ProjectPayloads,
) -> ArtifactRecord:
    """Rewrite a validated sdist as deterministic USTAR inside deterministic gzip."""

    inspected = _public_inspect_sdist(
        source, allowed_files, payloads, require_canonical=False
    )
    files = _validated_allowlist(allowed_files, MAX_SDIST_MEMBERS)
    expected = _sdist_member_plan(files)
    output = Path(destination)

    _atomic_output(
        output,
        lambda stream: _write_canonical_sdist(stream, expected, inspected.payloads),
    )
    return inspect_sdist(output, files, payloads)


def materialize_canonical_sdist(
    archive_path: str | os.PathLike[str],
    destination: str | os.PathLike[str],
    allowed_files: Sequence[str],
    payloads: ProjectPayloads,
) -> ArtifactRecord:
    """Materialize accepted regular files without using ``extractall``.

    ``destination`` must not already exist and becomes the sdist root contents;
    the archive's fixed top-level directory is intentionally stripped.
    """

    inspected = _public_inspect_sdist(
        archive_path, allowed_files, payloads, require_canonical=True
    )
    files = _validated_allowlist(allowed_files, MAX_SDIST_MEMBERS)
    target = Path(destination)
    parent = target.parent
    temporary: Path | None = None
    try:
        _require_absent(target)
        parent.mkdir(parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=".sdist-materialize-", dir=parent))
        os.chmod(temporary, 0o755)
        for relative in files:
            full_name = f"{SDIST_ROOT}/{relative}"
            output = temporary.joinpath(*relative.split("/"))
            output.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            _verify_materialized_parent(temporary, output.parent)
            descriptor = os.open(
                output,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | _no_follow_flag(),
                0o600,
            )
            try:
                stream = os.fdopen(descriptor, "wb", closefd=True)
                descriptor = -1
                with stream:
                    stream.write(inspected.payloads[full_name])
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(output, 0o644, follow_symlinks=False)
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        for directory in sorted(
            (item for item in temporary.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            os.chmod(directory, 0o755, follow_symlinks=False)
        os.replace(temporary, target)
        temporary = None
    except DistributionContractError:
        raise
    except (OSError, ValueError):
        raise DistributionContractError("output-invalid") from None
    finally:
        if temporary is not None:
            shutil.rmtree(temporary, ignore_errors=True)
    return inspected.record


def _public_inspect_wheel(
    path: str | os.PathLike[str],
    allowed_members: Sequence[str],
    payloads: ProjectPayloads,
    *,
    require_canonical: bool,
) -> _Inspection:
    try:
        return _inspect_wheel(path, allowed_members, payloads, require_canonical)
    except DistributionContractError:
        raise
    except (OSError, EOFError, UnicodeError, ValueError, zipfile.BadZipFile):
        raise DistributionContractError("archive-invalid") from None


def _public_inspect_sdist(
    path: str | os.PathLike[str],
    allowed_files: Sequence[str],
    payloads: ProjectPayloads,
    *,
    require_canonical: bool,
) -> _Inspection:
    try:
        return _inspect_sdist(path, allowed_files, payloads, require_canonical)
    except DistributionContractError:
        raise
    except (OSError, EOFError, UnicodeError, ValueError, tarfile.TarError):
        raise DistributionContractError("archive-invalid") from None


def _inspect_wheel(
    path: str | os.PathLike[str],
    allowed_members: Sequence[str],
    project_payloads: ProjectPayloads,
    require_canonical: bool,
) -> _Inspection:
    expected = _validated_allowlist(allowed_members, MAX_WHEEL_MEMBERS)
    required = {
        f"{DIST_INFO}/METADATA",
        f"{DIST_INFO}/WHEEL",
        f"{DIST_INFO}/entry_points.txt",
        f"{DIST_INFO}/top_level.txt",
        f"{DIST_INFO}/RECORD",
    }
    if not required.issubset(expected):
        _reject("allowlist-invalid")

    with _open_outer(path) as stream:
        outer_data, outer_hash = _read_outer(stream)
        outer_size = len(outer_data)
        with zipfile.ZipFile(
            io.BytesIO(outer_data), mode="r", allowZip64=False
        ) as archive:
            if archive.comment:
                _reject("canonical-metadata-invalid")
            infos = archive.infolist()
            if len(infos) > MAX_WHEEL_MEMBERS:
                _reject("member-limit-exceeded")
            observed = tuple(info.filename for info in infos)
            _validate_observed_paths(observed)
            if any(info.orig_filename != info.filename for info in infos):
                _reject("path-invalid")
            if observed != expected:
                _reject("allowlist-invalid")

            advertised_total = 0
            for info in infos:
                _validate_zip_info(info, require_canonical)
                advertised_total += info.file_size
                if advertised_total > MAX_WHEEL_PAYLOAD:
                    _reject("member-limit-exceeded")

            records: list[MemberRecord] = []
            contents: dict[str, bytes] = {}
            measured_total = 0
            for info in infos:
                data, digest = _read_zip_member(archive, info)
                measured_total += len(data)
                if measured_total > MAX_WHEEL_PAYLOAD:
                    _reject("member-limit-exceeded")
                contents[info.filename] = data
                records.append(
                    MemberRecord(
                        name=info.filename,
                        size=len(data),
                        sha256=digest,
                        compressed_size=info.compress_size,
                        mode=info.external_attr >> 16,
                        mtime=_zip_timestamp(info.date_time),
                    )
                )

    _validate_project_payloads(contents, project_payloads)
    _validate_record(contents[f"{DIST_INFO}/RECORD"], tuple(records), expected)
    if require_canonical:
        canonical = io.BytesIO()
        _write_canonical_wheel(canonical, expected, contents)
        _require_canonical_bytes(outer_data, canonical.getvalue())
    return _Inspection(
        ArtifactRecord("wheel", outer_size, outer_hash, tuple(records)), contents
    )


def _inspect_sdist(
    path: str | os.PathLike[str],
    allowed_files: Sequence[str],
    project_payloads: ProjectPayloads,
    require_canonical: bool,
) -> _Inspection:
    files = _validated_allowlist(allowed_files, MAX_SDIST_MEMBERS)
    if "PKG-INFO" not in files:
        _reject("allowlist-invalid")
    expected_plan = _sdist_member_plan(files)
    with _open_outer(path) as stream:
        outer_data, outer_hash = _read_outer(stream)
        outer_size = len(outer_data)
        if require_canonical:
            _validate_gzip_header(io.BytesIO(outer_data))
        tar_data = _decompress_sdist(outer_data)
        with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as archive:
            if archive.pax_headers:
                _reject("canonical-metadata-invalid")
            records: list[MemberRecord] = []
            contents: dict[str, bytes] = {}
            measured_total = 0
            aliases: set[str] = set()
            for expected_name, expected_directory in expected_plan:
                member = archive.next()
                if member is None:
                    _reject("allowlist-invalid")
                _validate_observed_path(member.name, aliases)
                if member.name != expected_name:
                    _reject("allowlist-invalid")
                _validate_tar_info(member, expected_directory, require_canonical)
                if expected_directory:
                    records.append(
                        MemberRecord(
                            member.name,
                            0,
                            hashlib.sha256(b"").hexdigest(),
                            None,
                            member.mode,
                            int(member.mtime),
                        )
                    )
                    continue
                measured_total += member.size
                if measured_total > MAX_SDIST_PAYLOAD:
                    _reject("member-limit-exceeded")
                extracted = archive.extractfile(member)
                if extracted is None:
                    _reject("member-invalid")
                data, digest = _read_bounded(extracted, member.size)
                contents[member.name] = data
                records.append(
                    MemberRecord(
                        member.name,
                        len(data),
                        digest,
                        None,
                        member.mode,
                        int(member.mtime),
                    )
                )
            if archive.next() is not None:
                if len(expected_plan) >= MAX_SDIST_MEMBERS:
                    _reject("member-limit-exceeded")
                _reject("allowlist-invalid")

    if contents[f"{SDIST_ROOT}/PKG-INFO"] != project_payloads.metadata:
        _reject("metadata-invalid")
    if require_canonical:
        canonical = io.BytesIO()
        _write_canonical_sdist(canonical, expected_plan, contents)
        _require_canonical_bytes(outer_data, canonical.getvalue())
    return _Inspection(
        ArtifactRecord("sdist", outer_size, outer_hash, tuple(records)), contents
    )


def _validate_project_payloads(
    contents: Mapping[str, bytes], payloads: ProjectPayloads
) -> None:
    expected = {
        f"{DIST_INFO}/METADATA": payloads.metadata,
        f"{DIST_INFO}/WHEEL": payloads.wheel,
        f"{DIST_INFO}/entry_points.txt": payloads.entry_points,
        f"{DIST_INFO}/top_level.txt": payloads.top_level,
    }
    if any(contents.get(name) != value for name, value in expected.items()):
        _reject("metadata-invalid")


def _validate_record(
    record_data: bytes,
    members: tuple[MemberRecord, ...],
    expected_order: tuple[str, ...],
) -> None:
    record_name = f"{DIST_INFO}/RECORD"
    try:
        text = record_data.decode("ascii")
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except (UnicodeError, csv.Error):
        _reject("record-invalid")
    if len(rows) != len(members) or any(len(row) != 3 for row in rows):
        _reject("record-invalid")
    if tuple(row[0] for row in rows) != expected_order:
        _reject("record-invalid")
    by_name = {member.name: member for member in members}
    canonical_lines: list[str] = []
    for name, encoded_digest, encoded_size in rows:
        if name == record_name:
            if encoded_digest or encoded_size:
                _reject("record-invalid")
            canonical_lines.append(f"{name},,\n")
            continue
        match = _RECORD_DIGEST.fullmatch(encoded_digest)
        member = by_name.get(name)
        if match is None or member is None or not _canonical_decimal(encoded_size):
            _reject("record-invalid")
        expected_digest = bytes.fromhex(member.sha256)
        canonical_digest = (
            base64.urlsafe_b64encode(expected_digest).rstrip(b"=").decode("ascii")
        )
        if (
            not hmac.compare_digest(match.group(1), canonical_digest)
            or int(encoded_size) != member.size
        ):
            _reject("record-invalid")
        canonical_lines.append(f"{name},{encoded_digest},{encoded_size}\n")
    if record_data != "".join(canonical_lines).encode("ascii"):
        _reject("record-invalid")


def _validate_zip_info(info: zipfile.ZipInfo, require_canonical: bool) -> None:
    mode = info.external_attr >> 16
    if info.file_size < 0 or info.file_size > MAX_MEMBER_SIZE:
        _reject("member-limit-exceeded")
    if (
        info.is_dir()
        or not stat.S_ISREG(mode)
        or info.flag_bits != 0
        or info.extra
        or info.comment
        or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
        or info.compress_size < 0
    ):
        _reject("member-invalid")
    if info.file_size and (
        info.compress_size == 0
        or info.file_size > info.compress_size * MAX_COMPRESSION_RATIO
    ):
        _reject("compression-invalid")
    if require_canonical and (
        info.create_system != 3
        or mode != stat.S_IFREG | 0o644
        or info.date_time != FIXED_ZIP_TIME
        or info.compress_type != zipfile.ZIP_DEFLATED
        or info.internal_attr != 0
    ):
        _reject("canonical-metadata-invalid")


def _validate_tar_info(
    member: tarfile.TarInfo, expected_directory: bool, require_canonical: bool
) -> None:
    if member.size < 0 or member.size > MAX_MEMBER_SIZE:
        _reject("member-limit-exceeded")
    _validate_member_pax_mtime(member, require_canonical)
    if member.sparse is not None or member.linkname:
        _reject("member-invalid")
    if expected_directory:
        if not member.isdir() or member.size != 0:
            _reject("member-invalid")
    elif not member.isreg():
        _reject("member-invalid")
    if require_canonical and (
        member.mode != (0o755 if expected_directory else 0o644)
        or member.uid != 0
        or member.gid != 0
        or member.uname != ""
        or member.gname != ""
        or member.mtime != FIXED_MTIME
    ):
        _reject("canonical-metadata-invalid")


def _validate_member_pax_mtime(
    member: tarfile.TarInfo, require_canonical: bool
) -> None:
    headers = member.pax_headers
    if not headers:
        return
    if set(headers) != {"mtime"}:
        _reject("member-invalid")
    value = headers["mtime"]
    if _PAX_MTIME.fullmatch(value) is None:
        _reject("member-invalid")
    parsed = decimal.Decimal(value)
    if parsed > MAX_RAW_MTIME or parsed != decimal.Decimal(str(member.mtime)):
        _reject("member-invalid")
    if require_canonical:
        _reject("canonical-metadata-invalid")


def _validated_allowlist(names: Sequence[str], limit: int) -> tuple[str, ...]:
    if isinstance(names, (str, bytes)):
        _reject("allowlist-invalid")
    try:
        result = tuple(names)
    except TypeError:
        _reject("allowlist-invalid")
    if not result or len(result) > limit:
        _reject("allowlist-invalid")
    aliases: set[str] = set()
    for name in result:
        if not isinstance(name, str):
            _reject("allowlist-invalid")
        _validate_safe_path(name)
        alias = _path_alias(name)
        if alias in aliases:
            _reject("allowlist-invalid")
        aliases.add(alias)
    return result


def _validate_observed_paths(names: Sequence[str]) -> None:
    aliases: set[str] = set()
    for name in names:
        _validate_observed_path(name, aliases)


def _validate_observed_path(name: str, aliases: set[str]) -> None:
    _validate_safe_path(name)
    alias = _path_alias(name)
    if alias in aliases:
        _reject("path-invalid")
    aliases.add(alias)


def _validate_safe_path(name: str) -> None:
    if (
        not name
        or len(name) > 240
        or name.startswith("/")
        or name.endswith("/")
        or "\\" in name
        or "\x00" in name
    ):
        _reject("path-invalid")
    try:
        name.encode("ascii", errors="strict")
    except UnicodeEncodeError:
        _reject("path-invalid")
    components = name.split("/")
    for component in components:
        stem = component.split(".", 1)[0].upper()
        if (
            not component
            or component in {".", ".."}
            or component.endswith(".")
            or _SAFE_COMPONENT.fullmatch(component) is None
            or stem in _WINDOWS_RESERVED
        ):
            _reject("path-invalid")


def _path_alias(name: str) -> str:
    return "/".join(component.casefold().rstrip(". ") for component in name.split("/"))


def _sdist_member_plan(files: tuple[str, ...]) -> tuple[tuple[str, bool], ...]:
    directories = {SDIST_ROOT}
    full_files: set[str] = set()
    for relative in files:
        full = f"{SDIST_ROOT}/{relative}"
        full_files.add(full)
        components = full.split("/")
        for length in range(1, len(components)):
            directories.add("/".join(components[:length]))
    if directories & full_files:
        _reject("allowlist-invalid")
    names = directories | full_files
    if len(names) > MAX_SDIST_MEMBERS:
        _reject("allowlist-invalid")
    return tuple((name, name in directories) for name in sorted(names))


def _open_outer(path: str | os.PathLike[str]) -> BinaryIO:
    try:
        descriptor = os.open(path, os.O_RDONLY | _no_follow_flag())
    except OSError:
        raise DistributionContractError("archive-invalid") from None
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            _reject("archive-invalid")
        if metadata.st_size > MAX_OUTER_SIZE:
            _reject("archive-too-large")
        return os.fdopen(descriptor, "rb", closefd=True)
    except BaseException:
        os.close(descriptor)
        raise


def _read_outer(stream: BinaryIO) -> tuple[bytes, str]:
    digest = hashlib.sha256()
    output = io.BytesIO()
    size = 0
    stream.seek(0)
    while chunk := stream.read(_CHUNK_SIZE):
        size += len(chunk)
        if size > MAX_OUTER_SIZE:
            _reject("archive-too-large")
        digest.update(chunk)
        output.write(chunk)
    return output.getvalue(), digest.hexdigest()


def _decompress_sdist(data: bytes) -> bytes:
    decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)
    try:
        payload = decompressor.decompress(data, MAX_SDIST_STREAM + 1)
        if len(payload) > MAX_SDIST_STREAM or decompressor.unconsumed_tail:
            _reject("member-limit-exceeded")
        payload += decompressor.flush(MAX_SDIST_STREAM - len(payload) + 1)
    except zlib.error:
        raise DistributionContractError("archive-invalid") from None
    if len(payload) > MAX_SDIST_STREAM:
        _reject("member-limit-exceeded")
    if not decompressor.eof or decompressor.unused_data:
        _reject("archive-invalid")
    return payload


def _read_zip_member(
    archive: zipfile.ZipFile, info: zipfile.ZipInfo
) -> tuple[bytes, str]:
    try:
        with archive.open(info, mode="r") as stream:
            return _read_bounded(stream, info.file_size)
    except (OSError, EOFError, RuntimeError, zipfile.BadZipFile):
        raise DistributionContractError("archive-invalid") from None


def _read_bounded(stream: IO[bytes], expected_size: int) -> tuple[bytes, str]:
    digest = hashlib.sha256()
    output = io.BytesIO()
    size = 0
    while chunk := stream.read(_CHUNK_SIZE):
        size += len(chunk)
        if size > MAX_MEMBER_SIZE or size > expected_size:
            _reject("member-limit-exceeded")
        digest.update(chunk)
        output.write(chunk)
    if size != expected_size:
        _reject("member-invalid")
    return output.getvalue(), digest.hexdigest()


def _validate_gzip_header(stream: BinaryIO) -> None:
    stream.seek(0)
    header = stream.read(10)
    if (
        len(header) != 10
        or header[:3] != b"\x1f\x8b\x08"
        or header[3] != 0
        or int.from_bytes(header[4:8], "little") != FIXED_MTIME
        or header[8] != 2
        or header[9] != 255
    ):
        _reject("canonical-metadata-invalid")


def _zip_timestamp(value: tuple[int, int, int, int, int, int]) -> int:
    if value == FIXED_ZIP_TIME:
        return FIXED_MTIME
    # A stable sentinel is enough for noncanonical inspection records.
    return 0


def _canonical_decimal(value: str) -> bool:
    return (
        bool(value)
        and value.isascii()
        and value.isdecimal()
        and (value == "0" or not value.startswith("0"))
    )


def _write_canonical_wheel(
    stream: BinaryIO,
    members: Sequence[str],
    payloads: Mapping[str, bytes],
) -> None:
    with zipfile.ZipFile(
        stream,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
        strict_timestamps=True,
    ) as archive:
        for name in members:
            info = zipfile.ZipInfo(name, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | 0o644) << 16
            info.internal_attr = 0
            info.extra = b""
            info.comment = b""
            archive.writestr(info, payloads[name], compresslevel=9)


def _write_canonical_sdist(
    stream: BinaryIO,
    members: Sequence[tuple[str, bool]],
    payloads: Mapping[str, bytes],
) -> None:
    with (
        gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=stream,
            compresslevel=9,
            mtime=FIXED_MTIME,
        ) as compressed,
        tarfile.open(
            fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT
        ) as archive,
    ):
        for full_name, is_directory in members:
            info = tarfile.TarInfo(full_name)
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            info.mtime = FIXED_MTIME
            if is_directory:
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                info.size = 0
                archive.addfile(info)
            else:
                data = payloads[full_name]
                info.type = tarfile.REGTYPE
                info.mode = 0o644
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))


def _require_canonical_bytes(observed: bytes, expected: bytes) -> None:
    if not hmac.compare_digest(observed, expected):
        _reject("canonical-metadata-invalid")


def _atomic_output(path: Path, writer: Callable[[BinaryIO], None]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w+b", closefd=True) as stream:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644, follow_symlinks=False)
        if temporary.stat(follow_symlinks=False).st_size > MAX_OUTER_SIZE:
            _reject("archive-too-large")
        os.replace(temporary, path)
    except DistributionContractError:
        raise
    except (OSError, ValueError, zipfile.BadZipFile, tarfile.TarError):
        raise DistributionContractError("output-invalid") from None
    finally:
        with suppress(OSError):
            temporary.unlink(missing_ok=True)


def _require_absent(path: Path) -> None:
    try:
        path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        _reject("output-invalid")
    _reject("output-invalid")


def _verify_materialized_parent(root: Path, parent: Path) -> None:
    current = root
    for component in parent.relative_to(root).parts:
        current /= component
        metadata = current.lstat()
        if not stat.S_ISDIR(metadata.st_mode):
            _reject("output-invalid")


def _no_follow_flag() -> int:
    return getattr(os, "O_NOFOLLOW", 0)


def _reject(code: ErrorCode) -> NoReturn:
    raise DistributionContractError(code)
