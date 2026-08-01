from __future__ import annotations

import copy
import importlib.util
import json
import struct
import sys
import zlib
from pathlib import Path
from typing import Protocol, cast

import pytest

from password_policy_lab.inspection import StateSpaceInspection, inspect_policy
from password_policy_lab.profiles import visible_ascii_policy


class _Checker(Protocol):
    EvidenceValidationError: type[ValueError]
    MANIFEST_PATH: str
    SWEEP_COLUMNS: tuple[str, ...]

    def _png_info(self, data: bytes, label: str) -> tuple[int, int, str]: ...

    def _gif_info(
        self,
        data: bytes,
        label: str,
    ) -> tuple[int, int, int, tuple[int, ...], str]: ...

    def _validate_safe_text(self, text: str, label: str) -> None: ...

    def _validate_frame_fidelity(
        self,
        reference: bytes,
        actual: bytes,
        *,
        width: int,
        height: int,
        label: str,
    ) -> None: ...

    def _expected_sweep(self) -> str: ...

    def _expected_inspection(self, report: StateSpaceInspection) -> str: ...

    def _load_json(self, path: Path) -> tuple[dict[str, object], str]: ...

    def _distribution_input_digest(self, root: Path) -> str: ...

    def _validate_distribution_attestation(
        self,
        root: Path,
        document: dict[str, object],
        json_text: str,
        transcript: str,
        diagram: str,
    ) -> None: ...

    def _validate_capture(self, value: object) -> dict[str, tuple[int, int]]: ...

    def _validate_ast_claims(
        self,
        root: Path,
        textual: dict[str, str],
    ) -> None: ...

    def _validate_readme(self, root: Path) -> None: ...

    def validate_evidence(self, root: Path) -> None: ...

    def main(self, argv: list[str] | None = None) -> int: ...


def _load_checker() -> _Checker:
    path = Path(__file__).resolve().parents[1] / "scripts/check_evidence.py"
    spec = importlib.util.spec_from_file_location("portfolio_evidence_checker", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load the evidence checker")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return cast(_Checker, module)


check_evidence = _load_checker()


def _chunk(kind: bytes, payload: bytes) -> bytes:
    checksum = zlib.crc32(kind + payload) & 0xFFFFFFFF
    return (
        struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", checksum)
    )


def _png(width: int = 2, height: int = 3) -> bytes:
    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    rows = b"".join(b"\x00" + (b"\x00\x00\x00" * width) for _ in range(height))
    return (
        b"\x89PNG\r\n\x1a\n"
        + _chunk(b"IHDR", header)
        + _chunk(b"IDAT", zlib.compress(rows))
        + _chunk(b"IEND", b"")
    )


def _gif(
    *,
    delays: tuple[int, ...] = (800, 800, 800),
    disposal: int = 1,
    loop: bool = False,
) -> bytes:
    logical_screen = b"\x01\x00\x01\x00\x80\x00\x00"
    global_palette = b"\x00\x00\x00\xff\xff\xff"
    loop_extension = b"!\xff\x0bNETSCAPE2.0\x03\x01\x00\x00\x00" if loop else b""
    frames: list[bytes] = []
    for delay in delays:
        hundredths = delay // 10
        control = (
            b"!\xf9\x04"
            + bytes((disposal << 2,))
            + hundredths.to_bytes(2, "little")
            + b"\x00\x00"
        )
        image = b",\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00"
        frames.append(control + image)
    return (
        b"GIF89a"
        + logical_screen
        + global_palette
        + loop_extension
        + b"".join(frames)
        + b";"
    )


def test_png_parser_verifies_dimensions_and_checksums() -> None:
    data = _png()

    assert check_evidence._png_info(data, "fixture.png") == (2, 3, "")

    corrupted = bytearray(data)
    corrupted[-5] ^= 1
    with pytest.raises(check_evidence.EvidenceValidationError, match="checksum"):
        check_evidence._png_info(bytes(corrupted), "fixture.png")


def test_gif_parser_records_explicit_one_shot_frame_durations() -> None:
    data = _gif()

    assert check_evidence._gif_info(data, "fixture.gif") == (
        1,
        1,
        3,
        (800, 800, 800),
        "",
    )

    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="loop extension",
    ):
        check_evidence._gif_info(_gif(loop=True), "fixture.gif")
    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="disposal method 1",
    ):
        check_evidence._gif_info(_gif(disposal=2), "fixture.gif")
    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="accessible animation",
    ):
        check_evidence._gif_info(_gif(delays=(700, 800, 800)), "fixture.gif")
    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="accessible animation",
    ):
        check_evidence._gif_info(
            _gif(delays=(1_800, 1_800, 1_800)),
            "fixture.gif",
        )


def test_localized_fidelity_rejects_clipping_that_global_average_hides() -> None:
    width = 108
    height = 90
    reference = bytes((80, 120, 160)) * (width * height)

    check_evidence._validate_frame_fidelity(
        reference,
        reference,
        width=width,
        height=height,
        label="synthetic frame",
    )

    clipped = bytearray(reference)
    for y in range(20, 22):
        for x in range(20, 24):
            offset = (y * width + x) * 3
            clipped[offset : offset + 3] = bytes((40, 80, 120))

    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="localized GIF fidelity",
    ):
        check_evidence._validate_frame_fidelity(
            reference,
            bytes(clipped),
            width=width,
            height=height,
            label="synthetic frame",
        )


@pytest.mark.parametrize(
    ("unsafe", "reason"),
    [
        ("/home/ubuntu/gitcode/project", "workspace path"),
        ("person@example.invalid", "email address"),
        ("captured 2026-07-26T14:30:00Z", "timestamp"),
        ("Authorization: Bearer not-a-real-token", "credential"),
        ("deterministic_test_vector: aA0!", "candidate output"),
    ],
)
def test_safe_text_rejects_sensitive_or_nondeterministic_material(
    unsafe: str,
    reason: str,
) -> None:
    with pytest.raises(check_evidence.EvidenceValidationError, match=reason):
        check_evidence._validate_safe_text(unsafe, "fixture")


def test_safe_text_allows_password_domain_vocabulary() -> None:
    check_evidence._validate_safe_text(
        "Password policy audit; generated-output absent; sampler calls 0.",
        "fixture",
    )


def test_exact_core_transcripts_cover_the_declared_range() -> None:
    sweep = check_evidence._expected_sweep()
    inspection = check_evidence._expected_inspection(
        inspect_policy(visible_ascii_policy(20))
    )

    assert sweep.splitlines()[0] == ",".join(check_evidence.SWEEP_COLUMNS)
    assert [line.split(",", 1)[0] for line in sweep.splitlines()[1:]] == [
        str(length) for length in range(8, 33)
    ]
    assert "length: 20\n" in inspection
    assert "uniform_candidate_probability: 1/" in inspection
    assert "timestamp" not in inspection


def test_manifest_loader_rejects_duplicates_and_noncanonical_json(
    tmp_path: Path,
) -> None:
    path = tmp_path / "manifest.json"
    path.write_text('{"schema_version":1,"schema_version":1}\n', encoding="utf-8")

    with pytest.raises(check_evidence.EvidenceValidationError, match="duplicate"):
        check_evidence._load_json(path)

    path.write_text(json.dumps({"schema_version": 1}) + "\n", encoding="utf-8")
    with pytest.raises(check_evidence.EvidenceValidationError, match="canonical"):
        check_evidence._load_json(path)


def test_distribution_attestation_is_source_bound_and_rejects_overclaim() -> None:
    root = Path(__file__).resolve().parents[1]
    path = root / "docs/evidence/distribution-attestation.json"
    document, text = check_evidence._load_json(path)
    transcript = (root / "docs/evidence/distribution-check.txt").read_text(
        encoding="utf-8"
    )
    diagram = (root / "docs/assets/distribution-contract.svg").read_text(
        encoding="utf-8"
    )

    check_evidence._validate_distribution_attestation(
        root,
        document,
        text,
        transcript,
        diagram,
    )
    source = cast(dict[str, object], document["source"])
    assert set(source) == {
        "distribution_input_count",
        "distribution_input_sha256",
        "git_index_stage",
    }
    assert source["distribution_input_sha256"] == (
        check_evidence._distribution_input_digest(root)
    )

    overclaimed = copy.deepcopy(document)
    boundaries = cast(dict[str, object], overclaimed["claim_boundaries"])
    boundaries["license_declared"] = True
    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="claim boundaries",
    ):
        check_evidence._validate_distribution_attestation(
            root,
            overclaimed,
            text,
            transcript,
            diagram,
        )

    stale = copy.deepcopy(document)
    stale_source = cast(dict[str, object], stale["source"])
    stale_source["distribution_input_sha256"] = "0" * 64
    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="input digest",
    ):
        check_evidence._validate_distribution_attestation(
            root,
            stale,
            text,
            transcript,
            diagram,
        )


def test_distribution_attestation_rejects_self_referential_git_fields() -> None:
    root = Path(__file__).resolve().parents[1]
    document, text = check_evidence._load_json(
        root / "docs/evidence/distribution-attestation.json"
    )
    transcript = (root / "docs/evidence/distribution-check.txt").read_text(
        encoding="utf-8"
    )
    diagram = (root / "docs/assets/distribution-contract.svg").read_text(
        encoding="utf-8"
    )
    source = cast(dict[str, object], document["source"])
    source["git_index_tree"] = "a" * 40

    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="unexpected schema",
    ):
        check_evidence._validate_distribution_attestation(
            root,
            document,
            text,
            transcript,
            diagram,
        )


def test_capture_rejects_unpinned_parallel_rasterization() -> None:
    root = Path(__file__).resolve().parents[1]
    document, _ = check_evidence._load_json(root / check_evidence.MANIFEST_PATH)
    capture = cast(dict[str, object], document["capture"])
    capture["chromium_launch_args"] = []

    with pytest.raises(
        check_evidence.EvidenceValidationError,
        match="one raster thread",
    ):
        check_evidence._validate_capture(capture)


def test_ast_claims_match_the_audited_core() -> None:
    root = Path(__file__).resolve().parents[1]
    textual = {
        "docs/assets/architecture.svg": (
            "CLI web invalid web request inspection PasswordSpace PasswordPolicy"
        ),
        "docs/assets/uniform-sampling-flow.svg": "uniform randbelow unrank",
    }

    check_evidence._validate_ast_claims(root, textual)


def test_readme_validation_is_robust_when_readme_is_absent(tmp_path: Path) -> None:
    check_evidence._validate_readme(tmp_path)


def test_checked_in_evidence_bundle_is_valid_when_generated() -> None:
    root = Path(__file__).resolve().parents[1]
    if not (root / check_evidence.MANIFEST_PATH).exists():
        pytest.skip("evidence generator has not populated the bundle yet")

    check_evidence.validate_evidence(root)


def test_main_emits_stable_success_output(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(check_evidence, "validate_evidence", lambda root: None)

    assert check_evidence.main(["--root", str(tmp_path)]) == 0
    captured = capsys.readouterr()
    assert captured.out == "evidence validation passed\n"
    assert captured.err == ""
