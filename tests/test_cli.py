from __future__ import annotations

import getpass
import io
import json
import sys
import warnings
from collections.abc import Sequence
from typing import TextIO

import pytest

from password_policy_lab import PasswordSpace, visible_ascii_policy
from password_policy_lab.cli import main, run


class _TTYInput(io.StringIO):
    def isatty(self) -> bool:
        return True


class _UnreadableInput(io.StringIO):
    def read(self, size: int | None = -1) -> str:
        raise AssertionError(f"stdin was read with size {size}")


class _UnicodeFailureInput(io.StringIO):
    def read(self, size: int | None = -1) -> str:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid")


class _BrokenOutput(io.StringIO):
    def write(self, value: str) -> int:
        del value
        raise BrokenPipeError


def _invoke(
    arguments: Sequence[str],
    *,
    candidate_input: str = "",
    stdin: TextIO | None = None,
    stdout: io.StringIO | None = None,
) -> tuple[int, str, str]:
    actual_stdin = io.StringIO(candidate_input) if stdin is None else stdin
    actual_stdout = io.StringIO() if stdout is None else stdout
    stderr = io.StringIO()
    status = run(
        arguments,
        stdin=actual_stdin,
        stdout=actual_stdout,
        stderr=stderr,
    )
    return status, actual_stdout.getvalue(), stderr.getvalue()


def test_inspect_json_is_exact_stable_and_randomness_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_randomness(upper_bound: int) -> int:
        raise AssertionError(f"unexpected entropy request: {upper_bound}")

    monkeypatch.setattr(
        "password_policy_lab.space.secrets.randbelow",
        forbidden_randomness,
    )
    arguments = ["inspect", "--length", "8", "--format", "json"]

    first = _invoke(arguments)
    second = _invoke(arguments)
    payload = json.loads(first[1])

    assert first == second
    assert first[0] == 0
    assert first[2] == ""
    assert first[1].endswith("\n")
    assert payload["report_schema_version"] == 1
    assert payload["operation"] == "inspect"
    assert payload["profile"] == "visible-ascii-v1"
    assert payload["policy"]["length"] == 8
    assert payload["policy"]["alphabet_size"] == 94
    assert isinstance(payload["state_space"]["valid"], str)
    assert "timestamp" not in first[1]
    assert "/home/" not in first[1]


def test_every_cli_operation_is_entropy_free(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def forbidden_randomness(upper_bound: int) -> int:
        raise AssertionError(f"unexpected entropy request: {upper_bound}")

    monkeypatch.setattr(
        "password_policy_lab.space.secrets.randbelow",
        forbidden_randomness,
    )
    invocations = [
        (["inspect", "--length", "4"], ""),
        (["sensitivity", "--length", "4"], ""),
        (
            [
                "sweep",
                "--start-length",
                "4",
                "--end-length",
                "5",
            ],
            "",
        ),
        (
            [
                "rank",
                "--length",
                "4",
                "--acknowledge-reversible-output",
            ],
            "aA0!\n",
        ),
        (
            [
                "unrank",
                "--length",
                "4",
                "--rank",
                "0",
                "--acknowledge-reversible-output",
            ],
            "",
        ),
    ]

    for arguments, candidate_input in invocations:
        status, _, error = _invoke(arguments, candidate_input=candidate_input)
        assert status == 0
        assert error == ""


def test_sensitivity_json_matches_independent_exact_counts() -> None:
    arguments = ["sensitivity", "--length", "4", "--format", "json"]

    first = _invoke(arguments, stdin=_UnreadableInput())
    second = _invoke(arguments, stdin=_UnreadableInput())
    payload = json.loads(first[1])
    baseline = PasswordSpace(visible_ascii_policy(4)).total
    relaxed_minima = (
        (0, 1, 1, 1),
        (1, 0, 1, 1),
        (1, 1, 0, 1),
        (1, 1, 1, 0),
    )

    assert first == second
    assert first[0] == 0
    assert first[2] == ""
    assert payload["sensitivity_schema_version"] == 1
    assert payload["analysis"] == "one-step-class-minimum-relaxation-v1"
    assert payload["operation"] == "sensitivity"
    assert payload["profile"] == "visible-ascii-v1"
    assert payload["baseline_valid"] == str(baseline)
    assert [row["class_name"] for row in payload["rows"]] == [
        "lower",
        "upper",
        "digits",
        "punctuation",
    ]
    for row, minima in zip(payload["rows"], relaxed_minima, strict=True):
        relaxed = PasswordSpace(visible_ascii_policy(4, minima)).total
        assert row["relaxation_applied"] is True
        assert row["relaxed_minimum"] == 0
        assert row["relaxed_valid"] == str(relaxed)
        assert row["added_if_relaxed"] == str(relaxed - baseline)
    assert payload["claim_boundary"] == {
        "one_step_only": True,
        "effects_are_not_additive": True,
        "contains_candidate": False,
        "samples_entropy": False,
    }
    assert "timestamp" not in first[1]
    assert "/home/" not in first[1]


@pytest.mark.parametrize("output_format", ["text", "csv"])
def test_sensitivity_reader_formats_expose_scope_and_zero_minimum(
    output_format: str,
) -> None:
    status, output, error = _invoke(
        [
            "sensitivity",
            "--length",
            "4",
            "--min-digits",
            "0",
            "--format",
            output_format,
        ],
        stdin=_UnreadableInput(),
    )

    assert status == 0
    assert error == ""
    if output_format == "csv":
        lines = output.splitlines()
        assert lines[0].startswith("sensitivity_schema_version,analysis,operation")
        assert len(lines) == 5
        assert all(len(line.split(",")) == 22 for line in lines)
        assert any(",digits,0,false,0," in line for line in lines[1:])
    else:
        assert "operation: sensitivity" in output
        assert "claim_boundary.effects_are_not_additive: true" in output
        assert "claim_boundary.contains_candidate: false" in output
        assert "class.digits.minimum: 0 -> 0" in output
        assert "class.digits.relaxation_applied: false" in output
        assert "class.digits.added_if_relaxed: 0" in output
        assert "class.digits.baseline_share_of_relaxed: 1/1" in output


def test_inspect_text_contains_exact_reader_facing_fields() -> None:
    status, output, error = _invoke(
        [
            "inspect",
            "--length",
            "8",
            "--min-lower",
            "2",
            "--min-digits",
            "0",
        ]
    )

    assert status == 0
    assert error == ""
    assert "profile: visible-ascii-v1" in output
    assert "class.lower: size=26 minimum=2" in output
    assert "class.digits: size=10 minimum=0" in output
    assert "satisfying_fraction:" in output
    assert "entropy_bits_floor:" in output
    assert "dp_transitions_upper_bound:" in output


@pytest.mark.parametrize("output_format", ["csv", "text"])
def test_sweep_delimited_output_is_inclusive_and_ascending(
    output_format: str,
) -> None:
    status, output, error = _invoke(
        [
            "sweep",
            "--start-length",
            "4",
            "--end-length",
            "6",
            "--format",
            output_format,
        ]
    )
    delimiter = "," if output_format == "csv" else "\t"
    lines = output.splitlines()

    assert status == 0
    assert error == ""
    assert lines[0].startswith(f"length{delimiter}policy_sha256")
    assert [line.split(delimiter, 1)[0] for line in lines[1:]] == ["4", "5", "6"]


def test_sweep_json_matches_independent_core_counts() -> None:
    status, output, error = _invoke(
        [
            "sweep",
            "--start-length",
            "4",
            "--end-length",
            "5",
            "--format",
            "json",
        ]
    )
    payload = json.loads(output)

    assert status == 0
    assert error == ""
    assert payload["inclusive_range"] == {
        "start_length": 4,
        "end_length": 5,
    }
    assert payload["class_minima"] == {
        "lower": 1,
        "upper": 1,
        "digits": 1,
        "punctuation": 1,
    }
    assert [row["length"] for row in payload["rows"]] == [4, 5]
    assert [row["valid"] for row in payload["rows"]] == [
        str(PasswordSpace(visible_ascii_policy(length)).total) for length in (4, 5)
    ]


@pytest.mark.parametrize(
    "arguments",
    [
        ["sweep", "--start-length", "6", "--end-length", "5"],
        ["sweep", "--start-length", "3", "--end-length", "5"],
        [
            "inspect",
            "--length",
            "3",
            "--min-lower",
            "1",
            "--min-upper",
            "1",
            "--min-digits",
            "1",
            "--min-punctuation",
            "1",
        ],
    ],
)
def test_invalid_policy_ranges_fail_atomically(arguments: list[str]) -> None:
    status, output, error = _invoke(arguments)

    assert status == 2
    assert output == ""
    assert error == "error: request could not be processed safely\n"


@pytest.mark.parametrize(
    "arguments",
    [
        [],
        ["inspect"],
        ["inspect", "--len", "8"],
        ["inspect", "--length", "8", "--length", "9"],
        ["inspect", "--length", "08"],
        ["inspect", "--length", "0"],
        ["inspect", "--length", "9999"],
        ["inspect", "--length", "8", "--min-lower=-1"],
        ["inspect", "--length", "8", "--format", "yaml"],
        ["sensitivity", "--length", "8", "--min-lower", "1", "--min-lower", "0"],
        ["sensitivity", "--length", "8", "--format", "yaml"],
        ["unknown"],
    ],
)
def test_parser_rejects_missing_ambiguous_or_noncanonical_arguments(
    arguments: list[str],
) -> None:
    status, output, error = _invoke(arguments)

    assert status == 2
    assert output == ""
    assert "error:" in error


def test_help_is_successful_and_does_not_touch_stdin() -> None:
    status, output, error = _invoke(["--help"], stdin=_UnreadableInput())

    assert status == 0
    assert "without sampling" in output
    assert error == ""


def test_rank_reads_one_bounded_record_and_never_echoes_candidate() -> None:
    candidate = "aA0!"
    status, output, error = _invoke(
        [
            "rank",
            "--length",
            "4",
            "--acknowledge-reversible-output",
            "--format",
            "json",
        ],
        candidate_input=candidate + "\n",
    )
    payload = json.loads(output)

    assert status == 0
    assert error == ""
    assert candidate not in output
    assert candidate not in error
    assert payload["operation"] == "rank"
    assert payload["profile"] == "visible-ascii-v1"
    assert payload["reversible_output"] is True
    assert payload["candidate_included"] is False
    assert payload["rank"] == str(
        PasswordSpace(visible_ascii_policy(4)).rank(candidate)
    )
    assert payload["state_space_size"] == str(
        PasswordSpace(visible_ascii_policy(4)).total
    )


def test_rank_text_marks_output_as_reversible() -> None:
    status, output, error = _invoke(
        [
            "rank",
            "--length",
            "4",
            "--acknowledge-reversible-output",
        ],
        candidate_input="aA0!",
    )

    assert status == 0
    assert error == ""
    assert "operation: rank" in output
    assert "reversible_output: true" in output
    assert "candidate_included: false" in output


def test_rank_requires_acknowledgement_before_reading_input() -> None:
    status, output, error = _invoke(
        ["rank", "--length", "4"],
        stdin=_UnreadableInput("aA0!"),
    )

    assert status == 2
    assert output == ""
    assert error == "error: request could not be processed safely\n"


def test_rank_parser_never_echoes_an_accidental_candidate_argument() -> None:
    candidate = "UNIQUE-CANDIDATE-THAT-MUST-NOT-LEAK"
    status, output, error = _invoke(
        [
            "rank",
            "--length",
            "4",
            "--acknowledge-reversible-output",
            candidate,
        ],
        stdin=_UnreadableInput(),
    )

    assert status == 2
    assert output == ""
    assert candidate not in error
    assert error.endswith("error: invalid arguments\n")


@pytest.mark.parametrize(
    "candidate",
    [
        "aA0!\r\n",
        "aA0!\n\n",
        "aA0",
        "aA0!!",
        "aA0\x00",
        "aaaa",
    ],
)
def test_rank_rejects_malformed_or_invalid_candidates_without_echo(
    candidate: str,
) -> None:
    status, output, error = _invoke(
        [
            "rank",
            "--length",
            "4",
            "--acknowledge-reversible-output",
        ],
        candidate_input=candidate,
    )

    assert status == 2
    assert output == ""
    assert candidate not in error
    assert error == "error: request could not be processed safely\n"


def test_rank_uses_hidden_terminal_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    candidate = "aA0!"
    prompts: list[tuple[str, TextIO | None]] = []

    def hidden_input(prompt: str, stream: TextIO | None = None) -> str:
        prompts.append((prompt, stream))
        return candidate

    monkeypatch.setattr("password_policy_lab.cli.getpass.getpass", hidden_input)
    terminal = _TTYInput()
    stdout = io.StringIO()
    stderr = io.StringIO()

    status = run(
        [
            "rank",
            "--length",
            "4",
            "--acknowledge-reversible-output",
        ],
        stdin=terminal,
        stdout=stdout,
        stderr=stderr,
    )

    assert status == 0
    assert candidate not in stdout.getvalue()
    assert prompts == [("Candidate (hidden): ", stderr)]


@pytest.mark.parametrize("failure_name", ["eof", "warning"])
def test_rank_refuses_unavailable_safe_terminal_input(
    monkeypatch: pytest.MonkeyPatch,
    failure_name: str,
) -> None:
    def unsafe_input(prompt: str, stream: TextIO | None = None) -> str:
        del prompt, stream
        if failure_name == "warning":
            warnings.warn(
                "terminal echo cannot be disabled",
                getpass.GetPassWarning,
                stacklevel=1,
            )
        raise EOFError

    monkeypatch.setattr("password_policy_lab.cli.getpass.getpass", unsafe_input)
    status, output, error = _invoke(
        [
            "rank",
            "--length",
            "4",
            "--acknowledge-reversible-output",
        ],
        stdin=_TTYInput(),
    )

    assert status == 2
    assert output == ""
    assert error == "error: request could not be processed safely\n"


@pytest.mark.parametrize("output_format", ["text", "json"])
def test_unrank_returns_an_explicit_unsampled_public_vector(
    output_format: str,
) -> None:
    status, output, error = _invoke(
        [
            "unrank",
            "--length",
            "4",
            "--rank",
            "0",
            "--acknowledge-reversible-output",
            "--format",
            output_format,
        ]
    )

    assert status == 0
    assert error == ""
    assert "unrank" in output
    assert "sampled" in output
    assert "false" in output.lower()
    assert (
        json.dumps(
            PasswordSpace(visible_ascii_policy(4)).unrank(0),
            ensure_ascii=True,
        )
        in output
    )


def test_unrank_requires_acknowledgement() -> None:
    assert _invoke(["unrank", "--length", "4", "--rank", "0"]) == (
        2,
        "",
        "error: request could not be processed safely\n",
    )


@pytest.mark.parametrize(
    "rank",
    [
        "01",
        "+1",
        "-1",
        "9" * 600,
    ],
)
def test_unrank_parser_rejects_noncanonical_or_unbounded_ranks(rank: str) -> None:
    status, output, error = _invoke(
        [
            "unrank",
            "--length",
            "4",
            "--rank",
            rank,
            "--acknowledge-reversible-output",
        ]
    )

    assert status == 2
    assert output == ""
    assert "error:" in error


@pytest.mark.parametrize("rank", ["99", "999"])
def test_unrank_rejects_same_or_greater_digit_out_of_range_ranks(
    rank: str,
) -> None:
    status, output, error = _invoke(
        [
            "unrank",
            "--length",
            "1",
            "--min-lower",
            "0",
            "--min-upper",
            "0",
            "--min-digits",
            "0",
            "--min-punctuation",
            "0",
            "--rank",
            rank,
            "--acknowledge-reversible-output",
        ]
    )

    assert status == 2
    assert output == ""
    assert error == "error: request could not be processed safely\n"


def test_unicode_input_failure_is_generic() -> None:
    status, output, error = _invoke(
        [
            "rank",
            "--length",
            "4",
            "--acknowledge-reversible-output",
        ],
        stdin=_UnicodeFailureInput(),
    )

    assert status == 2
    assert output == ""
    assert error == "error: request could not be processed safely\n"


def test_unexpected_internal_failure_is_generic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*args: object, **kwargs: object) -> str:
        del args, kwargs
        raise RuntimeError("unique-internal-detail")

    monkeypatch.setattr("password_policy_lab.cli._execute", fail)
    status, output, error = _invoke(["inspect", "--length", "8"])

    assert status == 1
    assert output == ""
    assert error == "error: internal failure\n"
    assert "unique-internal-detail" not in error


def test_broken_output_returns_failure_without_traceback() -> None:
    status, _, error = _invoke(
        ["inspect", "--length", "8"],
        stdout=_BrokenOutput(),
    )

    assert status == 1
    assert error == ""


def test_main_accepts_explicit_arguments(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert main(["inspect", "--length", "4"]) == 0
    captured = capsys.readouterr()
    assert "valid:" in captured.out
    assert captured.err == ""


def test_main_uses_process_arguments(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(sys, "argv", ["password-policy-lab", "--help"])

    assert main() == 0
    captured = capsys.readouterr()
    assert "password-policy-lab" in captured.out
    assert captured.err == ""
