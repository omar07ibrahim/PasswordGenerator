"""Strict deterministic CLI for inspecting the exact policy state space."""

from __future__ import annotations

import argparse
import getpass
import json
import re
import sys
import warnings
from collections.abc import Sequence
from contextlib import redirect_stderr, redirect_stdout
from typing import Any, Never, TextIO, cast

from password_policy_lab.errors import PasswordPolicyError
from password_policy_lab.inspection import (
    RANK_ORDER_VERSION,
    REPORT_SCHEMA_VERSION,
    StateSpaceInspection,
    inspect_policy,
    policy_sha256,
)
from password_policy_lab.policy import MAX_LENGTH, PasswordPolicy
from password_policy_lab.profiles import (
    VISIBLE_ASCII_CLASS_NAMES,
    VISIBLE_ASCII_PROFILE,
    VisibleAsciiMinima,
    visible_ascii_policy,
)
from password_policy_lab.space import PasswordSpace

_CANONICAL_UNSIGNED = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_MAX_RANK_DIGITS = len(str(94**MAX_LENGTH))
_REVERSIBLE_ACK = "--acknowledge-reversible-output"


class _CliInputError(ValueError):
    """A value-free command input failure."""


class _SafeArgumentParser(argparse.ArgumentParser):
    """Reject malformed invocations without reflecting argument values."""

    def error(self, message: str) -> Never:
        del message
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid arguments\n")


class _StoreOnce(argparse.Action):
    """Reject repeated options instead of silently accepting the last value."""

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
        setattr(namespace, self.dest, self.const if self.nargs == 0 else values)


def _bounded_integer(
    raw: str,
    *,
    minimum: int,
    maximum: int,
    label: str,
) -> int:
    if len(raw) > len(str(maximum)) or _CANONICAL_UNSIGNED.fullmatch(raw) is None:
        raise argparse.ArgumentTypeError(f"{label} must be a canonical decimal integer")
    value = int(raw)
    if not minimum <= value <= maximum:
        raise argparse.ArgumentTypeError(
            f"{label} must be between {minimum} and {maximum}"
        )
    return value


def _length(raw: str) -> int:
    return _bounded_integer(
        raw,
        minimum=1,
        maximum=MAX_LENGTH,
        label="length",
    )


def _minimum(raw: str) -> int:
    return _bounded_integer(
        raw,
        minimum=0,
        maximum=MAX_LENGTH,
        label="minimum",
    )


def _rank_token(raw: str) -> str:
    if len(raw) > _MAX_RANK_DIGITS or _CANONICAL_UNSIGNED.fullmatch(raw) is None:
        raise argparse.ArgumentTypeError("rank must be a canonical decimal integer")
    return raw


def _add_once_argument(
    parser: argparse.ArgumentParser,
    *flags: str,
    **kwargs: Any,
) -> None:
    parser.add_argument(*flags, action=_StoreOnce, **kwargs)


def _add_policy_options(
    parser: argparse.ArgumentParser,
    *,
    include_length: bool,
) -> None:
    if include_length:
        _add_once_argument(parser, "--length", required=True, type=_length)
    _add_once_argument(parser, "--min-lower", default=1, type=_minimum)
    _add_once_argument(parser, "--min-upper", default=1, type=_minimum)
    _add_once_argument(parser, "--min-digits", default=1, type=_minimum)
    _add_once_argument(parser, "--min-punctuation", default=1, type=_minimum)


def _add_format(
    parser: argparse.ArgumentParser,
    *,
    choices: tuple[str, ...],
) -> None:
    _add_once_argument(
        parser,
        "--format",
        choices=choices,
        default="text",
    )


def _add_reversible_acknowledgement(parser: argparse.ArgumentParser) -> None:
    _add_once_argument(
        parser,
        _REVERSIBLE_ACK,
        const=True,
        default=False,
        nargs=0,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="password-policy-lab",
        description=(
            "Inspect the exact visible-ASCII password policy state space "
            "without sampling."
        ),
        allow_abbrev=False,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inspect_parser = subparsers.add_parser(
        "inspect",
        help="report exact counts for one policy",
        allow_abbrev=False,
    )
    _add_policy_options(inspect_parser, include_length=True)
    _add_format(inspect_parser, choices=("text", "json"))

    sweep_parser = subparsers.add_parser(
        "sweep",
        help="report an inclusive ascending length range",
        allow_abbrev=False,
    )
    _add_once_argument(
        sweep_parser,
        "--start-length",
        required=True,
        type=_length,
    )
    _add_once_argument(
        sweep_parser,
        "--end-length",
        required=True,
        type=_length,
    )
    _add_policy_options(sweep_parser, include_length=False)
    _add_format(sweep_parser, choices=("text", "json", "csv"))

    rank_parser = subparsers.add_parser(
        "rank",
        help="rank one candidate read only from hidden input or stdin",
        allow_abbrev=False,
    )
    _add_policy_options(rank_parser, include_length=True)
    _add_reversible_acknowledgement(rank_parser)
    _add_format(rank_parser, choices=("text", "json"))

    unrank_parser = subparsers.add_parser(
        "unrank",
        help="resolve one explicitly public deterministic test vector",
        allow_abbrev=False,
    )
    _add_policy_options(unrank_parser, include_length=True)
    _add_once_argument(unrank_parser, "--rank", required=True, type=_rank_token)
    _add_reversible_acknowledgement(unrank_parser)
    _add_format(unrank_parser, choices=("text", "json"))
    return parser


def _minima(arguments: argparse.Namespace) -> VisibleAsciiMinima:
    return (
        cast(int, arguments.min_lower),
        cast(int, arguments.min_upper),
        cast(int, arguments.min_digits),
        cast(int, arguments.min_punctuation),
    )


def _policy(arguments: argparse.Namespace) -> PasswordPolicy:
    return visible_ascii_policy(cast(int, arguments.length), _minima(arguments))


def _json_document(payload: object) -> str:
    return json.dumps(payload, ensure_ascii=True, indent=2) + "\n"


def _inspection_text(report: StateSpaceInspection) -> str:
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
        f"class.{character_class.name}: size={len(character_class.symbols)} "
        f"minimum={character_class.minimum}"
        for character_class in policy.classes
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


def _sweep_row(report: StateSpaceInspection) -> dict[str, str | int]:
    return {
        "length": report.policy.length,
        "policy_sha256": report.policy_sha256,
        "valid": str(report.valid),
        "unconstrained": str(report.unconstrained),
        "excluded": str(report.excluded),
        "fraction_numerator": str(report.fraction_numerator),
        "fraction_denominator": str(report.fraction_denominator),
        "entropy_bits_floor": report.entropy_bits_floor,
        "entropy_bits_ceiling": report.entropy_bits_ceiling,
        "dp_cells_upper_bound": report.dp_cells_upper_bound,
        "dp_transitions_upper_bound": report.dp_transitions_upper_bound,
    }


_SWEEP_COLUMNS = (
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


def _sweep_delimited(
    rows: Sequence[dict[str, str | int]],
    *,
    delimiter: str,
) -> str:
    output = [delimiter.join(_SWEEP_COLUMNS)]
    output.extend(
        delimiter.join(str(row[column]) for column in _SWEEP_COLUMNS) for row in rows
    )
    return "\n".join(output) + "\n"


def _render_inspection(report: StateSpaceInspection, output_format: str) -> str:
    if output_format == "json":
        mapping = report.to_mapping()
        del mapping["report_schema_version"]
        return _json_document(
            {
                "report_schema_version": REPORT_SCHEMA_VERSION,
                "operation": "inspect",
                "profile": VISIBLE_ASCII_PROFILE,
                **mapping,
            }
        )
    return _inspection_text(report)


def _render_sweep(
    reports: Sequence[StateSpaceInspection],
    *,
    start_length: int,
    end_length: int,
    minima: VisibleAsciiMinima,
    output_format: str,
) -> str:
    rows = [_sweep_row(report) for report in reports]
    if output_format == "json":
        return _json_document(
            {
                "report_schema_version": REPORT_SCHEMA_VERSION,
                "operation": "sweep",
                "rank_order_version": RANK_ORDER_VERSION,
                "profile": VISIBLE_ASCII_PROFILE,
                "inclusive_range": {
                    "start_length": start_length,
                    "end_length": end_length,
                },
                "class_minima": {
                    name: minimum
                    for name, minimum in zip(
                        VISIBLE_ASCII_CLASS_NAMES,
                        minima,
                        strict=True,
                    )
                },
                "rows": rows,
            }
        )
    return _sweep_delimited(
        rows,
        delimiter="," if output_format == "csv" else "\t",
    )


def _read_candidate(
    stdin: TextIO,
    stderr: TextIO,
    *,
    expected_length: int,
) -> str:
    if stdin.isatty():
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                candidate = getpass.getpass("Candidate (hidden): ", stream=stderr)
            except (EOFError, getpass.GetPassWarning) as error:
                raise _CliInputError from error
    else:
        raw = stdin.read(expected_length + 2)
        if len(raw) > expected_length + 1:
            raise _CliInputError
        candidate = raw[:-1] if raw.endswith("\n") else raw

    if len(candidate) != expected_length or "\n" in candidate or "\r" in candidate:
        raise _CliInputError
    return candidate


def _require_reversible_acknowledgement(arguments: argparse.Namespace) -> None:
    if not cast(bool, arguments.acknowledge_reversible_output):
        raise _CliInputError


def _validated_rank(raw_rank: str, total: int) -> int:
    maximum = str(total - 1)
    if len(raw_rank) > len(maximum) or (
        len(raw_rank) == len(maximum) and raw_rank > maximum
    ):
        raise _CliInputError
    return int(raw_rank)


def _rank_document(
    *,
    policy: PasswordPolicy,
    rank: int,
    state_space_size: int,
    output_format: str,
) -> str:
    payload = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "operation": "rank",
        "profile": VISIBLE_ASCII_PROFILE,
        "rank_order_version": RANK_ORDER_VERSION,
        "policy_sha256": policy_sha256(policy),
        "reversible_output": True,
        "rank": str(rank),
        "state_space_size": str(state_space_size),
        "candidate_included": False,
    }
    if output_format == "json":
        return _json_document(payload)
    return (
        "\n".join(
            f"{key}: {str(value).lower() if type(value) is bool else value}"
            for key, value in payload.items()
        )
        + "\n"
    )


def _unrank_document(
    *,
    policy: PasswordPolicy,
    rank: int,
    state_space_size: int,
    candidate: str,
    output_format: str,
) -> str:
    payload = {
        "report_schema_version": REPORT_SCHEMA_VERSION,
        "operation": "unrank",
        "profile": VISIBLE_ASCII_PROFILE,
        "rank_order_version": RANK_ORDER_VERSION,
        "policy_sha256": policy_sha256(policy),
        "reversible_output": True,
        "sampled": False,
        "rank": str(rank),
        "state_space_size": str(state_space_size),
        "deterministic_test_vector": candidate,
    }
    if output_format == "json":
        return _json_document(payload)
    lines = [
        (
            f"{key}: {json.dumps(value, ensure_ascii=True)}"
            if key == "deterministic_test_vector"
            else f"{key}: {str(value).lower() if type(value) is bool else value}"
        )
        for key, value in payload.items()
    ]
    return "\n".join(lines) + "\n"


def _execute(
    arguments: argparse.Namespace,
    *,
    stdin: TextIO,
    stderr: TextIO,
) -> str:
    command = cast(str, arguments.command)
    output_format = cast(str, arguments.format)

    if command == "inspect":
        return _render_inspection(inspect_policy(_policy(arguments)), output_format)

    if command == "sweep":
        start_length = cast(int, arguments.start_length)
        end_length = cast(int, arguments.end_length)
        minima = _minima(arguments)
        if start_length > end_length or start_length < sum(minima):
            raise _CliInputError
        reports = [
            inspect_policy(visible_ascii_policy(length, minima))
            for length in range(start_length, end_length + 1)
        ]
        return _render_sweep(
            reports,
            start_length=start_length,
            end_length=end_length,
            minima=minima,
            output_format=output_format,
        )

    _require_reversible_acknowledgement(arguments)
    policy = _policy(arguments)
    space = PasswordSpace(policy)
    if command == "rank":
        candidate = _read_candidate(
            stdin,
            stderr,
            expected_length=policy.length,
        )
        return _rank_document(
            policy=policy,
            rank=space.rank(candidate),
            state_space_size=space.total,
            output_format=output_format,
        )

    raw_rank = cast(str, arguments.rank)
    rank = _validated_rank(raw_rank, space.total)
    return _unrank_document(
        policy=policy,
        rank=rank,
        state_space_size=space.total,
        candidate=space.unrank(rank),
        output_format=output_format,
    )


def run(
    argv: Sequence[str],
    *,
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    """Run one command with explicitly supplied streams."""

    parser = _build_parser()
    with redirect_stdout(stdout), redirect_stderr(stderr):
        try:
            arguments = parser.parse_args(list(argv))
        except SystemExit as error:
            return cast(int, error.code)

    try:
        document = _execute(arguments, stdin=stdin, stderr=stderr)
    except (_CliInputError, PasswordPolicyError, TypeError, UnicodeError, OSError):
        stderr.write("error: request could not be processed safely\n")
        return 2
    except Exception:
        stderr.write("error: internal failure\n")
        return 1

    try:
        stdout.write(document)
    except BrokenPipeError:
        return 1
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Console-script entry point."""

    return run(
        sys.argv[1:] if argv is None else argv,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )
