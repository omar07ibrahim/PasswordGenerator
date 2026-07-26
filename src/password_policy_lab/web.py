"""A small, local-only Flask interface for the audited password sampler."""

from __future__ import annotations

import re
from collections.abc import Mapping

from flask import Flask, Response, render_template, request
from werkzeug.exceptions import BadRequest, RequestEntityTooLarge

from password_policy_lab.inspection import StateSpaceInspection, inspect_space
from password_policy_lab.policy import PasswordPolicy
from password_policy_lab.profiles import visible_ascii_policy
from password_policy_lab.space import PasswordSpace

MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
DEFAULT_PASSWORD_LENGTH = 20

MAX_REQUEST_BYTES = 1_024
MAX_FORM_BYTES = 1_024
MAX_FORM_PARTS = 1

_FORM_MIMETYPE = "application/x-www-form-urlencoded"
_LENGTH = re.compile(r"[1-9][0-9]{0,2}\Z")
_FORM_ERROR = "Submit exactly one whole-number length from 8 through 128."
_MEDIA_TYPE_ERROR = "Submit the form as application/x-www-form-urlencoded."
_REQUEST_ERROR = "The request could not be accepted."
_TOO_LARGE_ERROR = "The submitted form is too large."

_CONTENT_SECURITY_POLICY = "; ".join(
    (
        "default-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
        "connect-src 'none'",
        "font-src 'none'",
        "frame-src 'none'",
        "img-src 'none'",
        "manifest-src 'none'",
        "media-src 'none'",
        "object-src 'none'",
        "script-src 'none'",
        "style-src 'self'",
        "worker-src 'none'",
    )
)


class _FormValidationError(ValueError):
    """An intentionally value-free form validation failure."""


class _UnsupportedFormMediaType(_FormValidationError):
    """A form arrived with a media type this single-purpose route rejects."""


def _default_policy(length: int) -> PasswordPolicy:
    return visible_ascii_policy(length)


def _parse_length() -> int:
    if request.mimetype != _FORM_MIMETYPE:
        raise _UnsupportedFormMediaType

    form = request.form
    if set(form) != {"length"}:
        raise _FormValidationError

    values = form.getlist("length")
    if len(values) != 1:
        raise _FormValidationError

    raw_length = values[0]
    if _LENGTH.fullmatch(raw_length) is None:
        raise _FormValidationError

    length = int(raw_length)
    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        raise _FormValidationError
    return length


def _render_page(
    *,
    length: int | str = DEFAULT_PASSWORD_LENGTH,
    password: str | None = None,
    error: str | None = None,
    form_error: bool = False,
    inspection: StateSpaceInspection | None = None,
) -> str:
    inspection_view: dict[str, object] | None = None
    if inspection is not None:
        inspection_view = {
            "alphabet_size": len(inspection.policy.alphabet),
            "class_count": len(inspection.policy.classes),
            "classes": [
                {
                    "minimum": character_class.minimum,
                    "name": character_class.name,
                    "size": len(character_class.symbols),
                }
                for character_class in inspection.policy.classes
            ],
            "dp_cells_upper_bound": f"{inspection.dp_cells_upper_bound:,}",
            "entropy_bits": (
                f"{inspection.entropy_bits_floor}"
                f"\u2013{inspection.entropy_bits_ceiling}"
            ),
            "excluded": f"{inspection.excluded:,}",
            "fraction": (
                f"{inspection.fraction_numerator}/{inspection.fraction_denominator}"
            ),
            "minimum_total": sum(inspection.policy.minima),
            "policy_sha256": inspection.policy_sha256,
            "unconstrained": f"{inspection.unconstrained:,}",
            "valid": f"{inspection.valid:,}",
            "valid_raw": str(inspection.valid),
        }
    return render_template(
        "index.html",
        error=error,
        form_error=form_error,
        inspection=inspection_view,
        length=length,
        maximum_length=MAX_PASSWORD_LENGTH,
        minimum_length=MIN_PASSWORD_LENGTH,
        password=password,
    )


def create_app(test_config: Mapping[str, object] | None = None) -> Flask:
    """Create the stateless, local-only password generator application."""

    app = Flask(__name__)
    app.config.from_mapping(
        MAX_CONTENT_LENGTH=MAX_REQUEST_BYTES,
        MAX_FORM_MEMORY_SIZE=MAX_FORM_BYTES,
        MAX_FORM_PARTS=MAX_FORM_PARTS,
        TRUSTED_HOSTS=["localhost", "127.0.0.1"],
    )
    if test_config is not None:
        app.config.from_mapping(test_config)

    @app.after_request
    def secure_response(response: Response) -> Response:
        response.headers["Cache-Control"] = "no-store, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Content-Security-Policy"] = _CONTENT_SECURITY_POLICY
        response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    @app.errorhandler(BadRequest)
    def handle_bad_request(error: BadRequest) -> tuple[str, int]:
        del error
        return _render_page(error=_REQUEST_ERROR), 400

    @app.errorhandler(RequestEntityTooLarge)
    def handle_oversized_request(error: RequestEntityTooLarge) -> tuple[str, int]:
        del error
        return _render_page(error=_TOO_LARGE_ERROR), 413

    @app.get("/")
    def index() -> str:
        space = PasswordSpace(_default_policy(DEFAULT_PASSWORD_LENGTH))
        return _render_page(inspection=inspect_space(space))

    @app.post("/")
    def generate_password() -> tuple[str, int] | str:
        try:
            length = _parse_length()
        except _UnsupportedFormMediaType:
            return _render_page(error=_MEDIA_TYPE_ERROR), 415
        except _FormValidationError:
            return _render_page(length="", error=_FORM_ERROR, form_error=True), 400

        space = PasswordSpace(_default_policy(length))
        inspection = inspect_space(space)
        password = space.sample_uniform()
        return _render_page(
            inspection=inspection,
            length=length,
            password=password,
        )

    return app
