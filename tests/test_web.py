from __future__ import annotations

import html
import logging
import re
import string
from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient
from werkzeug.datastructures import MultiDict

from password_policy_lab import (
    CharacterClass,
    PasswordPolicy,
    PasswordSpace,
    create_app,
)
from password_policy_lab.web import (
    MAX_FORM_BYTES,
    MAX_FORM_PARTS,
    MAX_PASSWORD_LENGTH,
    MAX_REQUEST_BYTES,
    MIN_PASSWORD_LENGTH,
)


@pytest.fixture
def app() -> Flask:
    return create_app({"TESTING": True})


@pytest.fixture
def client(app: Flask) -> Iterator[FlaskClient]:
    with app.test_client() as test_client:
        yield test_client


def test_app_factory_sets_bounded_local_only_configuration(app: Flask) -> None:
    assert (MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH) == (8, 128)
    assert app.secret_key is None
    assert app.config["MAX_CONTENT_LENGTH"] == MAX_REQUEST_BYTES == 1_024
    assert app.config["MAX_FORM_MEMORY_SIZE"] == MAX_FORM_BYTES == 1_024
    assert app.config["MAX_FORM_PARTS"] == MAX_FORM_PARTS == 1
    assert app.config["TRUSTED_HOSTS"] == ["localhost", "127.0.0.1"]


def test_app_factory_defaults_to_non_testing_mode() -> None:
    assert create_app().testing is False


def test_index_is_plain_self_contained_and_stateless(client: FlaskClient) -> None:
    response = client.get("/")
    document = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Password Policy State-Space Lab" in document
    assert 'value="20"' in document
    assert "Generated password" not in document
    assert "Set-Cookie" not in response.headers
    assert "http://" not in document
    assert "https://" not in document
    assert "<script" not in document
    assert "<style" not in document
    assert "<link" not in document
    assert "<img" not in document


def test_valid_form_uses_the_fixed_policy_and_uniform_sampler(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sampled_spaces: list[PasswordSpace] = []

    def sample_once(space: PasswordSpace) -> str:
        sampled_spaces.append(space)
        return "aA1!aaaa"

    monkeypatch.setattr(PasswordSpace, "sample_uniform", sample_once)

    response = client.post("/", data={"length": "8"})
    document = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "aA1!aaaa" in document
    assert 'value="8"' in document
    assert len(sampled_spaces) == 1
    policy = sampled_spaces[0].policy
    assert policy.length == 8
    assert tuple(item.name for item in policy.classes) == (
        "lower",
        "upper",
        "digits",
        "punctuation",
    )
    assert policy.minima == (1, 1, 1, 1)
    assert [len(item.symbols) for item in policy.classes] == [26, 26, 10, 32]


def test_maximum_length_fixed_rank_satisfies_the_fixed_policy(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected_space = PasswordSpace(
        PasswordPolicy(
            MAX_PASSWORD_LENGTH,
            (
                CharacterClass("lower", string.ascii_lowercase, 1),
                CharacterClass("upper", string.ascii_uppercase, 1),
                CharacterClass("digits", string.digits, 1),
                CharacterClass("punctuation", string.punctuation, 1),
            ),
        )
    )
    upper_bounds: list[int] = []

    def fixed_rank(upper_bound: int) -> int:
        upper_bounds.append(upper_bound)
        return upper_bound - 1

    monkeypatch.setattr(
        "password_policy_lab.space.secrets.randbelow",
        fixed_rank,
    )

    response = client.post("/", data={"length": str(MAX_PASSWORD_LENGTH)})
    match = re.search(
        r'<output id="generated-password">([^<]*)</output>',
        response.get_data(as_text=True),
    )

    assert response.status_code == 200
    assert upper_bounds == [expected_space.total]
    assert match is not None
    password = html.unescape(match.group(1))
    assert password == expected_space.unrank(expected_space.total - 1)
    assert len(password) == MAX_PASSWORD_LENGTH
    assert any(symbol in string.ascii_lowercase for symbol in password)
    assert any(symbol in string.ascii_uppercase for symbol in password)
    assert any(symbol in string.digits for symbol in password)
    assert any(symbol in string.punctuation for symbol in password)


@pytest.mark.parametrize(
    "data",
    [
        {"unexpected": "field"},
        {"length": ""},
        {"length": "7"},
        {"length": "129"},
        {"length": " 8"},
        {"length": "+8"},
        {"length": "8.0"},
        {"length": "008"},
        {"length": "8", "extra": "unexpected"},
        MultiDict((("length", "8"), ("length", "9"))),
    ],
)
def test_invalid_form_values_are_rejected_without_generation(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
    data: dict[str, str] | MultiDict[str, str],
) -> None:
    def must_not_build_policy(length: int) -> PasswordPolicy:
        raise AssertionError(f"unexpected policy construction for length {length}")

    monkeypatch.setattr(
        "password_policy_lab.web._default_policy",
        must_not_build_policy,
    )

    response = client.post("/", data=data)

    assert response.status_code == 400
    assert "Submit exactly one whole-number length from 8 through 128." in (
        response.get_data(as_text=True)
    )


def test_non_urlencoded_form_is_rejected(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_build_policy(length: int) -> PasswordPolicy:
        raise AssertionError(f"unexpected policy construction for length {length}")

    monkeypatch.setattr(
        "password_policy_lab.web._default_policy",
        must_not_build_policy,
    )

    response = client.post(
        "/", data={"length": "8"}, content_type="multipart/form-data"
    )

    assert response.status_code == 415
    assert "Submit the form as application/x-www-form-urlencoded." in (
        response.get_data(as_text=True)
    )


def test_oversized_body_is_rejected_before_generation(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def must_not_build_policy(length: int) -> PasswordPolicy:
        raise AssertionError(f"unexpected policy construction for length {length}")

    monkeypatch.setattr(
        "password_policy_lab.web._default_policy",
        must_not_build_policy,
    )
    body = "length=8&padding=" + ("x" * MAX_REQUEST_BYTES)

    response = client.post(
        "/",
        data=body,
        content_type="application/x-www-form-urlencoded",
    )

    assert response.status_code == 413
    assert "The submitted form is too large." in response.get_data(as_text=True)


@pytest.mark.parametrize(
    "host",
    ["localhost", "localhost:5000", "127.0.0.1", "127.0.0.1:5000"],
)
def test_loopback_hosts_are_accepted(client: FlaskClient, host: str) -> None:
    assert client.get("/", headers={"Host": host}).status_code == 200


def test_untrusted_host_is_rejected_without_echoing_it(client: FlaskClient) -> None:
    host = "untrusted.example"

    response = client.get("/", headers={"Host": host})

    assert response.status_code == 400
    assert host not in response.get_data(as_text=True)
    assert "The request could not be accepted." in response.get_data(as_text=True)


def test_generated_password_is_escaped_and_never_logged(
    client: FlaskClient,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    generated = "<script>"

    def sample_once(space: PasswordSpace) -> str:
        assert space.policy.length == len(generated)
        return generated

    monkeypatch.setattr(PasswordSpace, "sample_uniform", sample_once)
    caplog.set_level(logging.DEBUG)

    response = client.post("/", data={"length": str(len(generated))})
    document = response.get_data(as_text=True)
    header_text = "\n".join(
        f"{name}: {value}" for name, value in response.headers.items()
    )
    following_document = client.get("/").get_data(as_text=True)

    assert response.status_code == 200
    assert generated not in document
    assert "&lt;script&gt;" in document
    assert generated not in header_text
    assert generated not in following_document
    assert all(generated not in record.getMessage() for record in caplog.records)
    assert "Set-Cookie" not in response.headers
    assert "Location" not in response.headers


@pytest.mark.parametrize(
    "response_factory",
    [
        lambda client: client.get("/"),
        lambda client: client.post("/", data={"length": "invalid"}),
        lambda client: client.post("/", json={"length": "8"}),
        lambda client: client.post(
            "/",
            data="length=8&padding=" + ("x" * MAX_REQUEST_BYTES),
            content_type="application/x-www-form-urlencoded",
        ),
        lambda client: client.get("/", headers={"Host": "untrusted.example"}),
        lambda client: client.get("/missing"),
        lambda client: client.put("/"),
    ],
)
def test_security_headers_cover_success_and_error_responses(
    client: FlaskClient,
    response_factory: object,
) -> None:
    assert callable(response_factory)
    response = response_factory(client)

    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Content-Security-Policy"] == (
        "default-src 'none'; base-uri 'none'; form-action 'self'; "
        "frame-ancestors 'none'; connect-src 'none'; font-src 'none'; "
        "frame-src 'none'; img-src 'none'; manifest-src 'none'; "
        "media-src 'none'; object-src 'none'; script-src 'none'; "
        "style-src 'none'; worker-src 'none'"
    )
    assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"


def test_method_not_allowed_advertises_only_the_defined_route_methods(
    client: FlaskClient,
) -> None:
    response = client.put("/")

    assert response.status_code == 405
    assert set(response.headers["Allow"].replace(" ", "").split(",")) == {
        "GET",
        "HEAD",
        "OPTIONS",
        "POST",
    }


def test_unexpected_error_is_generic_and_still_gets_security_headers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "internal-test-marker"

    def fail_after_validation(space: PasswordSpace) -> str:
        raise RuntimeError(f"{marker}:{space.policy.length}")

    monkeypatch.setattr(PasswordSpace, "sample_uniform", fail_after_validation)
    application = create_app(
        {
            "PROPAGATE_EXCEPTIONS": False,
            "TESTING": False,
        }
    )

    with application.test_client() as error_client:
        response = error_client.post("/", data={"length": "8"})

    assert response.status_code == 500
    assert marker not in response.get_data(as_text=True)
    assert response.headers["Cache-Control"] == "no-store, max-age=0"
    assert response.headers["Pragma"] == "no-cache"
    assert response.headers["Content-Security-Policy"].startswith("default-src 'none'")
    assert response.headers["Cross-Origin-Embedder-Policy"] == "require-corp"
    assert response.headers["Cross-Origin-Opener-Policy"] == "same-origin"
    assert response.headers["Cross-Origin-Resource-Policy"] == "same-origin"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["X-Frame-Options"] == "DENY"
