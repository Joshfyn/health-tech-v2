"""One error shape with fixed codes, no library text out, DTO responses, and logging."""

import logging
import re
import uuid

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from health_tech import logger as clog
from health_tech.auth.model import Auth
from health_tech.auth.router import new_auth_router
from health_tech.auth.service import AuthService
from health_tech.lib import errors
from health_tech.lib.db import Base
from health_tech.lib.errors import CATALOG, FIELD_RULES, ErrorCode
from health_tech.lib.validation import ResponseModel
from health_tech.user.model import User, UserRole
from health_tech.user.router import new_user_router
from health_tech.user.service import UserService
from tests.conftest import auth_header
from tests.test_user import NEW_PATIENT, insert_user, insert_users

SNAKE_CASE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*")
USERS = "/health-tech/user"
SIGN_IN = "/health-tech/auth/signin"


# --- The catalog ---


def test_every_code_is_snake_case():
    for code in ErrorCode:
        assert SNAKE_CASE.fullmatch(code.value), code


def test_every_code_has_exactly_one_error():
    assert set(CATALOG) == set(ErrorCode)


def test_every_error_is_a_client_or_server_error():
    for error in CATALOG.values():
        assert 400 <= error.status <= 599, error


def test_field_rules_name_their_field():
    for error in FIELD_RULES.values():
        assert error.for_field("firstName").message.startswith("firstName ")
    for error in set(CATALOG.values()) - set(FIELD_RULES.values()):
        assert "{" not in error.message, error


def test_codes_and_messages_that_clients_rely_on_do_not_change():
    # The wire contract, written out: a failing line here is a breaking API change.
    assert {c: (e.status, e.message) for c, e in CATALOG.items() if c in PINNED} == PINNED


PINNED = {
    "unauthorized": (401, "Unauthorized"),
    "forbidden": (403, "Forbidden"),
    "invalid_credentials": (401, "invalid credentials"),
    "user_not_authorized": (401, "user not authorized"),
    "invalid_request_body": (400, "invalid request body"),
    "internal_error": (500, "internal server error"),
    "email_required": (400, "email is required"),
    "password_required": (400, "password is required"),
    "role_required": (400, "role is required"),
    "invalid_role": (400, "unknown role"),
    "organisation_id_required": (400, "organisation id is required"),
    "invalid_organisation_id": (400, "invalid organisation id"),
    "organisation_id_not_allowed": (400, "organisation id is not allowed for this role"),
    "user_not_found": (404, "user not found"),
    "account_exists": (409, "an account with this email and role already exists"),
    "provider_not_found": (404, "provider account not found"),
    "already_in_organisation": (409, "provider already works for this organisation"),
    "unsafe_input": (400, "{field} contains characters or content that are not allowed"),
}


# --- Every error leaves in the one shape ---


@pytest.fixture
def lenient_user_client(db, mailer):
    """A user service client that answers unexpected exceptions as production does."""
    svc = UserService(db=db, mailer=mailer)
    with TestClient(new_user_router(svc), raise_server_exceptions=False) as client:
        yield client


@pytest.fixture
def lenient_auth_client(db):
    svc = AuthService(db=db)
    with TestClient(new_auth_router(svc), raise_server_exceptions=False) as client:
        yield client


def test_unknown_path_is_not_found(user_client, auth_client):
    for client in (user_client, auth_client):
        resp = client.get("/no/such/path")

        assert resp.status_code == 404
        assert resp.json() == {"code": "not_found", "error": "not found"}


def test_wrong_method_is_method_not_allowed(user_client):
    resp = user_client.delete(USERS)

    assert resp.status_code == 405
    assert resp.json() == {"code": "method_not_allowed", "error": "method not allowed"}
    assert "allow" in resp.headers  # Starlette's header is passed on


SECRET_DETAIL = "password=hunter2 host=db.internal"


def explode(*args, **kwargs):
    raise RuntimeError(SECRET_DETAIL)


def test_unexpected_exception_is_a_plain_internal_error(lenient_user_client, monkeypatch):
    monkeypatch.setattr(User, "get_users_page", explode)

    resp = lenient_user_client.get(USERS, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 500
    assert resp.json() == {"code": "internal_error", "error": "internal server error"}
    assert SECRET_DETAIL not in resp.text
    assert "RuntimeError" not in resp.text


def test_unexpected_exception_at_sign_in_is_a_plain_internal_error(
    lenient_auth_client, monkeypatch
):
    monkeypatch.setattr(Auth, "get_user_by_email_and_role", explode)

    resp = lenient_auth_client.post(
        SIGN_IN, json={"email": "a@example.com", "password": "x", "role": "patient"}
    )

    assert resp.status_code == 500
    assert resp.json() == errors.INTERNAL_ERROR.body()
    assert SECRET_DETAIL not in resp.text


@pytest.mark.parametrize(
    "token",
    ["abc", "a.b.c", "eyJhbGciOiJIUzI1NiJ9.e30.x"],
)
def test_confirmation_token_errors_do_not_show_the_library_message(user_client, token):
    resp = user_client.get(f"{USERS}/confirm", params={"token": token})

    assert resp.status_code == 400
    assert resp.json() == {
        "code": "invalid_confirmation_token",
        "error": "invalid confirmation token",
    }
    for library_text in ("segments", "Signature", "decode", "token validation failed", "JWT"):
        assert library_text not in resp.text


def test_database_error_looking_up_a_provider_user_is_internal(user_client, db, monkeypatch):
    # Was 400 "user must have a basic account first": an outage is not the caller's fault.
    def fail(*args, **kwargs):
        raise OperationalError("SELECT", {}, Exception("database is unavailable"))

    monkeypatch.setattr(User, "get_single_user", fail)
    body = {
        "email": "user2@example.com",
        "role": "doctor",
        "password": "placeholder-password",
        "userId": str(insert_user(db)),
        "organisationId": "7d4c2e1a-3b5f-4a6e-9d8c-1f2e3a4b5c6d",
    }

    resp = user_client.post(
        f"{USERS}/healthcare-providers", json=body, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    assert resp.json() == errors.INTERNAL_ERROR.body()
    assert "database" not in resp.text


ERROR_REQUESTS = [
    ("user", "get", USERS, {}, None),
    ("user", "get", USERS, auth_header(UserRole.PATIENT), None),
    ("user", "get", USERS, auth_header(UserRole.SUPER_ADMIN) | {"x": "1"}, {"page": "0"}),
    ("user", "get", f"{USERS}/{uuid.uuid4()}", auth_header(UserRole.SUPER_ADMIN), None),
    ("user", "get", f"{USERS}/confirm", {}, None),
    ("user", "post", USERS, auth_header(UserRole.SUPER_ADMIN), {"email": "bad"}),
    ("user", "post", USERS, auth_header(UserRole.SUPER_ADMIN), {"x": "<b>"}),
    ("user", "post", f"{USERS}/healthcare-providers", auth_header(UserRole.DOCTOR), {}),
    ("auth", "post", SIGN_IN, {}, {"email": "a@example.com"}),
    ("auth", "post", SIGN_IN, {}, {"email": "a@example.com", "password": "x", "role": "x"}),
    ("auth", "get", "/health-tech/auth/validate", {"X-USER-TOKEN": "x"}, None),
    ("auth", "post", "/health-tech/auth/refresh", {}, None),
]


@pytest.mark.parametrize(("service", "method", "path", "headers", "data"), ERROR_REQUESTS)
def test_every_error_has_exactly_a_code_and_a_message(
    user_client, auth_client, service, method, path, headers, data
):
    client = user_client if service == "user" else auth_client
    if method == "get":
        resp = client.get(path, headers=headers, params=data)
    else:
        resp = client.post(path, headers=headers, json=data)

    assert resp.status_code >= 400
    body = resp.json()
    assert body.keys() == {"code", "error"}
    assert body["code"] in set(ErrorCode)
    assert CATALOG[ErrorCode(body["code"])].status == resp.status_code


# --- Responses are DTOs, never database models ---


def all_routes():
    user_app = new_user_router(UserService(db=None, mailer=None))
    auth_app = new_auth_router(AuthService(db=None))
    return [r for app in (user_app, auth_app) for r in app.routes if isinstance(r, APIRoute)]


@pytest.mark.parametrize("route", all_routes(), ids=lambda r: f"{r.methods} {r.path}")
def test_every_route_answers_with_a_response_dto(route):
    model = route.response_model
    assert isinstance(model, type)
    assert issubclass(model, ResponseModel)
    assert not issubclass(model, Base)


def test_openapi_documents_the_error_shape(user_client):
    schema = user_client.get("/openapi.json").json()

    operation = schema["paths"]["/health-tech/user"]["post"]
    assert operation["responses"]["400"]["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/ErrorResponse"
    }


RECORD_KEYS = {
    "id",
    "email",
    "firstName",
    "lastName",
    "dateOfBirth",
    "contact",
    "createdAt",
    "updatedAt",
}


def test_a_record_shows_exactly_the_dto_fields(user_client, db):
    user_id = uuid.uuid4()
    with db.begin() as session:
        session.add(
            User(
                id=user_id,
                email="a@example.com",
                national_id="AB-12",
                # Stored before requests were validated: extra keys must not be shown.
                contact={"phone": "1", "internalNote": "vip", "address": {"geo": "x"}},
            )
        )

    resp = user_client.get(f"{USERS}/{user_id}", headers=auth_header(UserRole.SUPER_ADMIN))

    body = resp.json()
    assert body.keys() == RECORD_KEYS | {"nationalID"}
    assert body["contact"] == {
        "phone": "1",
        "address": {"street": "", "city": "", "state": "", "zipCode": "", "country": ""},
    }
    assert "internalNote" not in resp.text
    assert "geo" not in resp.text


def test_a_stored_contact_of_the_wrong_shape_does_not_fail_the_read(user_client, db):
    user_id = uuid.uuid4()
    with db.begin() as session:
        session.add(User(id=user_id, email="a@example.com", contact={"phone": ["not", "a", "str"]}))

    resp = user_client.get(f"{USERS}/{user_id}", headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 200
    assert resp.json()["contact"]["phone"] == ""


def test_a_listing_shows_exactly_the_summary_fields(user_client, db):
    insert_users(db, 2)

    resp = user_client.get(USERS, headers=auth_header(UserRole.SUPER_ADMIN))

    assert [user.keys() for user in resp.json()["users"]] == [RECORD_KEYS, RECORD_KEYS]


# --- Logging ---


@pytest.fixture
def log_lines():
    """Lines both services log, formatted as in production."""
    lines: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record):
            lines.append(self.format(record))

    handler = Collect()
    handler.setFormatter(clog._TextFormatter())
    logger = logging.getLogger(clog.LOGGER_NAME)
    logger.addHandler(handler)
    yield lines
    logger.removeHandler(handler)


def test_each_error_response_is_logged_with_its_status_and_code(user_client, log_lines):
    user_client.get(USERS, params={"page": "0"}, headers=auth_header(UserRole.SUPER_ADMIN))

    assert any(
        "Request failed: status=400 code=invalid_page" in line
        and "resource=GET /health-tech/user" in line
        for line in log_lines
    )


def test_one_requests_fields_do_not_leak_onto_later_log_lines(auth_client, log_lines):
    # The auth service adds the email to its failed sign-in line; it used to stay on the shared
    # logger and appear on every later line, whoever's request it was.
    auth_client.post(
        SIGN_IN, json={"email": "first@example.com", "password": "x", "role": "patient"}
    )
    log_lines.clear()

    auth_client.get("/health-tech/auth/validate", headers={"X-USER-TOKEN": "x"})

    assert log_lines
    assert not any("first@example.com" in line for line in log_lines)


def test_with_field_returns_a_new_logger():
    clog.log.with_field("email", "a@example.com").with_fields({"role": "patient"})

    assert clog.log._fields == {}


def test_client_text_cannot_forge_log_lines(user_client, log_lines):
    # A patient's token, and a path that tries to start a second log line.
    user_client.get(f"{USERS}/x%0Alevel=error%20msg=forged", headers=auth_header(UserRole.PATIENT))

    assert log_lines
    assert all("\n" not in line for line in log_lines)


def test_unexpected_exceptions_are_logged_with_an_indented_traceback(
    lenient_user_client, monkeypatch, log_lines
):
    monkeypatch.setattr(User, "get_users_page", explode)

    lenient_user_client.get(USERS, headers=auth_header(UserRole.SUPER_ADMIN))

    (line,) = [line for line in log_lines if "Unhandled RuntimeError" in line]
    first, *traceback = line.split("\n")
    assert first.startswith("time=")
    assert traceback
    assert all(t.startswith(clog.TRACEBACK_PREFIX) for t in traceback)


def test_passwords_are_never_logged(user_client, auth_client, log_lines):
    password = "never-log-this-password"
    user_client.post(
        USERS,
        json={**NEW_PATIENT, "password": password, "email": "bad"},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )
    auth_client.post(SIGN_IN, json={"email": "a@example.com", "password": password, "role": "x"})
    auth_client.post(
        SIGN_IN, json={"email": "a@example.com", "password": password, "role": "patient"}
    )

    assert log_lines
    assert not any(password in line for line in log_lines)
