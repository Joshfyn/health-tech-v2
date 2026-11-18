"""Each endpoint admits only its roles; everyone else gets 401 before the body is read."""

import uuid
from typing import Annotated

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import select

from health_tech.lib import errors
from health_tech.lib.access import PUBLIC, AccessPolicyError, caller_claims, roles
from health_tech.lib.http import new_app
from health_tech.lib.payload_guard import MAX_BODY_BYTES
from health_tech.lib.tokenmaker import TokenClaims, TokenPurpose
from health_tech.user import middleware as user_middleware
from health_tech.user.model import RoleAccount, User, UserRole
from tests.conftest import ORGANISATION_ID, auth_header, make_token
from tests.test_user import NEW_PATIENT, insert_user

USERS = "/health-tech/user"
PROVIDERS = f"{USERS}/healthcare-providers"
ADD_ORGANISATION = f"{PROVIDERS}/organisations"
RECORD = f"{USERS}/{{user_id}}"
UNAUTHORIZED = {"code": "unauthorized", "error": "Unauthorized"}
ROLE_NOT_ALLOWED = {
    "code": "role_not_allowed",
    "error": "this role is not allowed to use this endpoint",
}

SUPER = UserRole.SUPER_ADMIN
PATIENT = UserRole.PATIENT
DOCTOR = UserRole.DOCTOR
PHARMACIST = UserRole.PHARMACIST
HOSPITAL_ADMIN = UserRole.HOSPITAL_ADMIN
PHARMACY_ADMIN = UserRole.PHARMACY_ADMIN

# Written out, not read from user/router.py: a wrong entry there must fail here.
ALLOWED = {
    ("POST", USERS): {SUPER},
    ("GET", USERS): {SUPER},
    ("GET", RECORD): {SUPER, PATIENT},
    ("POST", PROVIDERS): {SUPER, HOSPITAL_ADMIN, PHARMACY_ADMIN},
    ("POST", ADD_ORGANISATION): {SUPER, HOSPITAL_ADMIN, PHARMACY_ADMIN},
}


def call(client, method: str, path: str, headers: dict, **kwargs):
    path = path.replace("{user_id}", str(uuid.uuid4()))
    return client.request(method, path, headers=headers, **kwargs)


@pytest.mark.parametrize(
    ("method", "path", "role"),
    [
        pytest.param(method, path, role, id=f"{method} {path} as {role}")
        for (method, path), allowed in ALLOWED.items()
        for role in UserRole
        if role not in allowed
    ],
)
def test_roles_an_endpoint_does_not_allow_get_401(user_client, method, path, role):
    resp = call(user_client, method, path, auth_header(role, str(uuid.uuid4())), json={})

    assert resp.status_code == 401
    assert resp.json() == ROLE_NOT_ALLOWED


@pytest.mark.parametrize(
    ("method", "path", "role"),
    [
        pytest.param(method, path, role, id=f"{method} {path} as {role}")
        for (method, path), allowed in ALLOWED.items()
        for role in allowed
    ],
)
def test_roles_an_endpoint_allows_get_past_access_control(user_client, method, path, role):
    # What they get next depends on the request (400 for this empty body, 403, 404, ...).
    resp = call(user_client, method, path, auth_header(role, str(uuid.uuid4())), json={})

    assert resp.status_code != 401


@pytest.mark.parametrize(("method", "path"), list(ALLOWED))
@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no token"),
        pytest.param({"X-USER-TOKEN": "not-a-jwt"}, id="not a token"),
        pytest.param(
            {"X-USER-TOKEN": make_token(SUPER, purpose=TokenPurpose.REFRESH)}, id="refresh"
        ),
        pytest.param(
            {"X-USER-TOKEN": make_token(SUPER, purpose=TokenPurpose.EMAIL_CONFIRMATION)},
            id="confirmation link token",
        ),
        pytest.param({"X-REFRESH-TOKEN": make_token(SUPER)}, id="access token in another header"),
    ],
)
def test_callers_without_a_valid_access_token_get_401(user_client, method, path, headers):
    resp = call(user_client, method, path, headers, json={})

    assert resp.status_code == 401
    assert resp.json() == UNAUTHORIZED


def test_a_get_is_checked_against_the_get_rule_not_an_earlier_post(user_client):
    # POST /health-tech/user is registered first and matches the path; GET must not stop there.
    resp = user_client.get(USERS, headers=auth_header(DOCTOR))

    assert resp.status_code == 401
    assert resp.json() == ROLE_NOT_ALLOWED


# --- Early: a refused caller's request goes no further ---


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b'{"user": "<html>example_name</>"}', id="unsafe"),
        pytest.param(b"{not json", id="not json"),
        pytest.param(b'{"a": "' + b"x" * (MAX_BODY_BYTES + 1) + b'"}', id="too large"),
    ],
)
@pytest.mark.parametrize(
    "headers", [{}, auth_header(DOCTOR), auth_header(PHARMACIST), auth_header(HOSPITAL_ADMIN)]
)
def test_refused_callers_get_401_whatever_their_body(user_client, content, headers):
    resp = user_client.post(
        USERS, content=content, headers={**headers, "Content-Type": "application/json"}
    )

    assert resp.status_code == 401


@pytest.mark.parametrize("role", [DOCTOR, PHARMACIST, HOSPITAL_ADMIN, PHARMACY_ADMIN, PATIENT])
def test_refused_callers_reach_no_handler_and_change_nothing(
    user_client, db, mailer, monkeypatch, role
):
    hashed = []
    monkeypatch.setattr(user_middleware, "generate_from_password", hashed.append)

    resp = user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(role))

    assert resp.status_code == 401
    assert hashed == []  # not even the body's password was hashed
    assert mailer.sent == []
    with db() as session:
        assert session.scalars(select(User)).all() == []


# --- POST /health-tech/user creates patient and super admin logins only ---


@pytest.mark.parametrize("role", [DOCTOR, PHARMACIST, HOSPITAL_ADMIN, PHARMACY_ADMIN])
def test_post_user_refuses_to_create_provider_and_admin_roles(user_client, db, mailer, role):
    resp = user_client.post(USERS, json={**NEW_PATIENT, "role": role}, headers=auth_header(SUPER))

    assert resp.status_code == 400
    assert resp.json() == errors.ACCOUNT_ROLE_NOT_ALLOWED.body()
    assert mailer.sent == []
    with db() as session:
        assert session.scalars(select(User)).all() == []
        assert session.scalars(select(RoleAccount)).all() == []


@pytest.mark.parametrize("role", [PATIENT, SUPER])
def test_post_user_creates_patient_and_super_admin_logins(user_client, db, role):
    resp = user_client.post(USERS, json={**NEW_PATIENT, "role": role}, headers=auth_header(SUPER))

    assert resp.status_code == 200
    with db() as session:
        assert session.scalars(select(RoleAccount.role)).all() == [role]


def test_doctors_are_created_through_the_providers_endpoint(user_client, db):
    # The person first, with no login, then their doctor login.
    person = user_client.post(USERS, json={**NEW_PATIENT, "role": ""}, headers=auth_header(SUPER))
    with db() as session:
        (user_id,) = session.scalars(select(User.id)).all()
    doctor = user_client.post(
        PROVIDERS,
        json={
            "email": NEW_PATIENT["email"],
            "role": DOCTOR,
            "password": "placeholder-password",
            "userId": str(user_id),
            "organisationId": ORGANISATION_ID,
        },
        headers=auth_header(SUPER),
    )

    assert (person.status_code, doctor.status_code) == (200, 200)
    with db() as session:
        assert session.scalars(select(RoleAccount.role)).all() == [DOCTOR]


# --- Finer rules stay with the endpoint and answer 403 ---


def test_patient_may_use_the_record_endpoint_but_not_for_anothers_record(user_client, db):
    own, other = insert_user(db, "a@example.com"), insert_user(db, "b@example.com")
    headers = auth_header(PATIENT, str(own))

    assert user_client.get(f"{USERS}/{own}", headers=headers).status_code == 200
    resp = user_client.get(f"{USERS}/{other}", headers=headers)
    assert resp.status_code == 403
    assert resp.json() == errors.FORBIDDEN.body()


def test_hospital_admin_may_use_the_providers_endpoint_but_not_for_pharmacists(user_client, db):
    body = {
        "email": "user2@example.com",
        "role": PHARMACIST,
        "password": "placeholder-password",
        "userId": str(insert_user(db)),
    }

    resp = user_client.post(PROVIDERS, json=body, headers=auth_header(HOSPITAL_ADMIN))

    assert resp.status_code == 403
    assert resp.json() == errors.FORBIDDEN.body()


# --- Other routes ---


def test_the_confirmation_link_needs_no_access_token(user_client):
    resp = user_client.get(f"{USERS}/confirm", params={"token": "x"})

    assert resp.json()["code"] == "invalid_confirmation_token"  # the endpoint's own check


def test_unknown_paths_and_methods_are_not_hidden_behind_401(user_client):
    assert user_client.get("/no/such/path").status_code == 404
    assert user_client.delete(USERS).status_code == 405


def test_openapi_documents_the_access_token(user_client):
    schema = user_client.get("/openapi.json").json()

    assert schema["components"]["securitySchemes"]["APIKeyHeader"]["name"] == "X-USER-TOKEN"
    assert schema["paths"][USERS]["post"]["security"] == [{"APIKeyHeader": []}]


# --- The access table itself ---


def test_app_refuses_to_start_with_a_route_that_has_no_access_rule():
    app = new_app("test", "test", access={("GET", "/a"): PUBLIC})
    app.add_api_route("/a", lambda: {}, methods=["GET"])
    app.add_api_route("/b", lambda: {}, methods=["GET"])

    with pytest.raises(AccessPolicyError, match="/b"), TestClient(app):
        pass


def test_app_refuses_to_start_with_a_rule_for_no_route():
    app = new_app("test", "test", access={("GET", "/a"): PUBLIC, ("GET", "/gone"): PUBLIC})
    app.add_api_route("/a", lambda: {}, methods=["GET"])

    with pytest.raises(AccessPolicyError, match="/gone"), TestClient(app):
        pass


def test_endpoint_wrongly_marked_public_fails_closed():
    # It asks for the caller, but the table let everyone in: it must not run unauthenticated.
    def endpoint(claims: Annotated[TokenClaims, Depends(caller_claims)]) -> dict:
        return {"ran": True}

    app = new_app("test", "test", access={("GET", "/a"): PUBLIC})
    app.add_api_route("/a", endpoint, methods=["GET"])

    with TestClient(app) as client:
        resp = client.get("/a", headers=auth_header(SUPER))

    assert resp.status_code == 401
    assert resp.json() == UNAUTHORIZED


def test_an_endpoint_needs_at_least_one_role():
    with pytest.raises(ValueError):
        roles()
