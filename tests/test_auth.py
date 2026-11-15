import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.exc import OperationalError

from health_tech import logger as clog
from health_tech.auth import messages
from health_tech.auth.model import Auth
from health_tech.auth.router import new_auth_router
from health_tech.auth.service import AuthService
from health_tech.lib.ids import NIL_UUID
from health_tech.lib.password import generate_from_password
from health_tech.lib.tokenmaker import TokenError, TokenPurpose, validate_token
from health_tech.user.model import RoleAccount, UserRole
from tests.conftest import auth_header, make_token, refresh_header
from tests.test_user import NEW_PATIENT

EMAIL = "user1@example.com"
PASSWORD = "placeholder-password"
SIGN_IN = "/health-tech/auth/signin"
INVALID_CREDENTIALS = {"error": messages.INVALID_CREDENTIALS}
UNAUTHORIZED = {"error": messages.UNAUTHORIZED}
USER_NOT_AUTHORIZED = {"error": messages.USER_NOT_AUTHORIZED}


@pytest.fixture
def role_account_id(db) -> uuid.UUID:
    """A confirmed patient account that can sign in."""
    account_id = uuid.uuid4()
    with db.begin() as session:
        session.add(
            RoleAccount(
                role_account_id=account_id,
                user_id=uuid.uuid4(),
                email=EMAIL,
                role=UserRole.PATIENT,
                password_hash=generate_from_password(PASSWORD),
                is_confirmed=True,
                is_active=True,
            )
        )
    return account_id


def test_sign_in_returns_access_and_refresh_tokens(auth_client, role_account_id):
    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD})

    assert resp.status_code == 200
    body = resp.json()
    assert body.keys() == {"message", "token", "refresh_token"}
    assert body["message"] == messages.SIGN_IN_SUCCESS
    for token, purpose in [
        (body["token"], TokenPurpose.ACCESS),
        (body["refresh_token"], TokenPurpose.REFRESH),
    ]:
        claims = validate_token(token, purpose)
        assert claims.user_id == str(role_account_id)
        assert claims.role == UserRole.PATIENT
        assert claims.email == EMAIL


def test_registered_patients_sign_in_with_their_own_account_id(
    user_client, auth_client, db, mailer
):
    emails = ["user1@example.com", "user3@example.com"]
    for email in emails:
        user_client.post(
            "/health-tech/user",
            json={**NEW_PATIENT, "email": email},
            headers=auth_header(UserRole.SUPER_ADMIN),
        )
    for _, link_token in mailer.sent:
        user_client.get("/health-tech/user/confirm", params={"token": link_token})

    token_ids = []
    for email in emails:
        resp = auth_client.post(SIGN_IN, json={"email": email, "password": NEW_PATIENT["password"]})
        assert resp.status_code == 200
        assert resp.json()["message"] == messages.SIGN_IN_SUCCESS
        with db() as session:
            account_id = session.scalars(
                select(RoleAccount.role_account_id).where(RoleAccount.email == email)
            ).one()
        for token, purpose in [
            (resp.json()["token"], TokenPurpose.ACCESS),
            (resp.json()["refresh_token"], TokenPurpose.REFRESH),
        ]:
            assert validate_token(token, purpose).user_id == str(account_id)
        token_ids.append(validate_token(resp.json()["token"], TokenPurpose.ACCESS).user_id)

    assert str(NIL_UUID) not in token_ids
    assert len(set(token_ids)) == len(emails)


def test_sign_in_refuses_account_without_id(legacy_db):
    with legacy_db.begin() as session:
        session.add(
            RoleAccount(
                role_account_id=NIL_UUID,
                user_id=uuid.uuid4(),
                email=EMAIL,
                role=UserRole.PATIENT,
                password_hash=generate_from_password(PASSWORD),
                is_confirmed=True,
                is_active=True,
            )
        )
    svc = AuthService(db=legacy_db, logger=clog.must_new("auth"))

    with TestClient(new_auth_router(svc)) as client:
        resp = client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD})

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}


def test_sign_in_tokens_are_not_interchangeable(auth_client, role_account_id):
    body = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD}).json()

    with pytest.raises(TokenError):
        validate_token(body["token"], TokenPurpose.REFRESH)
    with pytest.raises(TokenError):
        validate_token(body["refresh_token"], TokenPurpose.ACCESS)


def test_sign_in_rejects_wrong_password(auth_client, role_account_id):
    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": "wrong"})

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_sign_in_rejects_unknown_email(auth_client, role_account_id):
    resp = auth_client.post(SIGN_IN, json={"email": "user9@example.com", "password": PASSWORD})

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_sign_in_rejects_unconfirmed_account(auth_client, db, role_account_id):
    with db.begin() as session:
        session.execute(
            update(RoleAccount).where(RoleAccount.email == EMAIL).values(is_confirmed=False)
        )

    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD})

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_sign_in_failures_do_not_reveal_whether_email_exists(auth_client, role_account_id):
    wrong_password = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": "wrong"})
    unknown_email = auth_client.post(
        SIGN_IN, json={"email": "user9@example.com", "password": "wrong"}
    )

    assert wrong_password.status_code == unknown_email.status_code
    assert wrong_password.json() == unknown_email.json()


def test_sign_in_database_error_is_internal_server_error(auth_client, monkeypatch):
    def fail(self, session):
        raise OperationalError("SELECT", {}, Exception("database is unavailable"))

    monkeypatch.setattr(Auth, "get_user_by_email", fail)

    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD})

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param({"password": PASSWORD}, {"error": messages.EMAIL_REQUIRED}, id="no email"),
        pytest.param({"email": EMAIL}, {"error": messages.PASSWORD_REQUIRED}, id="no password"),
        pytest.param(None, {"error": messages.INVALID_REQUEST_BODY}, id="no body"),
    ],
)
def test_sign_in_rejects_invalid_body(auth_client, body, expected):
    resp = auth_client.post(SIGN_IN, json=body)

    assert resp.status_code == 400
    assert resp.json() == expected


def test_validate_token_returns_claims_of_access_token(auth_client):
    resp = auth_client.get(
        "/health-tech/auth/validate", headers=auth_header(UserRole.DOCTOR, "role-account-1")
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "email": "admin@example.com",
        "role": "doctor",
        "user_id": "role-account-1",
    }


@pytest.mark.parametrize(
    ("headers", "expected"),
    [
        pytest.param({}, UNAUTHORIZED, id="no token"),
        pytest.param({"X-USER-TOKEN": "not-a-jwt"}, USER_NOT_AUTHORIZED, id="invalid token"),
        pytest.param(
            {"X-USER-TOKEN": make_token(UserRole.DOCTOR, "role-account-1", TokenPurpose.REFRESH)},
            USER_NOT_AUTHORIZED,
            id="refresh token",
        ),
        pytest.param(
            {
                "X-USER-TOKEN": make_token(
                    UserRole.DOCTOR, "role-account-1", TokenPurpose.EMAIL_CONFIRMATION
                )
            },
            USER_NOT_AUTHORIZED,
            id="email confirmation token",
        ),
    ],
)
def test_validate_token_rejects_missing_or_non_access_tokens(auth_client, headers, expected):
    resp = auth_client.get("/health-tech/auth/validate", headers=headers)

    assert resp.status_code == 401
    assert resp.json() == expected


def test_refresh_token_returns_new_access_token(auth_client):
    resp = auth_client.post(
        "/health-tech/auth/refresh", headers=refresh_header(UserRole.DOCTOR, "role-account-1")
    )

    assert resp.status_code == 200
    assert resp.json().keys() == {"token"}
    token = resp.json()["token"]
    claims = validate_token(token, TokenPurpose.ACCESS)
    assert (claims.user_id, claims.role) == ("role-account-1", UserRole.DOCTOR)
    with pytest.raises(TokenError):
        validate_token(token, TokenPurpose.REFRESH)


def test_refresh_token_from_sign_in_works(auth_client, role_account_id):
    signed_in = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD}).json()

    refreshed = auth_client.post(
        "/health-tech/auth/refresh", headers={"X-REFRESH-TOKEN": signed_in["refresh_token"]}
    )
    assert refreshed.status_code == 200
    validated = auth_client.get(
        "/health-tech/auth/validate", headers={"X-USER-TOKEN": refreshed.json()["token"]}
    )
    assert validated.status_code == 200
    assert validated.json()["user_id"] == str(role_account_id)


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no token"),
        pytest.param({"X-REFRESH-TOKEN": "not-a-jwt"}, id="invalid token"),
        pytest.param(
            {"X-REFRESH-TOKEN": make_token(UserRole.DOCTOR, "role-account-1")},
            id="access token",
        ),
        pytest.param(
            {
                "X-REFRESH-TOKEN": make_token(
                    UserRole.DOCTOR, "role-account-1", TokenPurpose.EMAIL_CONFIRMATION
                )
            },
            id="email confirmation token",
        ),
        pytest.param(auth_header(UserRole.DOCTOR, "role-account-1"), id="access token, old header"),
        pytest.param(
            {"X-USER-TOKEN": make_token(UserRole.DOCTOR, "role-account-1", TokenPurpose.REFRESH)},
            id="refresh token in access header",
        ),
    ],
)
def test_refresh_token_accepts_only_refresh_tokens(auth_client, headers):
    resp = auth_client.post("/health-tech/auth/refresh", headers=headers)

    assert resp.status_code == 401
    assert resp.json() == UNAUTHORIZED
