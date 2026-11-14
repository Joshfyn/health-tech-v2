import uuid

import pytest

from health_tech.lib.password import generate_from_password
from health_tech.lib.tokenmaker import validate_verification_token
from health_tech.user.model import RoleAccount, UserRole
from tests.conftest import auth_header

EMAIL = "user1@example.com"
PASSWORD = "placeholder-password"


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


def test_sign_in_returns_token_for_role_account(auth_client, role_account_id):
    resp = auth_client.post("/health-tech/auth/signin", json={"email": EMAIL, "password": PASSWORD})

    assert resp.status_code == 200
    claims = validate_verification_token(resp.json()["token"])
    assert claims.user_id == str(role_account_id)
    assert claims.role == UserRole.PATIENT


def test_sign_in_rejects_wrong_password(auth_client, role_account_id):
    resp = auth_client.post("/health-tech/auth/signin", json={"email": EMAIL, "password": "wrong"})

    assert resp.status_code == 401
    assert resp.json() == {"error": "invalid credentials"}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param({"password": PASSWORD}, {"error": "email is required"}, id="no email"),
        pytest.param({"email": EMAIL}, {"error": "password is required"}, id="no password"),
        pytest.param(None, {"error": "invalid request body"}, id="no body"),
    ],
)
def test_sign_in_rejects_invalid_body(auth_client, body, expected):
    resp = auth_client.post("/health-tech/auth/signin", json=body)

    assert resp.status_code == 400
    assert resp.json() == expected


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        pytest.param({}, 401, id="no token"),
        pytest.param({"X-USER-TOKEN": "not-a-jwt"}, 401, id="invalid token"),
        pytest.param(auth_header(UserRole.DOCTOR, "role-account-1"), 200, id="valid token"),
    ],
)
def test_validate_token(auth_client, headers, expected_status):
    resp = auth_client.get("/health-tech/auth/validate", headers=headers)

    assert resp.status_code == expected_status
    if expected_status == 200:
        assert resp.json() == {
            "email": "admin@example.com",
            "role": "doctor",
            "user_id": "role-account-1",
        }


def test_refresh_token_returns_new_valid_token(auth_client):
    resp = auth_client.post(
        "/health-tech/auth/refresh", headers=auth_header(UserRole.DOCTOR, "role-account-1")
    )

    assert resp.status_code == 200
    assert validate_verification_token(resp.json()["token"]).user_id == "role-account-1"


def test_refresh_token_requires_token(auth_client):
    resp = auth_client.post("/health-tech/auth/refresh")

    assert resp.status_code == 401
