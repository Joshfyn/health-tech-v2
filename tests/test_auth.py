import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError, OperationalError

from health_tech import logger as clog
from health_tech.auth import messages
from health_tech.auth import service as auth_service
from health_tech.auth.model import Auth
from health_tech.auth.router import new_auth_router
from health_tech.auth.service import AuthService
from health_tech.lib.ids import NIL_UUID
from health_tech.lib.password import generate_from_password
from health_tech.lib.tokenmaker import TokenError, TokenPurpose, validate_token
from health_tech.user.model import (
    ORGANISATION_ROLES,
    OrganisationMembership,
    RoleAccount,
    User,
    UserRole,
)
from tests.conftest import (
    ORGANISATION_ID,
    OTHER_ORGANISATION_ID,
    auth_header,
    make_token,
    refresh_header,
)
from tests.test_user import NEW_PATIENT

EMAIL = "user1@example.com"
PASSWORD = "placeholder-password"
ROLE = UserRole.PATIENT.value
# The person the signed-in role account belongs to (users.id).
PERSON_ID = uuid.UUID("5a3f1c9e-8d2b-4e7a-9c1d-2b6e4f8a0c37")
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
                user_id=PERSON_ID,
                email=EMAIL,
                role=UserRole.PATIENT,
                password_hash=generate_from_password(PASSWORD),
                is_confirmed=True,
                is_active=True,
            )
        )
    return account_id


def test_sign_in_returns_access_and_refresh_tokens(auth_client, role_account_id):
    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE})

    assert resp.status_code == 200
    body = resp.json()
    assert body.keys() == {"message", "token", "refresh_token"}
    assert body["message"] == messages.SIGN_IN_SUCCESS
    for token, purpose in [
        (body["token"], TokenPurpose.ACCESS),
        (body["refresh_token"], TokenPurpose.REFRESH),
    ]:
        claims = validate_token(token, purpose)
        assert claims.user_id == str(PERSON_ID)
        assert claims.role_account_id == str(role_account_id)
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

    account_ids, person_ids = [], []
    for email in emails:
        resp = auth_client.post(
            SIGN_IN, json={"email": email, "password": NEW_PATIENT["password"], "role": ROLE}
        )
        assert resp.status_code == 200
        assert resp.json()["message"] == messages.SIGN_IN_SUCCESS
        with db() as session:
            account = session.scalars(select(RoleAccount).where(RoleAccount.email == email)).one()
            person = session.scalars(select(User).where(User.email == email)).one()
        assert account.user_id == person.id
        for token, purpose in [
            (resp.json()["token"], TokenPurpose.ACCESS),
            (resp.json()["refresh_token"], TokenPurpose.REFRESH),
        ]:
            claims = validate_token(token, purpose)
            assert claims.user_id == str(person.id)
            assert claims.role_account_id == str(account.role_account_id)
        access = validate_token(resp.json()["token"], TokenPurpose.ACCESS)
        account_ids.append(access.role_account_id)
        person_ids.append(access.user_id)

    for ids in (account_ids, person_ids):
        assert str(NIL_UUID) not in ids
        assert len(set(ids)) == len(emails)


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
        resp = client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE})

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}


def test_sign_in_tokens_are_not_interchangeable(auth_client, role_account_id):
    body = auth_client.post(
        SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE}
    ).json()

    with pytest.raises(TokenError):
        validate_token(body["token"], TokenPurpose.REFRESH)
    with pytest.raises(TokenError):
        validate_token(body["refresh_token"], TokenPurpose.ACCESS)


def test_sign_in_rejects_wrong_password(auth_client, role_account_id):
    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": "wrong", "role": ROLE})

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_sign_in_rejects_unknown_email(auth_client, role_account_id):
    resp = auth_client.post(
        SIGN_IN, json={"email": "user9@example.com", "password": PASSWORD, "role": ROLE}
    )

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_sign_in_rejects_unconfirmed_account(auth_client, db, role_account_id):
    with db.begin() as session:
        session.execute(
            update(RoleAccount).where(RoleAccount.email == EMAIL).values(is_confirmed=False)
        )

    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE})

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_sign_in_failures_do_not_reveal_whether_email_exists(auth_client, role_account_id):
    wrong_password = auth_client.post(
        SIGN_IN, json={"email": EMAIL, "password": "wrong", "role": ROLE}
    )
    unknown_email = auth_client.post(
        SIGN_IN, json={"email": "user9@example.com", "password": "wrong", "role": ROLE}
    )

    assert wrong_password.status_code == unknown_email.status_code
    assert wrong_password.json() == unknown_email.json()


def test_sign_in_database_error_is_internal_server_error(auth_client, monkeypatch):
    def fail(self, session):
        raise OperationalError("SELECT", {}, Exception("database is unavailable"))

    monkeypatch.setattr(Auth, "get_user_by_email_and_role", fail)

    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE})

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param({"password": PASSWORD}, {"error": messages.EMAIL_REQUIRED}, id="no email"),
        pytest.param({"email": EMAIL}, {"error": messages.PASSWORD_REQUIRED}, id="no password"),
        pytest.param(None, {"error": messages.INVALID_REQUEST_BODY}, id="no body"),
        pytest.param(
            {"email": EMAIL, "password": PASSWORD, "role": None},
            {"error": messages.INVALID_REQUEST_BODY},
            id="null role",
        ),
        pytest.param(
            {"email": EMAIL, "password": PASSWORD, "role": 5},
            {"error": messages.INVALID_REQUEST_BODY},
            id="role not a string",
        ),
    ],
)
def test_sign_in_rejects_invalid_body(auth_client, body, expected):
    resp = auth_client.post(SIGN_IN, json=body)

    assert resp.status_code == 400
    assert resp.json() == expected


def test_validate_token_returns_claims_of_access_token(auth_client):
    resp = auth_client.get(
        "/health-tech/auth/validate",
        headers=auth_header(UserRole.DOCTOR, "person-1", "role-account-1"),
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "email": "admin@example.com",
        "role": "doctor",
        "user_id": "person-1",
        "role_account_id": "role-account-1",
        "organisation_id": ORGANISATION_ID,
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
        "/health-tech/auth/refresh",
        headers=refresh_header(UserRole.DOCTOR, "person-1", "role-account-1"),
    )

    assert resp.status_code == 200
    assert resp.json().keys() == {"token"}
    token = resp.json()["token"]
    claims = validate_token(token, TokenPurpose.ACCESS)
    assert (claims.user_id, claims.role_account_id, claims.role) == (
        "person-1",
        "role-account-1",
        UserRole.DOCTOR,
    )
    with pytest.raises(TokenError):
        validate_token(token, TokenPurpose.REFRESH)


def test_refresh_token_from_sign_in_works(auth_client, role_account_id):
    signed_in = auth_client.post(
        SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE}
    ).json()

    refreshed = auth_client.post(
        "/health-tech/auth/refresh", headers={"X-REFRESH-TOKEN": signed_in["refresh_token"]}
    )
    assert refreshed.status_code == 200
    validated = auth_client.get(
        "/health-tech/auth/validate", headers={"X-USER-TOKEN": refreshed.json()["token"]}
    )
    assert validated.status_code == 200
    assert validated.json()["user_id"] == str(PERSON_ID)
    assert validated.json()["role_account_id"] == str(role_account_id)


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


def test_sign_in_takes_identity_from_the_account_not_the_request(auth_client, role_account_id):
    # The token names the stored account, whatever else the body carries.
    resp = auth_client.post(
        SIGN_IN,
        json={
            "email": EMAIL,
            "password": PASSWORD,
            "role": ROLE,
            "user_id": str(uuid.uuid4()),
            "role_account_id": str(uuid.uuid4()),
            "Role": UserRole.SUPER_ADMIN,
        },
    )

    claims = validate_token(resp.json()["token"], TokenPurpose.ACCESS)
    assert (claims.email, claims.user_id, claims.role_account_id, claims.role) == (
        EMAIL,
        str(PERSON_ID),
        str(role_account_id),
        UserRole.PATIENT,
    )


def test_sign_in_refuses_account_without_user(legacy_db):
    with legacy_db.begin() as session:
        session.add(
            RoleAccount(
                user_id=NIL_UUID,
                email=EMAIL,
                role=UserRole.PATIENT,
                password_hash=generate_from_password(PASSWORD),
                is_confirmed=True,
                is_active=True,
            )
        )
    svc = AuthService(db=legacy_db, logger=clog.must_new("auth"))

    with TestClient(new_auth_router(svc)) as client:
        resp = client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE})

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}


# --- Sign in names the role: one email can hold several logins ---

ROLE_REQUIRED = {"error": messages.ROLE_REQUIRED}
INVALID_ROLE = {"error": messages.INVALID_ROLE}


@pytest.fixture
def no_lookup(monkeypatch) -> list[str]:
    """Record any account lookup or password check; the test asserts none happened."""
    calls: list[str] = []

    def lookup(self, session):
        calls.append("lookup")

    def compare(hashed, password):
        calls.append("password check")

    monkeypatch.setattr(Auth, "get_user_by_email_and_role", lookup)
    monkeypatch.setattr(auth_service, "compare_hash_and_password", compare)
    return calls


@pytest.mark.parametrize(
    "body",
    [
        pytest.param({"email": EMAIL, "password": PASSWORD}, id="no role field"),
        pytest.param({"email": EMAIL, "password": PASSWORD, "role": ""}, id="empty role"),
    ],
)
def test_sign_in_without_role_returns_early(auth_client, role_account_id, no_lookup, body):
    resp = auth_client.post(SIGN_IN, json=body)

    assert resp.status_code == 400
    assert resp.json() == ROLE_REQUIRED
    assert no_lookup == []


@pytest.mark.parametrize(
    "role",
    [
        pytest.param("p", id="abbreviation"),
        pytest.param("Patient", id="other case"),
        pytest.param("PATIENT", id="upper case"),
        pytest.param(" patient", id="leading space"),
        pytest.param("patient ", id="trailing space"),
        pytest.param("admin", id="not a role"),
        pytest.param("patient,doctor", id="two roles"),
        pytest.param("PATIENT_ROLE", id="enum-like name"),
    ],
)
def test_sign_in_with_unknown_role_returns_early(auth_client, role_account_id, no_lookup, role):
    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": role})

    assert resp.status_code == 400
    assert resp.json() == INVALID_ROLE
    assert no_lookup == []


def test_unknown_role_answer_does_not_list_the_roles(auth_client, role_account_id):
    resp = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": "p"})

    assert resp.json() == {"error": "unknown role"}
    for role in UserRole:
        assert role.value not in resp.text


def organisation_params(role: str) -> dict[str, str]:
    """The query string sign in needs for role."""
    return {"organisationId": ORGANISATION_ID} if role in ORGANISATION_ROLES else {}


@pytest.mark.parametrize("role", list(UserRole))
def test_sign_in_accepts_every_role_the_user_service_creates(auth_client, role_account_id, role):
    # Roles the email does not hold get past validation and fail like any wrong credential.
    resp = auth_client.post(
        SIGN_IN,
        params=organisation_params(role),
        json={"email": EMAIL, "password": PASSWORD, "role": role},
    )

    if role == UserRole.PATIENT:
        assert resp.status_code == 200
    else:
        assert resp.status_code == 401
        assert resp.json() == INVALID_CREDENTIALS


def add_account(
    db, role: str, password: str, *, confirmed: bool = True, email: str = EMAIL
) -> uuid.UUID:
    """Give PERSON_ID a login with email in role; db must allow it (see legacy_db).

    Organisation roles work for ORGANISATION_ID.
    """
    account_id = uuid.uuid4()
    with db.begin() as session:
        session.add(
            RoleAccount(
                role_account_id=account_id,
                user_id=PERSON_ID,
                email=email,
                role=role,
                password_hash=generate_from_password(password),
                is_confirmed=confirmed,
                is_active=True,
            )
        )
        if role in ORGANISATION_ROLES:
            session.add(
                OrganisationMembership(
                    role_account_id=account_id, organisation_id=uuid.UUID(ORGANISATION_ID)
                )
            )
    return account_id


def sign_in(client, role: str, password: str, email: str = EMAIL, **params: str):
    """Sign in, to ORGANISATION_ID for organisation roles unless params say otherwise."""
    return client.post(
        SIGN_IN,
        params=organisation_params(role) | params,
        json={"email": email, "password": password, "role": role},
    )


def test_person_with_several_logins_signs_in_to_the_one_named(auth_client, db, role_account_id):
    doctor_id = add_account(db, UserRole.DOCTOR, "doctor-password")

    for role, password, account_id in [
        (UserRole.PATIENT, PASSWORD, role_account_id),
        (UserRole.DOCTOR, "doctor-password", doctor_id),
    ]:
        resp = sign_in(auth_client, role, password)

        assert resp.status_code == 200
        for token, purpose in [
            (resp.json()["token"], TokenPurpose.ACCESS),
            (resp.json()["refresh_token"], TokenPurpose.REFRESH),
        ]:
            claims = validate_token(token, purpose)
            assert (claims.role, claims.role_account_id, claims.user_id) == (
                role,
                str(account_id),
                str(PERSON_ID),
            )


def test_sign_in_does_not_depend_on_which_login_was_created_first(auth_client, db):
    doctor_id = add_account(db, UserRole.DOCTOR, "doctor-password")
    add_account(db, UserRole.PATIENT, PASSWORD)

    resp = sign_in(auth_client, UserRole.DOCTOR, "doctor-password")

    assert resp.status_code == 200
    assert validate_token(resp.json()["token"], TokenPurpose.ACCESS).role_account_id == str(
        doctor_id
    )


def test_password_of_another_login_does_not_sign_in(auth_client, db, role_account_id):
    add_account(db, UserRole.DOCTOR, "doctor-password")

    resp = auth_client.post(
        SIGN_IN, json={"email": EMAIL, "password": "doctor-password", "role": UserRole.PATIENT}
    )

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_role_the_email_does_not_hold_looks_like_wrong_credentials(auth_client, role_account_id):
    held_elsewhere = sign_in(auth_client, UserRole.DOCTOR, PASSWORD)
    unknown_email = sign_in(auth_client, UserRole.DOCTOR, PASSWORD, email="user9@example.com")

    assert held_elsewhere.status_code == unknown_email.status_code == 401
    assert held_elsewhere.json() == unknown_email.json() == INVALID_CREDENTIALS


def test_unconfirmed_login_is_not_signed_in_to_even_beside_a_confirmed_one(
    auth_client, db, role_account_id
):
    add_account(db, UserRole.DOCTOR, "doctor-password", confirmed=False)

    resp = sign_in(auth_client, UserRole.DOCTOR, "doctor-password")

    assert resp.status_code == 401
    assert resp.json() == INVALID_CREDENTIALS


def test_database_refuses_second_login_with_same_email_and_role(db, role_account_id):
    with pytest.raises(IntegrityError):
        add_account(db, UserRole.PATIENT, "other-password")


def test_sign_in_refuses_to_guess_on_database_not_yet_migrated(legacy_db):
    # Only a database that has not run migrate-db can still hold such duplicates.
    for _ in range(2):
        add_account(legacy_db, UserRole.PATIENT, PASSWORD)
    svc = AuthService(db=legacy_db, logger=clog.must_new("auth"))

    with TestClient(new_auth_router(svc)) as client:
        resp = client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": ROLE})

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}


# --- Organisation roles sign in to one organisation, named in the query string ---

ORGANISATION_ID_REQUIRED = {"error": messages.ORGANISATION_ID_REQUIRED}
INVALID_ORGANISATION_ID = {"error": messages.INVALID_ORGANISATION_ID}
ORGANISATION_ID_NOT_ALLOWED = {"error": messages.ORGANISATION_ID_NOT_ALLOWED}
NON_ORGANISATION_ROLES = [role for role in UserRole if role not in ORGANISATION_ROLES]


def add_membership(db, account_id: uuid.UUID, organisation_id: str) -> None:
    with db.begin() as session:
        session.add(
            OrganisationMembership(
                role_account_id=account_id, organisation_id=uuid.UUID(organisation_id)
            )
        )


def test_organisation_roles_are_the_provider_roles():
    assert {
        UserRole.DOCTOR,
        UserRole.PHARMACIST,
        UserRole.HOSPITAL_ADMIN,
        UserRole.PHARMACY_ADMIN,
    } == ORGANISATION_ROLES


@pytest.mark.parametrize("role", sorted(ORGANISATION_ROLES))
@pytest.mark.parametrize("params", [{}, {"organisationId": ""}], ids=["absent", "empty"])
def test_organisation_role_without_organisation_returns_early(auth_client, no_lookup, role, params):
    resp = auth_client.post(
        SIGN_IN, params=params, json={"email": EMAIL, "password": PASSWORD, "role": role}
    )

    assert resp.status_code == 400
    assert resp.json() == ORGANISATION_ID_REQUIRED
    assert no_lookup == []


@pytest.mark.parametrize(
    "organisation_id",
    ["abc", "1234", str(NIL_UUID), ORGANISATION_ID + "0", "' OR 1=1 --"],
)
def test_organisation_role_with_invalid_organisation_returns_early(
    auth_client, no_lookup, organisation_id
):
    resp = sign_in(auth_client, UserRole.DOCTOR, PASSWORD, organisationId=organisation_id)

    assert resp.status_code == 400
    assert resp.json() == INVALID_ORGANISATION_ID
    assert no_lookup == []


@pytest.mark.parametrize("role", NON_ORGANISATION_ROLES)
def test_other_roles_may_not_name_an_organisation(auth_client, no_lookup, role):
    resp = sign_in(auth_client, role, PASSWORD, organisationId=ORGANISATION_ID)

    assert resp.status_code == 400
    assert resp.json() == ORGANISATION_ID_NOT_ALLOWED
    assert no_lookup == []


def test_role_is_checked_before_organisation(auth_client, no_lookup):
    missing = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD})
    unknown = auth_client.post(SIGN_IN, json={"email": EMAIL, "password": PASSWORD, "role": "d"})

    assert missing.json() == ROLE_REQUIRED
    assert unknown.json() == INVALID_ROLE


@pytest.mark.parametrize("role", sorted(ORGANISATION_ROLES))
def test_organisation_role_signs_in_to_its_organisation(auth_client, db, role):
    account_id = add_account(db, role, "provider-password")

    resp = sign_in(auth_client, role, "provider-password")

    assert resp.status_code == 200
    for token, purpose in [
        (resp.json()["token"], TokenPurpose.ACCESS),
        (resp.json()["refresh_token"], TokenPurpose.REFRESH),
    ]:
        claims = validate_token(token, purpose)
        assert (claims.role, claims.role_account_id, claims.organisation_id) == (
            role,
            str(account_id),
            ORGANISATION_ID,
        )


def test_provider_cannot_sign_in_to_an_organisation_it_does_not_work_for(auth_client, db):
    add_account(db, UserRole.DOCTOR, "doctor-password")

    other = sign_in(
        auth_client, UserRole.DOCTOR, "doctor-password", organisationId=OTHER_ORGANISATION_ID
    )
    wrong_password = sign_in(auth_client, UserRole.DOCTOR, "wrong")

    # Same answer as a wrong password, so memberships cannot be probed.
    assert other.status_code == wrong_password.status_code == 401
    assert other.json() == wrong_password.json() == INVALID_CREDENTIALS


def test_provider_in_two_organisations_signs_in_to_each(auth_client, db):
    account_id = add_account(db, UserRole.DOCTOR, "doctor-password")
    add_membership(db, account_id, OTHER_ORGANISATION_ID)

    for organisation_id in (ORGANISATION_ID, OTHER_ORGANISATION_ID):
        resp = sign_in(
            auth_client, UserRole.DOCTOR, "doctor-password", organisationId=organisation_id
        )

        assert resp.status_code == 200
        claims = validate_token(resp.json()["token"], TokenPurpose.ACCESS)
        assert (claims.role_account_id, claims.organisation_id) == (
            str(account_id),
            organisation_id,
        )


def test_membership_of_another_login_does_not_count(auth_client, db, role_account_id):
    # The person's patient login is in no organisation; their pharmacist login is.
    pharmacist_id = add_account(db, UserRole.PHARMACIST, "pharmacist-password")
    doctor_id = add_account(db, UserRole.DOCTOR, "doctor-password", email="user5@example.com")
    add_membership(db, pharmacist_id, OTHER_ORGANISATION_ID)

    resp = sign_in(
        auth_client,
        UserRole.DOCTOR,
        "doctor-password",
        email="user5@example.com",
        organisationId=OTHER_ORGANISATION_ID,
    )

    assert doctor_id != pharmacist_id
    assert resp.status_code == 401


def test_organisation_id_in_any_uuid_form_signs_in_with_its_canonical_form(auth_client, db):
    add_account(db, UserRole.DOCTOR, "doctor-password")

    resp = sign_in(
        auth_client,
        UserRole.DOCTOR,
        "doctor-password",
        organisationId=ORGANISATION_ID.upper().replace("-", ""),
    )

    assert resp.status_code == 200
    assert validate_token(resp.json()["token"], TokenPurpose.ACCESS).organisation_id == (
        ORGANISATION_ID
    )


def test_non_organisation_role_token_names_no_organisation(auth_client, role_account_id):
    resp = sign_in(auth_client, UserRole.PATIENT, PASSWORD)

    assert validate_token(resp.json()["token"], TokenPurpose.ACCESS).organisation_id == ""


def test_refresh_and_validate_keep_the_organisation(auth_client, db):
    add_account(db, UserRole.PHARMACIST, "pharmacist-password")
    signed_in = sign_in(auth_client, UserRole.PHARMACIST, "pharmacist-password").json()

    refreshed = auth_client.post(
        "/health-tech/auth/refresh", headers={"X-REFRESH-TOKEN": signed_in["refresh_token"]}
    )
    validated = auth_client.get(
        "/health-tech/auth/validate", headers={"X-USER-TOKEN": refreshed.json()["token"]}
    )

    assert validated.status_code == 200
    assert validated.json()["organisation_id"] == ORGANISATION_ID


# --- Emails compare without regard to case ---


@pytest.mark.parametrize("typed", ["USER1@EXAMPLE.COM", "User1@Example.com", "user1@example.com"])
def test_sign_in_email_is_not_case_sensitive(auth_client, role_account_id, typed):
    resp = auth_client.post(SIGN_IN, json={"email": typed, "password": PASSWORD, "role": ROLE})

    assert resp.status_code == 200
    assert validate_token(resp.json()["token"], TokenPurpose.ACCESS).email == EMAIL


def test_password_stays_case_sensitive(auth_client, role_account_id):
    resp = auth_client.post(
        SIGN_IN, json={"email": EMAIL, "password": PASSWORD.upper(), "role": ROLE}
    )

    assert resp.status_code == 401


# --- One person, two logins: /auth/validate shows which person and which login ---


def test_doctor_who_is_also_a_patient_sees_two_different_ids_in_validate(
    user_client, auth_client, db, mailer
):
    # The person and their patient login, created and confirmed through the API.
    user_client.post(
        "/health-tech/user", json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN)
    )
    user_client.get("/health-tech/user/confirm", params={"token": mailer.sent[-1][1]})
    with db() as session:
        person_id = session.scalars(select(User.id)).one()
    # The same person's doctor login, same email and password, in an organisation.
    user_client.post(
        "/health-tech/user/healthcare-providers",
        json={
            "email": NEW_PATIENT["email"],
            "role": UserRole.DOCTOR,
            "password": NEW_PATIENT["password"],
            "userId": str(person_id),
            "organisationId": ORGANISATION_ID,
        },
        headers=auth_header(UserRole.SUPER_ADMIN),
    )
    user_client.get("/health-tech/user/confirm", params={"token": mailer.sent[-1][1]})

    validated = {}
    for role in (UserRole.PATIENT, UserRole.DOCTOR):
        signed_in = sign_in(auth_client, role, NEW_PATIENT["password"], NEW_PATIENT["email"])
        assert signed_in.status_code == 200
        resp = auth_client.get(
            "/health-tech/auth/validate", headers={"X-USER-TOKEN": signed_in.json()["token"]}
        )
        assert resp.status_code == 200
        validated[role] = resp.json()

    patient, doctor = validated[UserRole.PATIENT], validated[UserRole.DOCTOR]
    # Each response shows two IDs, the person and the login, and they differ.
    for body in (patient, doctor):
        assert body["user_id"] and body["role_account_id"]
        assert body["user_id"] != body["role_account_id"]
    # Across the two logins: the same person, two different login IDs.
    assert patient["user_id"] == doctor["user_id"] == str(person_id)
    assert patient["role_account_id"] != doctor["role_account_id"]
    with db() as session:
        stored = dict(session.execute(select(RoleAccount.role, RoleAccount.role_account_id)).all())
    assert patient["role_account_id"] == str(stored[UserRole.PATIENT])
    assert doctor["role_account_id"] == str(stored[UserRole.DOCTOR])
    assert (patient["role"], patient["organisation_id"]) == (UserRole.PATIENT, "")
    assert (doctor["role"], doctor["organisation_id"]) == (UserRole.DOCTOR, ORGANISATION_ID)
    assert patient["email"] == doctor["email"] == NEW_PATIENT["email"]


# --- Token creation failures ---


def test_sign_in_token_failure_is_internal_server_error(auth_client, role_account_id, monkeypatch):
    def fail(*args, **kwargs):
        raise TokenError("cannot sign")

    monkeypatch.setattr(auth_service, "generate_token", fail)

    resp = sign_in(auth_client, UserRole.PATIENT, PASSWORD)

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}


def test_refresh_token_failure_is_internal_server_error(auth_client, monkeypatch):
    headers = refresh_header(UserRole.DOCTOR, "person-1", "role-account-1")

    def fail(*args, **kwargs):
        raise TokenError("cannot sign")

    monkeypatch.setattr(auth_service, "generate_token", fail)

    resp = auth_client.post("/health-tech/auth/refresh", headers=headers)

    assert resp.status_code == 500
    assert resp.json() == {"error": messages.INTERNAL_SERVER_ERROR}
