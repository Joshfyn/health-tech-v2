import uuid

import pytest
from sqlalchemy import select

from health_tech.lib.ids import NIL_UUID
from health_tech.lib.mail import MailError
from health_tech.lib.tokenmaker import TokenPurpose, TokenRequirements, generate_token
from health_tech.user.model import RoleAccount, User, UserRole
from tests.conftest import auth_header, make_token

NEW_PATIENT = {
    "email": "user1@example.com",
    "role": "patient",
    "firstName": "Sample",
    "lastName": "Patient",
    "dateOfBirth": "1990-05-15T00:00:00Z",
    "contact": {
        "phone": "123439373",
        "address": {
            "street": "1 Example Street",
            "city": "Example City",
            "state": "EX",
            "zipCode": "00000",
            "country": "US",
        },
    },
    "nationalID": "000000-0000",
    "password": "placeholder-password",
}


def provider_body(user_id: uuid.UUID, role: str = UserRole.DOCTOR) -> dict[str, str]:
    return {
        "email": "user2@example.com",
        "role": role,
        "password": "placeholder-password",
        "userId": str(user_id),
    }


def insert_user(db, email: str = "user2@example.com") -> uuid.UUID:
    user_id = uuid.uuid4()
    with db.begin() as session:
        session.add(User(id=user_id, email=email))
    return user_id


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        pytest.param({}, 401, id="no token"),
        pytest.param({"X-USER-TOKEN": "not-a-jwt"}, 401, id="invalid token"),
        pytest.param(auth_header(UserRole.PATIENT), 403, id="patient"),
        pytest.param(auth_header(UserRole.HOSPITAL_ADMIN), 403, id="hospital admin"),
        pytest.param(
            {"X-USER-TOKEN": make_token(UserRole.SUPER_ADMIN, purpose=TokenPurpose.REFRESH)},
            401,
            id="super admin refresh token",
        ),
        pytest.param(
            {
                "X-USER-TOKEN": make_token(
                    UserRole.SUPER_ADMIN, purpose=TokenPurpose.EMAIL_CONFIRMATION
                )
            },
            401,
            id="super admin email confirmation token",
        ),
    ],
)
def test_create_user_refuses_non_super_admins(user_client, db, headers, expected_status):
    resp = user_client.post("/health-tech/user", json=NEW_PATIENT, headers=headers)

    assert resp.status_code == expected_status
    with db() as session:
        assert User.get_users(session) == []


def test_create_patient_creates_user_and_role_account(user_client, db, mailer):
    resp = user_client.post(
        "/health-tech/user", json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 200
    assert resp.json() == {"message": "User created successfully"}
    with db() as session:
        account = session.scalars(select(RoleAccount)).one()
        assert account.role == UserRole.PATIENT
        assert account.role_account_id != NIL_UUID
        assert account.is_confirmed is False
        assert account.password_hash != NEW_PATIENT["password"]
    assert [email for email, _ in mailer.sent] == [NEW_PATIENT["email"]]


@pytest.mark.parametrize("role", [UserRole.PATIENT, UserRole.SUPER_ADMIN])
def test_each_new_role_account_gets_its_own_id(user_client, db, role):
    for email in ("user1@example.com", "user3@example.com"):
        resp = user_client.post(
            "/health-tech/user",
            json={**NEW_PATIENT, "email": email, "role": role},
            headers=auth_header(UserRole.SUPER_ADMIN),
        )
        assert resp.status_code == 200

    with db() as session:
        ids = session.scalars(select(RoleAccount.role_account_id)).all()
    assert len(ids) == 2
    assert NIL_UUID not in ids
    assert len(set(ids)) == 2


def test_create_user_rolls_back_when_mail_fails(user_client, db, mailer):
    mailer.error = MailError("smtp unavailable")

    resp = user_client.post(
        "/health-tech/user", json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    with db() as session:
        assert User.get_users(session) == []
        assert session.scalars(select(RoleAccount)).all() == []


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        pytest.param(
            {**NEW_PATIENT, "password": ""}, {"error": "password is required"}, id="no password"
        ),
        pytest.param(
            {**NEW_PATIENT, "firstName": 5}, {"error": "invalid request body"}, id="bad type"
        ),
    ],
)
def test_create_user_rejects_invalid_body(user_client, body, expected):
    resp = user_client.post(
        "/health-tech/user", json=body, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 400
    assert resp.json() == expected


def test_confirm_user_marks_account_confirmed(user_client, db, mailer):
    user_client.post(
        "/health-tech/user", json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN)
    )
    _, token = mailer.sent[0]

    resp = user_client.get("/health-tech/user/confirm", params={"token": token})

    assert resp.status_code == 200
    with db() as session:
        assert session.scalars(select(RoleAccount.is_confirmed)).one() is True


def test_emailed_confirmation_token_is_not_a_session_token(user_client, db, mailer):
    new_admin = {**NEW_PATIENT, "email": "user3@example.com", "role": UserRole.SUPER_ADMIN}
    user_client.post("/health-tech/user", json=new_admin, headers=auth_header(UserRole.SUPER_ADMIN))
    _, link_token = mailer.sent[0]

    resp = user_client.post(
        "/health-tech/user", json=NEW_PATIENT, headers={"X-USER-TOKEN": link_token}
    )

    assert resp.status_code == 401
    with db() as session:
        assert [user.email for user in User.get_users(session)] == [new_admin["email"]]


def test_confirm_user_rejects_non_confirmation_tokens(user_client, db, mailer):
    user_client.post(
        "/health-tech/user", json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN)
    )
    with db() as session:
        account = session.scalars(select(RoleAccount)).one()
    identity = TokenRequirements(
        email=account.email, user_id=str(account.user_id), role=account.role
    )

    for purpose in (TokenPurpose.ACCESS, TokenPurpose.REFRESH):
        resp = user_client.get(
            "/health-tech/user/confirm", params={"token": generate_token(identity, purpose)}
        )
        assert resp.status_code == 400

    with db() as session:
        assert session.scalars(select(RoleAccount.is_confirmed)).one() is False


def test_confirm_user_requires_token(user_client):
    resp = user_client.get("/health-tech/user/confirm")

    assert resp.status_code == 401


@pytest.mark.parametrize(
    ("caller", "role", "expected_status"),
    [
        pytest.param(UserRole.PATIENT, UserRole.DOCTOR, 403, id="patient caller"),
        pytest.param(
            UserRole.HOSPITAL_ADMIN, UserRole.PHARMACIST, 403, id="hospital admin, pharmacist"
        ),
        pytest.param(UserRole.PHARMACY_ADMIN, UserRole.DOCTOR, 403, id="pharmacy admin, doctor"),
        pytest.param(UserRole.SUPER_ADMIN, UserRole.PATIENT, 400, id="non-provider role"),
    ],
)
def test_create_provider_refuses_disallowed_roles(user_client, db, caller, role, expected_status):
    user_id = insert_user(db)
    body = provider_body(user_id, role)

    resp = user_client.post(
        "/health-tech/user/healthcare-providers", json=body, headers=auth_header(caller)
    )

    assert resp.status_code == expected_status
    with db() as session:
        assert session.scalars(select(RoleAccount)).all() == []


def test_hospital_admin_creates_doctor(user_client, db, mailer):
    user_id = insert_user(db)
    body = provider_body(user_id)

    resp = user_client.post(
        "/health-tech/user/healthcare-providers",
        json=body,
        headers=auth_header(UserRole.HOSPITAL_ADMIN),
    )

    assert resp.status_code == 200
    with db() as session:
        account = session.scalars(select(RoleAccount)).one()
        assert account.role == UserRole.DOCTOR
        assert account.role_account_id != NIL_UUID
        assert account.confirmation_token
    assert len(mailer.sent) == 1


def test_provider_confirmation_token_cannot_create_providers(user_client, db, mailer):
    user_client.post(
        "/health-tech/user/healthcare-providers",
        json=provider_body(insert_user(db), UserRole.HOSPITAL_ADMIN),
        headers=auth_header(UserRole.SUPER_ADMIN),
    )
    _, link_token = mailer.sent[0]

    resp = user_client.post(
        "/health-tech/user/healthcare-providers",
        json={**provider_body(insert_user(db, "user4@example.com")), "email": "user4@example.com"},
        headers={"X-USER-TOKEN": link_token},
    )

    assert resp.status_code == 401
    with db() as session:
        assert session.scalars(select(RoleAccount.role)).all() == [UserRole.HOSPITAL_ADMIN]


@pytest.mark.parametrize(
    ("existing_role", "expected"),
    [
        pytest.param(None, {"error": "user must have a basic account first"}, id="unknown user"),
        pytest.param(UserRole.DOCTOR, {"error": "user already has this role"}, id="duplicate role"),
    ],
)
def test_create_provider_rejects_unknown_user_or_duplicate_role(
    user_client, db, existing_role, expected
):
    user_id = uuid.uuid4()
    if existing_role is not None:
        user_id = insert_user(db)
        with db.begin() as session:
            session.add(RoleAccount(user_id=user_id, email="user2@example.com", role=existing_role))
    body = provider_body(user_id)

    resp = user_client.post(
        "/health-tech/user/healthcare-providers",
        json=body,
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert resp.status_code == 400
    assert resp.json() == expected
