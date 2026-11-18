import time
import uuid
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, OperationalError

from health_tech.lib import tokenmaker
from health_tech.lib.ids import NIL_UUID
from health_tech.lib.mail import MailError
from health_tech.lib.tokenmaker import (
    TokenError,
    TokenPurpose,
    TokenRequirements,
    generate_token,
    validate_token,
)
from health_tech.migrate.seed import create_sample_users
from health_tech.user import messages
from health_tech.user import service as user_service
from health_tech.user.dto import DEFAULT_PAGE_SIZE, MAX_PAGE_SIZE
from health_tech.user.model import OrganisationMembership, RoleAccount, User, UserRole
from tests.conftest import ORGANISATION_ID, OTHER_ORGANISATION_ID, auth_header, make_token

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
        "organisationId": ORGANISATION_ID,
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
        *[
            pytest.param(auth_header(role), 401, id=role)
            for role in UserRole
            if role != UserRole.SUPER_ADMIN
        ],
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
            {**NEW_PATIENT, "password": ""}, messages.PASSWORD_REQUIRED.body(), id="no password"
        ),
        pytest.param(
            {**NEW_PATIENT, "firstName": 5}, messages.INVALID_REQUEST_BODY.body(), id="bad type"
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
        pytest.param(UserRole.PATIENT, UserRole.DOCTOR, 401, id="patient caller"),
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
        pytest.param(None, messages.BASIC_ACCOUNT_REQUIRED.body(), id="unknown user"),
        pytest.param(UserRole.DOCTOR, messages.ROLE_ALREADY_HELD.body(), id="duplicate role"),
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


# --- Listing users: super admins only, one page at a time ---

USERS = "/health-tech/user"
FORBIDDEN = messages.FORBIDDEN.body()
ROLE_NOT_ALLOWED = messages.ROLE_NOT_ALLOWED.body()
USER_NOT_FOUND = messages.USER_NOT_FOUND.body()
INVALID_CONFIRMATION_TOKEN = messages.INVALID_CONFIRMATION_TOKEN.body()
INTERNAL_SERVER_ERROR = messages.INTERNAL_ERROR.body()
ORGANISATION_ID_REQUIRED = messages.ORGANISATION_ID_REQUIRED.body()


def insert_users(db, count: int) -> list[uuid.UUID]:
    """Insert count users created one second apart; return their IDs, oldest first."""
    start = datetime(2026, 1, 1, tzinfo=UTC)
    users = [
        User(
            id=uuid.uuid4(),
            email=f"user{n}@example.com",
            national_id=f"000000-{n:04d}",
            created_at=start + timedelta(seconds=n),
        )
        for n in range(count)
    ]
    with db.begin() as session:
        # Newest first, so insertion order never passes for creation order.
        for user in reversed(users):
            session.add(user)
            session.flush()
    return [user.id for user in users]


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    [
        pytest.param({}, 401, id="no token"),
        pytest.param({"X-USER-TOKEN": "not-a-jwt"}, 401, id="invalid token"),
        pytest.param(
            {"X-USER-TOKEN": make_token(UserRole.SUPER_ADMIN, purpose=TokenPurpose.REFRESH)},
            401,
            id="super admin refresh token",
        ),
        *[
            pytest.param(auth_header(role, str(uuid.uuid4()), str(uuid.uuid4())), 401, id=role)
            for role in UserRole
            if role != UserRole.SUPER_ADMIN
        ],
    ],
)
def test_list_users_refuses_everyone_but_super_admins(user_client, db, headers, expected_status):
    insert_users(db, 3)

    resp = user_client.get(USERS, headers=headers)

    assert resp.status_code == expected_status
    assert "users" not in resp.json()
    assert "000000-0000" not in resp.text


def test_list_users_checks_the_caller_before_the_paging_parameters(user_client):
    resp = user_client.get(USERS, params={"page": "0"})

    assert resp.status_code == 401


def test_list_users_returns_first_page_by_default(user_client, db):
    ids = insert_users(db, DEFAULT_PAGE_SIZE + 5)

    resp = user_client.get(USERS, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 200
    body = resp.json()
    assert body.keys() == {"users", "page", "pageSize", "total", "totalPages"}
    assert (body["page"], body["pageSize"], body["total"], body["totalPages"]) == (
        1,
        DEFAULT_PAGE_SIZE,
        DEFAULT_PAGE_SIZE + 5,
        2,
    )
    assert [user["id"] for user in body["users"]] == [str(i) for i in ids[:DEFAULT_PAGE_SIZE]]
    assert all("nationalID" not in user for user in body["users"])


def test_list_users_pages_cover_every_user_once_in_creation_order(user_client, db):
    ids = insert_users(db, 7)

    pages = [
        user_client.get(
            USERS, params={"page": page, "pageSize": 3}, headers=auth_header(UserRole.SUPER_ADMIN)
        ).json()
        for page in (1, 2, 3)
    ]

    assert [len(p["users"]) for p in pages] == [3, 3, 1]
    assert {(p["total"], p["totalPages"], p["pageSize"]) for p in pages} == {(7, 3, 3)}
    assert [u["id"] for p in pages for u in p["users"]] == [str(i) for i in ids]


def test_list_users_orders_users_with_equal_creation_times_deterministically(user_client, db):
    with db.begin() as session:
        session.add_all(User(id=uuid.uuid4(), email=f"u{n}@example.com") for n in range(5))

    def listed(page_size: int) -> list[str]:
        pages = [
            user_client.get(
                USERS,
                params={"page": page, "pageSize": page_size},
                headers=auth_header(UserRole.SUPER_ADMIN),
            ).json()["users"]
            for page in range(1, 6)
        ]
        return [u["id"] for p in pages for u in p]

    assert listed(2) == listed(5)
    assert len(set(listed(2))) == 5


@pytest.mark.parametrize("page", ["4", "999999999999999999999999999999"])
def test_list_users_past_the_last_page_is_empty(user_client, db, page):
    insert_users(db, 5)

    resp = user_client.get(
        USERS, params={"page": page, "pageSize": 2}, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 200
    assert resp.json()["users"] == []
    assert (resp.json()["total"], resp.json()["totalPages"]) == (5, 3)


def test_list_users_with_no_users(user_client):
    resp = user_client.get(USERS, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 200
    assert resp.json() == {"users": [], "page": 1, "pageSize": 20, "total": 0, "totalPages": 0}


def test_list_users_accepts_the_maximum_page_size(user_client, db):
    insert_users(db, MAX_PAGE_SIZE + 1)

    resp = user_client.get(
        USERS, params={"pageSize": MAX_PAGE_SIZE}, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 200
    assert len(resp.json()["users"]) == MAX_PAGE_SIZE


PAGE_ERROR = messages.INVALID_PAGE.body()
PAGE_SIZE_ERROR = messages.INVALID_PAGE_SIZE.body()


@pytest.mark.parametrize(
    ("params", "expected"),
    [
        pytest.param({"page": "0"}, PAGE_ERROR, id="page zero"),
        pytest.param({"page": "-1"}, PAGE_ERROR, id="negative page"),
        pytest.param({"page": "abc"}, PAGE_ERROR, id="page not a number"),
        pytest.param({"page": "1.5"}, PAGE_ERROR, id="fractional page"),
        pytest.param({"page": ""}, PAGE_ERROR, id="empty page"),
        pytest.param({"page": " 2"}, PAGE_ERROR, id="page with space"),
        pytest.param({"page": "\u0662"}, PAGE_ERROR, id="non-ascii digit"),
        pytest.param({"page": "9" * 5000}, PAGE_ERROR, id="page too long to parse"),
        pytest.param({"pageSize": "0"}, PAGE_SIZE_ERROR, id="page size zero"),
        pytest.param({"pageSize": "-5"}, PAGE_SIZE_ERROR, id="negative page size"),
        pytest.param({"pageSize": "ten"}, PAGE_SIZE_ERROR, id="page size not a number"),
    ],
)
def test_list_users_rejects_invalid_paging(user_client, params, expected):
    resp = user_client.get(USERS, params=params, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert resp.json() == expected


def test_created_users_get_creation_times(user_client, db):
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))

    with db() as session:
        user = session.scalars(select(User)).one()
    assert user.created_at is not None
    assert user.updated_at == user.created_at


# --- Reading one user's record: patients see only their own ---


def user_url(user_id: uuid.UUID | str) -> str:
    return f"{USERS}/{user_id}"


def test_patient_reads_own_record(user_client, db):
    own, _ = insert_users(db, 2)

    resp = user_client.get(
        user_url(own), headers=auth_header(UserRole.PATIENT, str(own), str(uuid.uuid4()))
    )

    assert resp.status_code == 200
    assert resp.json()["id"] == str(own)
    assert resp.json()["nationalID"] == "000000-0000"


@pytest.mark.parametrize("target", ["other user", "unknown user", "not a uuid"])
def test_patient_cannot_read_another_record(user_client, db, target):
    own, other = insert_users(db, 2)
    path = {"other user": other, "unknown user": uuid.uuid4(), "not a uuid": "abc"}[target]

    resp = user_client.get(
        user_url(path), headers=auth_header(UserRole.PATIENT, str(own), str(uuid.uuid4()))
    )

    # Same answer whether or not the record exists, so IDs cannot be probed.
    assert resp.status_code == 403
    assert resp.json() == FORBIDDEN


def test_patient_token_without_user_id_reads_nothing(user_client, db):
    (own,) = insert_users(db, 1)

    resp = user_client.get(user_url(own), headers=auth_header(UserRole.PATIENT))

    assert resp.status_code == 403
    assert resp.json() == FORBIDDEN


def test_patient_cannot_pass_role_account_id_as_user_id(user_client, db):
    # Old tokens put the role account ID in UserID; the record is keyed by the person.
    own, other = insert_users(db, 2)

    resp = user_client.get(
        user_url(other), headers=auth_header(UserRole.PATIENT, str(own), str(other))
    )

    assert resp.status_code == 403
    assert resp.json() == FORBIDDEN


@pytest.mark.parametrize(
    "role", [r for r in UserRole if r not in (UserRole.PATIENT, UserRole.SUPER_ADMIN)]
)
def test_other_roles_have_no_per_patient_access(user_client, db, role):
    own, other = insert_users(db, 2)

    for target in (own, other):
        resp = user_client.get(
            user_url(target), headers=auth_header(role, str(own), str(uuid.uuid4()))
        )
        assert resp.status_code == 401
        assert resp.json() == ROLE_NOT_ALLOWED


@pytest.mark.parametrize(
    "headers",
    [
        pytest.param({}, id="no token"),
        pytest.param({"X-USER-TOKEN": "not-a-jwt"}, id="invalid token"),
        pytest.param(
            {"X-USER-TOKEN": make_token(UserRole.PATIENT, purpose=TokenPurpose.REFRESH)},
            id="refresh token",
        ),
        pytest.param(
            {"X-USER-TOKEN": make_token(UserRole.PATIENT, purpose=TokenPurpose.EMAIL_CONFIRMATION)},
            id="email confirmation token",
        ),
    ],
)
def test_reading_a_record_needs_an_access_token(user_client, db, headers):
    (own,) = insert_users(db, 1)

    resp = user_client.get(user_url(own), headers=headers)

    assert resp.status_code == 401


def test_super_admin_reads_any_record(user_client, db):
    _, other = insert_users(db, 2)

    resp = user_client.get(user_url(other), headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 200
    assert resp.json()["id"] == str(other)


@pytest.mark.parametrize("path", [str(uuid.uuid4()), "abc"])
def test_super_admin_gets_not_found_for_unknown_record(user_client, path):
    resp = user_client.get(user_url(path), headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 404
    assert resp.json() == USER_NOT_FOUND


def test_fixed_user_paths_are_not_read_as_user_ids(user_client):
    resp = user_client.get(f"{USERS}/confirm", headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 401  # the confirm route, asking for its token


def create_confirm_and_sign_in(user_client, auth_client, mailer, email: str) -> str:
    """Register a patient through the API, confirm it and return its access token."""
    user_client.post(
        USERS, json={**NEW_PATIENT, "email": email}, headers=auth_header("super_admin")
    )
    user_client.get(f"{USERS}/confirm", params={"token": mailer.sent[-1][1]})
    resp = auth_client.post(
        "/health-tech/auth/signin",
        json={"email": email, "password": NEW_PATIENT["password"], "role": UserRole.PATIENT},
    )
    assert resp.status_code == 200
    return resp.json()["token"]


def test_signed_in_patient_reads_only_own_record(user_client, auth_client, db, mailer):
    alice = create_confirm_and_sign_in(user_client, auth_client, mailer, "user1@example.com")
    create_confirm_and_sign_in(user_client, auth_client, mailer, "user3@example.com")
    with db() as session:
        ids = {u.email: u.id for u in User.get_users(session)}

    own = user_client.get(user_url(ids["user1@example.com"]), headers={"X-USER-TOKEN": alice})
    other = user_client.get(user_url(ids["user3@example.com"]), headers={"X-USER-TOKEN": alice})
    listing = user_client.get(USERS, headers={"X-USER-TOKEN": alice})

    assert own.status_code == 200
    assert own.json()["email"] == "user1@example.com"
    assert other.status_code == 403  # patients may read records: not this one
    assert other.json() == FORBIDDEN
    assert listing.status_code == 401  # patients may not list users at all
    assert listing.json() == ROLE_NOT_ALLOWED


# --- Confirmation tokens name the person and the exact role account ---


def test_patient_confirmation_token_names_person_and_role_account(user_client, db, mailer):
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))

    claims = validate_token(mailer.sent[0][1], TokenPurpose.EMAIL_CONFIRMATION)
    with db() as session:
        account = session.scalars(select(RoleAccount)).one()
    assert claims.user_id == str(account.user_id)
    assert claims.role_account_id == str(account.role_account_id)


def test_provider_confirmation_token_names_person_and_role_account(user_client, db, mailer):
    user_id = insert_user(db)
    user_client.post(
        "/health-tech/user/healthcare-providers",
        json=provider_body(user_id),
        headers=auth_header(UserRole.HOSPITAL_ADMIN),
    )

    claims = validate_token(mailer.sent[0][1], TokenPurpose.EMAIL_CONFIRMATION)
    with db() as session:
        account = session.scalars(select(RoleAccount)).one()
    assert claims.user_id == str(user_id)
    assert claims.role_account_id == str(account.role_account_id)


def test_confirmed_provider_signs_in_as_their_person(user_client, auth_client, db, mailer):
    user_id = insert_user(db)
    user_client.post(
        "/health-tech/user/healthcare-providers",
        json=provider_body(user_id),
        headers=auth_header(UserRole.HOSPITAL_ADMIN),
    )

    confirmed = user_client.get(f"{USERS}/confirm", params={"token": mailer.sent[0][1]})
    resp = auth_client.post(
        "/health-tech/auth/signin",
        params={"organisationId": ORGANISATION_ID},
        json={
            "email": "user2@example.com",
            "password": "placeholder-password",
            "role": UserRole.DOCTOR,
        },
    )

    assert confirmed.status_code == 200
    assert resp.status_code == 200
    claims = validate_token(resp.json()["token"], TokenPurpose.ACCESS)
    with db() as session:
        account = session.scalars(select(RoleAccount)).one()
    assert (claims.user_id, claims.role_account_id, claims.role, claims.organisation_id) == (
        str(user_id),
        str(account.role_account_id),
        UserRole.DOCTOR,
        ORGANISATION_ID,
    )


def confirmation_token(**claims: str) -> str:
    return generate_token(TokenRequirements(**claims), TokenPurpose.EMAIL_CONFIRMATION)


def test_confirmation_confirms_only_the_named_role_account(user_client, db):
    # One person, one email, two logins.
    user_id = insert_user(db)
    account_ids = [uuid.uuid4(), uuid.uuid4()]
    roles = [UserRole.PATIENT, UserRole.DOCTOR]
    with db.begin() as session:
        for account_id, role in zip(account_ids, roles, strict=True):
            session.add(
                RoleAccount(
                    role_account_id=account_id,
                    user_id=user_id,
                    email="user2@example.com",
                    role=role,
                )
            )

    resp = user_client.get(
        f"{USERS}/confirm",
        params={
            "token": confirmation_token(
                email="user2@example.com",
                user_id=str(user_id),
                role_account_id=str(account_ids[1]),
                role=UserRole.DOCTOR,
            )
        },
    )

    assert resp.status_code == 200
    with db() as session:
        confirmed = dict(
            session.execute(select(RoleAccount.role_account_id, RoleAccount.is_confirmed)).all()
        )
    assert confirmed == {account_ids[0]: False, account_ids[1]: True}


@pytest.mark.parametrize(
    ("override", "expected_status", "expected"),
    [
        pytest.param(
            {"role_account_id": str(uuid.uuid4())}, 404, USER_NOT_FOUND, id="other role account"
        ),
        pytest.param({"role": UserRole.SUPER_ADMIN}, 404, USER_NOT_FOUND, id="other role"),
        pytest.param({"email": "user9@example.com"}, 404, USER_NOT_FOUND, id="other email"),
        pytest.param({"user_id": str(uuid.uuid4())}, 404, USER_NOT_FOUND, id="unknown person"),
        pytest.param({"user_id": ""}, 400, INVALID_CONFIRMATION_TOKEN, id="no person"),
        pytest.param(
            {"role_account_id": "not-a-uuid"},
            400,
            INVALID_CONFIRMATION_TOKEN,
            id="bad role account id",
        ),
    ],
)
def test_confirmation_token_must_match_the_role_account(
    user_client, db, mailer, override, expected_status, expected
):
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))
    claims = validate_token(mailer.sent[0][1], TokenPurpose.EMAIL_CONFIRMATION)
    identity = {
        "email": claims.email,
        "user_id": claims.user_id,
        "role_account_id": claims.role_account_id,
        "role": claims.role,
    }

    resp = user_client.get(
        f"{USERS}/confirm", params={"token": confirmation_token(**(identity | override))}
    )

    assert resp.status_code == expected_status
    assert resp.json() == expected
    with db() as session:
        assert session.scalars(select(RoleAccount.is_confirmed)).one() is False


def test_patient_confirmation_link_from_before_role_account_claim_still_works(
    user_client, db, mailer
):
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))
    claims = validate_token(mailer.sent[0][1], TokenPurpose.EMAIL_CONFIRMATION)
    now = int(time.time())
    legacy = jwt.encode(
        {
            "Email": claims.email,
            "UserID": claims.user_id,
            "Role": claims.role,
            "Purpose": TokenPurpose.EMAIL_CONFIRMATION.value,
            "iat": now,
            "exp": now + 60,
        },
        tokenmaker._signing_key(TokenPurpose.EMAIL_CONFIRMATION),
        algorithm="HS256",
    )

    resp = user_client.get(f"{USERS}/confirm", params={"token": legacy})

    assert resp.status_code == 200
    with db() as session:
        assert session.scalars(select(RoleAccount.is_confirmed)).one() is True


# --- Database failures answer with a generic message, never the database error ---

DB_ERROR = "database is unavailable"


def fail(*args, **kwargs):
    raise OperationalError("SELECT", {}, Exception(DB_ERROR))


def test_list_users_database_error_is_internal_server_error(user_client, monkeypatch):
    monkeypatch.setattr(User, "get_users_page", fail)

    resp = user_client.get(USERS, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert DB_ERROR not in resp.text


def test_read_record_database_error_is_internal_server_error(user_client, monkeypatch):
    monkeypatch.setattr(User, "get_user", fail)

    resp = user_client.get(user_url(uuid.uuid4()), headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert DB_ERROR not in resp.text


def test_confirm_user_database_error_is_internal_server_error(user_client, mailer, monkeypatch):
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))
    monkeypatch.setattr(RoleAccount, "confirm_user", fail)

    resp = user_client.get(f"{USERS}/confirm", params={"token": mailer.sent[0][1]})

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert DB_ERROR not in resp.text


# --- One login per email and role ---

ACCOUNT_EXISTS = messages.ACCOUNT_EXISTS.body()
PROVIDERS = "/health-tech/user/healthcare-providers"


def role_accounts(db) -> list[tuple[str, str]]:
    with db() as session:
        rows = session.execute(select(RoleAccount.email, RoleAccount.role)).all()
    return sorted((email, role) for email, role in rows)


@pytest.mark.parametrize("role", [UserRole.PATIENT, UserRole.SUPER_ADMIN])
def test_create_user_refuses_taken_email_and_role(user_client, db, mailer, role):
    body = {**NEW_PATIENT, "role": role}
    first = user_client.post(USERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    second = user_client.post(USERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json() == ACCOUNT_EXISTS
    with db() as session:
        assert len(User.get_users(session)) == 1  # the second user row was rolled back
    assert role_accounts(db) == [(NEW_PATIENT["email"], role)]
    assert len(mailer.sent) == 1


def test_create_user_allows_taken_email_in_another_role(user_client, db):
    for role in (UserRole.PATIENT, UserRole.SUPER_ADMIN):
        resp = user_client.post(
            USERS, json={**NEW_PATIENT, "role": role}, headers=auth_header(UserRole.SUPER_ADMIN)
        )
        assert resp.status_code == 200

    assert role_accounts(db) == [
        (NEW_PATIENT["email"], UserRole.PATIENT),
        (NEW_PATIENT["email"], UserRole.SUPER_ADMIN),
    ]


def test_create_basic_user_with_taken_email_creates_no_login(user_client, db):
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))

    resp = user_client.post(
        USERS, json={**NEW_PATIENT, "role": ""}, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 200
    assert role_accounts(db) == [(NEW_PATIENT["email"], UserRole.PATIENT)]


def test_create_provider_refuses_email_and_role_taken_by_another_person(user_client, db, mailer):
    first = user_client.post(
        PROVIDERS,
        json=provider_body(insert_user(db, "user2@example.com")),
        headers=auth_header(UserRole.HOSPITAL_ADMIN),
    )

    second = user_client.post(
        PROVIDERS,
        json=provider_body(insert_user(db, "user4@example.com")),
        headers=auth_header(UserRole.HOSPITAL_ADMIN),
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json() == ACCOUNT_EXISTS
    assert role_accounts(db) == [("user2@example.com", UserRole.DOCTOR)]
    assert len(mailer.sent) == 1


def test_create_provider_allows_patient_email_for_the_doctor_login(user_client, db):
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))
    with db() as session:
        (user,) = User.get_users(session)

    resp = user_client.post(
        PROVIDERS,
        json={**provider_body(user.id), "email": NEW_PATIENT["email"]},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert resp.status_code == 200
    assert role_accounts(db) == [
        (NEW_PATIENT["email"], UserRole.DOCTOR),
        (NEW_PATIENT["email"], UserRole.PATIENT),
    ]


@pytest.fixture
def lost_race(db, monkeypatch):
    """Another request's login with the same email and role commits just after the check.

    The login is already stored and the first, in-transaction check reports the pair free, as
    it would have a moment earlier; the insert then meets the unique index.
    """
    for email, role in [
        (NEW_PATIENT["email"], UserRole.PATIENT),
        ("user2@example.com", UserRole.DOCTOR),
    ]:
        with db.begin() as session:
            session.add(RoleAccount(user_id=uuid.uuid4(), email=email, role=role))
    real = RoleAccount.email_role_taken.__func__
    checks = []

    def check(cls, session, *, email, role):
        checks.append(role)
        return False if len(checks) == 1 else real(cls, session, email=email, role=role)

    monkeypatch.setattr(RoleAccount, "email_role_taken", classmethod(check))
    return checks


def test_create_user_losing_the_race_gets_conflict_not_error(user_client, db, mailer, lost_race):
    resp = user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 409
    assert resp.json() == ACCOUNT_EXISTS
    assert len(lost_race) == 2  # the check, then the recheck after the unique index refused
    with db() as session:
        assert User.get_users(session) == []  # the new user row was rolled back
    assert role_accounts(db) == [
        (NEW_PATIENT["email"], UserRole.PATIENT),
        ("user2@example.com", UserRole.DOCTOR),
    ]
    assert mailer.sent == []


def test_create_provider_losing_the_race_gets_conflict_not_error(
    user_client, db, mailer, lost_race
):
    resp = user_client.post(
        PROVIDERS, json=provider_body(insert_user(db)), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 409
    assert resp.json() == ACCOUNT_EXISTS
    assert len(lost_race) == 2
    assert role_accounts(db) == [
        (NEW_PATIENT["email"], UserRole.PATIENT),
        ("user2@example.com", UserRole.DOCTOR),
    ]
    assert mailer.sent == []


def integrity_error(*args, **kwargs):
    raise IntegrityError("INSERT", {}, Exception("some other constraint"))


def test_other_integrity_errors_creating_user_stay_internal_errors(user_client, monkeypatch):
    monkeypatch.setattr(RoleAccount, "create_new_user_account", integrity_error)

    resp = user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR


def test_other_integrity_errors_creating_provider_stay_internal_errors(
    user_client, db, monkeypatch
):
    monkeypatch.setattr(RoleAccount, "create_new_user_account", integrity_error)

    resp = user_client.post(
        PROVIDERS, json=provider_body(insert_user(db)), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR


# --- Providers work for organisations ---

ADD_ORGANISATION = f"{PROVIDERS}/organisations"


def memberships(db) -> list[tuple[str, str]]:
    """(email, organisation id) of every membership."""
    with db() as session:
        rows = session.execute(
            select(RoleAccount.email, OrganisationMembership.organisation_id).join(
                RoleAccount,
                RoleAccount.role_account_id == OrganisationMembership.role_account_id,
            )
        ).all()
    return sorted((email, str(organisation_id)) for email, organisation_id in rows)


@pytest.mark.parametrize(
    ("caller", "role"),
    [
        (UserRole.SUPER_ADMIN, UserRole.HOSPITAL_ADMIN),
        (UserRole.HOSPITAL_ADMIN, UserRole.DOCTOR),
        (UserRole.PHARMACY_ADMIN, UserRole.PHARMACIST),
    ],
)
def test_new_provider_works_for_the_organisation(user_client, db, caller, role):
    resp = user_client.post(
        PROVIDERS, json=provider_body(insert_user(db), role), headers=auth_header(caller)
    )

    assert resp.status_code == 200
    assert memberships(db) == [("user2@example.com", ORGANISATION_ID)]


def test_super_admin_must_name_the_organisation(user_client, db, mailer):
    body = provider_body(insert_user(db))
    del body["organisationId"]

    resp = user_client.post(PROVIDERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert resp.json() == ORGANISATION_ID_REQUIRED
    assert role_accounts(db) == []
    assert mailer.sent == []


def test_admin_adds_provider_to_own_organisation_when_none_named(user_client, db):
    body = provider_body(insert_user(db))
    del body["organisationId"]

    resp = user_client.post(PROVIDERS, json=body, headers=auth_header(UserRole.HOSPITAL_ADMIN))

    assert resp.status_code == 200
    assert memberships(db) == [("user2@example.com", ORGANISATION_ID)]


def test_admin_cannot_create_provider_in_another_organisation(user_client, db, mailer):
    body = {**provider_body(insert_user(db)), "organisationId": OTHER_ORGANISATION_ID}

    resp = user_client.post(PROVIDERS, json=body, headers=auth_header(UserRole.HOSPITAL_ADMIN))

    assert resp.status_code == 403
    assert resp.json() == FORBIDDEN
    assert role_accounts(db) == []
    assert mailer.sent == []


def test_admin_token_without_organisation_cannot_create_providers(user_client, db):
    resp = user_client.post(
        PROVIDERS,
        json=provider_body(insert_user(db)),
        headers=auth_header(UserRole.HOSPITAL_ADMIN, organisation_id=""),
    )

    assert resp.status_code == 403
    assert role_accounts(db) == []


@pytest.mark.parametrize("organisation_id", ["abc", 5])
def test_create_provider_rejects_malformed_organisation(user_client, db, organisation_id):
    body = {**provider_body(insert_user(db)), "organisationId": organisation_id}

    resp = user_client.post(PROVIDERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert role_accounts(db) == []


def test_membership_rolls_back_with_failed_provider_creation(user_client, db, mailer):
    mailer.error = MailError("smtp unavailable")

    resp = user_client.post(
        PROVIDERS, json=provider_body(insert_user(db)), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    assert role_accounts(db) == []
    assert memberships(db) == []


def create_doctor(user_client, db) -> None:
    """A doctor login, user2@example.com, working for ORGANISATION_ID."""
    resp = user_client.post(
        PROVIDERS, json=provider_body(insert_user(db)), headers=auth_header(UserRole.SUPER_ADMIN)
    )
    assert resp.status_code == 200


def add_organisation_body(organisation_id: str = OTHER_ORGANISATION_ID, **overrides) -> dict:
    return {
        "email": "user2@example.com",
        "role": UserRole.DOCTOR,
        "organisationId": organisation_id,
    } | overrides


def test_doctor_joins_a_second_organisation_and_signs_in_to_both(
    user_client, auth_client, db, mailer
):
    create_doctor(user_client, db)
    user_client.get(f"{USERS}/confirm", params={"token": mailer.sent[0][1]})

    resp = user_client.post(
        ADD_ORGANISATION,
        json=add_organisation_body(),
        headers=auth_header(UserRole.HOSPITAL_ADMIN, organisation_id=OTHER_ORGANISATION_ID),
    )

    assert resp.status_code == 200
    assert resp.json() == {"message": messages.PROVIDER_ADDED_TO_ORGANISATION}
    assert memberships(db) == [
        ("user2@example.com", OTHER_ORGANISATION_ID),
        ("user2@example.com", ORGANISATION_ID),
    ]
    assert len(mailer.sent) == 1  # the same login: no new account, no new email
    for organisation_id in (ORGANISATION_ID, OTHER_ORGANISATION_ID):
        signed_in = auth_client.post(
            "/health-tech/auth/signin",
            params={"organisationId": organisation_id},
            json={
                "email": "user2@example.com",
                "password": "placeholder-password",
                "role": UserRole.DOCTOR,
            },
        )
        assert signed_in.status_code == 200
        claims = validate_token(signed_in.json()["token"], TokenPurpose.ACCESS)
        assert claims.organisation_id == organisation_id


def test_admin_adds_to_own_organisation_when_none_named(user_client, db):
    create_doctor(user_client, db)
    body = add_organisation_body()
    del body["organisationId"]

    resp = user_client.post(
        ADD_ORGANISATION,
        json=body,
        headers=auth_header(UserRole.HOSPITAL_ADMIN, organisation_id=OTHER_ORGANISATION_ID),
    )

    assert resp.status_code == 200
    assert ("user2@example.com", OTHER_ORGANISATION_ID) in memberships(db)


def test_adding_to_an_organisation_twice_is_a_conflict(user_client, db):
    create_doctor(user_client, db)

    resp = user_client.post(
        ADD_ORGANISATION,
        json=add_organisation_body(ORGANISATION_ID),
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert resp.status_code == 409
    assert resp.json() == messages.ALREADY_IN_ORGANISATION.body()
    assert memberships(db) == [("user2@example.com", ORGANISATION_ID)]


def test_adding_an_unknown_provider_is_not_found(user_client, db):
    resp = user_client.post(
        ADD_ORGANISATION, json=add_organisation_body(), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 404
    assert resp.json() == messages.PROVIDER_NOT_FOUND.body()
    assert memberships(db) == []


def test_provider_is_found_whatever_the_case_of_the_email(user_client, db):
    create_doctor(user_client, db)

    resp = user_client.post(
        ADD_ORGANISATION,
        json=add_organisation_body(email="USER2@Example.COM"),
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert resp.status_code == 200


def test_adding_to_organisation_losing_the_race_is_a_conflict(user_client, db, monkeypatch):
    create_doctor(user_client, db)
    with db() as session:
        account_id = session.scalars(select(RoleAccount.role_account_id)).one()
    with db.begin() as session:  # the other request's membership, already committed
        session.add(
            OrganisationMembership(
                role_account_id=account_id, organisation_id=uuid.UUID(OTHER_ORGANISATION_ID)
            )
        )
    real = OrganisationMembership.is_member.__func__
    checks = []

    def check(cls, session, **kwargs):
        checks.append(kwargs)
        return False if len(checks) == 1 else real(cls, session, **kwargs)

    monkeypatch.setattr(OrganisationMembership, "is_member", classmethod(check))

    resp = user_client.post(
        ADD_ORGANISATION, json=add_organisation_body(), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 409
    assert resp.json() == messages.ALREADY_IN_ORGANISATION.body()
    assert len(checks) == 2


@pytest.mark.parametrize(
    ("headers", "body", "expected_status", "expected"),
    [
        pytest.param({}, add_organisation_body(), 401, None, id="no token"),
        *[
            pytest.param(auth_header(role), add_organisation_body(), 401, ROLE_NOT_ALLOWED, id=role)
            for role in (UserRole.PATIENT, UserRole.DOCTOR, UserRole.PHARMACIST)
        ],
        pytest.param(
            auth_header(UserRole.HOSPITAL_ADMIN),
            add_organisation_body(role=UserRole.PHARMACIST),
            403,
            FORBIDDEN,
            id="hospital admin, pharmacist",
        ),
        pytest.param(
            auth_header(UserRole.PHARMACY_ADMIN),
            add_organisation_body(),
            403,
            FORBIDDEN,
            id="pharmacy admin, doctor",
        ),
        pytest.param(
            auth_header(UserRole.HOSPITAL_ADMIN),
            add_organisation_body(),
            403,
            FORBIDDEN,
            id="admin naming another organisation",
        ),
        pytest.param(
            auth_header(UserRole.HOSPITAL_ADMIN, organisation_id=""),
            add_organisation_body(ORGANISATION_ID),
            403,
            FORBIDDEN,
            id="admin token without organisation",
        ),
        pytest.param(
            auth_header(UserRole.SUPER_ADMIN),
            add_organisation_body(role=UserRole.PATIENT),
            400,
            messages.NOT_ORGANISATION_ROLE.body(),
            id="patient role",
        ),
        pytest.param(
            auth_header(UserRole.SUPER_ADMIN),
            add_organisation_body(email=""),
            400,
            messages.EMAIL_REQUIRED.body(),
            id="no email",
        ),
        pytest.param(
            auth_header(UserRole.SUPER_ADMIN),
            {k: v for k, v in add_organisation_body().items() if k != "organisationId"},
            400,
            ORGANISATION_ID_REQUIRED,
            id="super admin naming no organisation",
        ),
        pytest.param(
            auth_header(UserRole.SUPER_ADMIN),
            add_organisation_body("abc"),
            400,
            messages.INVALID_REQUEST_BODY.body(),
            id="malformed organisation",
        ),
    ],
)
def test_add_to_organisation_refuses(user_client, db, headers, body, expected_status, expected):
    create_doctor(user_client, db)

    resp = user_client.post(ADD_ORGANISATION, json=body, headers=headers)

    assert resp.status_code == expected_status
    if expected is not None:
        assert resp.json() == expected
    assert memberships(db) == [("user2@example.com", ORGANISATION_ID)]


# --- Emails and names are stored in lower case ---


def test_create_user_stores_email_and_names_in_lower_case(user_client, db, mailer):
    body = {
        **NEW_PATIENT,
        "email": "Sam.Example@EXAMPLE.com",
        "firstName": "ÉLODIE",
        "lastName": "McOrsted",
        "nationalID": "AB-12",
    }

    resp = user_client.post(USERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 200
    with db() as session:
        (user,) = User.get_users(session)
    assert (user.email, user.first_name, user.last_name) == (
        "sam.example@example.com",
        "élodie",
        "mcorsted",
    )
    assert user.national_id == "AB-12"  # identifiers keep their case
    assert user.contact["address"]["state"] == "EX"
    assert role_accounts(db) == [("sam.example@example.com", UserRole.PATIENT)]
    recipient, token = mailer.sent[0]
    assert recipient == "sam.example@example.com"
    assert validate_token(token, TokenPurpose.EMAIL_CONFIRMATION).email == recipient


def test_emails_differing_only_in_case_are_one_email(user_client, db):
    first = user_client.post(
        USERS,
        json={**NEW_PATIENT, "email": "Sam@Example.com"},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )
    second = user_client.post(
        USERS,
        json={**NEW_PATIENT, "email": "sam@example.com"},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert first.status_code == 200
    assert second.status_code == 409
    assert second.json() == ACCOUNT_EXISTS


def test_provider_emails_differing_only_in_case_are_one_login(user_client, db):
    create_doctor(user_client, db)

    resp = user_client.post(
        PROVIDERS,
        json={**provider_body(insert_user(db, "user4@example.com")), "email": "USER2@example.com"},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert resp.status_code == 409
    assert resp.json() == ACCOUNT_EXISTS
    assert role_accounts(db) == [("user2@example.com", UserRole.DOCTOR)]


def test_every_write_path_stores_lower_case(db):
    # Not only the API: the model lowers emails and names on any write, e.g. the seed script.
    with db.begin() as session:
        create_sample_users(session)
        session.add(RoleAccount(user_id=uuid.uuid4(), email="Seed@Example.COM", role="doctor"))

    with db() as session:
        users = User.get_users(session)
    assert {u.first_name for u in users} == {"sample"}
    assert {u.last_name for u in users} == {"patient", "doctor", "pharmacist"}
    assert role_accounts(db) == [("seed@example.com", "doctor")]


def test_confirmation_link_with_mixed_case_email_still_confirms(user_client, db, mailer):
    # Links emailed before emails were lower-cased carry the case that was typed.
    user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))
    claims = validate_token(mailer.sent[0][1], TokenPurpose.EMAIL_CONFIRMATION)
    token = confirmation_token(
        email=claims.email.upper(),
        user_id=claims.user_id,
        role_account_id=claims.role_account_id,
        role=claims.role,
    )

    resp = user_client.get(f"{USERS}/confirm", params={"token": token})

    assert resp.status_code == 200
    with db() as session:
        assert session.scalars(select(RoleAccount.is_confirmed)).one() is True


@pytest.mark.parametrize("path", [PROVIDERS, ADD_ORGANISATION])
def test_admin_token_without_organisation_naming_none_is_forbidden(user_client, db, path):
    if path == ADD_ORGANISATION:
        create_doctor(user_client, db)
        body = add_organisation_body()
    else:
        body = provider_body(insert_user(db))
    del body["organisationId"]
    before = memberships(db)

    resp = user_client.post(
        path, json=body, headers=auth_header(UserRole.HOSPITAL_ADMIN, organisation_id="")
    )

    assert resp.status_code == 403
    assert resp.json() == FORBIDDEN
    assert memberships(db) == before


# --- GET /health-tech/user: who may list users ---


def signed_in_token(user_client, auth_client, mailer, role: str, email: str) -> str:
    """Create, confirm and sign in a login of role through the API; return its access token."""
    user_client.post(
        USERS,
        json={**NEW_PATIENT, "email": email, "role": role},
        headers=auth_header("super_admin"),
    )
    user_client.get(f"{USERS}/confirm", params={"token": mailer.sent[-1][1]})
    resp = auth_client.post(
        "/health-tech/auth/signin",
        json={"email": email, "password": NEW_PATIENT["password"], "role": role},
    )
    assert resp.status_code == 200
    return resp.json()["token"]


def test_list_users_without_token_is_unauthorized(user_client, db):
    insert_users(db, 3)

    resp = user_client.get(USERS)

    assert resp.status_code == 401
    assert resp.json() == {"code": "unauthorized", "error": "Unauthorized"}


def test_list_users_with_patient_token_is_unauthorized(user_client, auth_client, db, mailer):
    insert_users(db, 3)
    token = signed_in_token(user_client, auth_client, mailer, UserRole.PATIENT, "pat@example.com")

    resp = user_client.get(USERS, headers={"X-USER-TOKEN": token})

    assert resp.status_code == 401
    assert resp.json() == {
        "code": "role_not_allowed",
        "error": "this role is not allowed to use this endpoint",
    }


def test_list_users_with_super_admin_token_is_ok(user_client, auth_client, db, mailer):
    insert_users(db, 3)
    token = signed_in_token(
        user_client, auth_client, mailer, UserRole.SUPER_ADMIN, "root@example.com"
    )

    resp = user_client.get(USERS, headers={"X-USER-TOKEN": token})

    assert resp.status_code == 200
    assert resp.json()["total"] == 4  # the three users and the super admin's own
    assert len(resp.json()["users"]) == 4


# --- 150 users, a request for 500 ---


def test_asking_for_500_of_150_users_returns_100_without_national_ids(user_client, db):
    ids = insert_users(db, 150)
    with db() as session:
        national_ids = {user.national_id for user in User.get_users(session)}
    assert len(national_ids) == 150

    resp = user_client.get(
        USERS, params={"pageSize": 500}, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["users"]) == 100
    assert body["total"] == 150
    assert (body["page"], body["pageSize"], body["totalPages"]) == (1, 100, 2)
    assert [user["id"] for user in body["users"]] == [str(i) for i in ids[:100]]
    for user in body["users"]:
        assert "nationalID" not in user
    for national_id in national_ids:
        assert national_id not in resp.text


def test_second_page_of_oversized_request_holds_the_other_50_users(user_client, db):
    ids = insert_users(db, 150)

    resp = user_client.get(
        USERS, params={"page": 2, "pageSize": 500}, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 200
    assert [user["id"] for user in resp.json()["users"]] == [str(i) for i in ids[100:]]
    assert all("nationalID" not in user for user in resp.json()["users"])


@pytest.mark.parametrize(
    ("asked", "used"),
    [("1", 1), ("100", 100), ("101", 100), ("500", 100), ("9" * 30, 100)],
)
def test_page_size_is_capped_at_the_maximum(user_client, db, asked, used):
    insert_users(db, 120)

    resp = user_client.get(
        USERS, params={"pageSize": asked}, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 200
    assert resp.json()["pageSize"] == used
    assert len(resp.json()["users"]) == used


def test_one_record_still_shows_its_national_id(user_client, db):
    (user_id,) = insert_users(db, 1)

    resp = user_client.get(user_url(user_id), headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.json()["nationalID"] == "000000-0000"


# --- Provider body validation ---


@pytest.mark.parametrize(
    ("override", "expected"),
    [
        pytest.param({"email": ""}, messages.EMAIL_REQUIRED.body(), id="no email"),
        pytest.param({"userId": str(NIL_UUID)}, messages.USER_ID_REQUIRED.body(), id="no user"),
        pytest.param({"password": ""}, messages.PASSWORD_REQUIRED.body(), id="no password"),
        pytest.param({"role": "nurse"}, messages.NOT_PROVIDER_ROLE.body(), id="unknown role"),
    ],
)
def test_create_provider_rejects_incomplete_body(user_client, db, mailer, override, expected):
    body = provider_body(insert_user(db)) | override

    resp = user_client.post(PROVIDERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert resp.json() == expected
    assert role_accounts(db) == []
    assert memberships(db) == []
    assert mailer.sent == []


# --- Failures while creating logins and memberships ---


def token_failure(*args, **kwargs):
    raise TokenError("cannot sign")


def db_failure(*args, **kwargs):
    raise OperationalError("SELECT", {}, Exception(DB_ERROR))


def test_create_user_token_failure_creates_nothing(user_client, db, mailer, monkeypatch):
    monkeypatch.setattr(user_service, "generate_token", token_failure)

    resp = user_client.post(USERS, json=NEW_PATIENT, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 500
    with db() as session:
        assert User.get_users(session) == []
    assert role_accounts(db) == []
    assert mailer.sent == []


def test_create_provider_token_failure_creates_nothing(user_client, db, mailer, monkeypatch):
    user_id = insert_user(db)
    monkeypatch.setattr(user_service, "generate_token", token_failure)

    resp = user_client.post(
        PROVIDERS, json=provider_body(user_id), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    assert role_accounts(db) == []
    assert memberships(db) == []
    assert mailer.sent == []


@pytest.mark.parametrize("path", [USERS, PROVIDERS])
def test_email_role_check_failure_is_internal_error(user_client, db, mailer, monkeypatch, path):
    body = NEW_PATIENT if path == USERS else provider_body(insert_user(db))
    monkeypatch.setattr(RoleAccount, "email_role_taken", db_failure)

    resp = user_client.post(path, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert DB_ERROR not in resp.text
    assert role_accounts(db) == []
    assert mailer.sent == []


@pytest.mark.parametrize("path", [USERS, PROVIDERS])
def test_failed_recheck_after_integrity_error_is_internal_error(
    user_client, db, mailer, monkeypatch, path
):
    # The insert fails on a constraint and the recheck cannot reach the database:
    # nothing shows the pair is taken, so this is not reported as a conflict.
    body = NEW_PATIENT if path == USERS else provider_body(insert_user(db))
    checks = []

    def check(cls, session, *, email, role):
        checks.append(role)
        if len(checks) == 1:
            return False
        raise OperationalError("SELECT", {}, Exception(DB_ERROR))

    monkeypatch.setattr(RoleAccount, "email_role_taken", classmethod(check))
    monkeypatch.setattr(RoleAccount, "create_new_user_account", integrity_error)

    resp = user_client.post(path, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert len(checks) == 2
    assert mailer.sent == []


def test_add_to_organisation_database_error_is_internal_error(user_client, db, monkeypatch):
    create_doctor(user_client, db)
    monkeypatch.setattr(OrganisationMembership, "is_member", db_failure)

    resp = user_client.post(
        ADD_ORGANISATION, json=add_organisation_body(), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert DB_ERROR not in resp.text
    assert memberships(db) == [("user2@example.com", ORGANISATION_ID)]


def test_add_to_organisation_other_integrity_error_is_internal_error(user_client, db, monkeypatch):
    # Not a membership another request added: the recheck finds none.
    create_doctor(user_client, db)
    monkeypatch.setattr(OrganisationMembership, "add", integrity_error)

    resp = user_client.post(
        ADD_ORGANISATION, json=add_organisation_body(), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert memberships(db) == [("user2@example.com", ORGANISATION_ID)]


def test_add_to_organisation_failed_recheck_is_internal_error(user_client, db, monkeypatch):
    create_doctor(user_client, db)
    real = RoleAccount.get_by_email_and_role.__func__
    lookups = []

    def lookup(cls, session, **kwargs):
        lookups.append(kwargs)
        if len(lookups) == 1:
            return real(cls, session, **kwargs)
        raise OperationalError("SELECT", {}, Exception(DB_ERROR))

    monkeypatch.setattr(RoleAccount, "get_by_email_and_role", classmethod(lookup))
    monkeypatch.setattr(OrganisationMembership, "add", integrity_error)

    resp = user_client.post(
        ADD_ORGANISATION, json=add_organisation_body(), headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 500
    assert resp.json() == INTERNAL_SERVER_ERROR
    assert len(lookups) == 2
