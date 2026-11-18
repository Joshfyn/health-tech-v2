"""Request rules: formats, roles, required values, lengths, dates; unknown fields dropped."""

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select

from health_tech.lib import errors
from health_tech.user.model import RoleAccount, User, UserRole
from tests.conftest import ORGANISATION_ID, auth_header
from tests.test_user import NEW_PATIENT, insert_user

USERS = "/health-tech/user"
PROVIDERS = "/health-tech/user/healthcare-providers"
ADD_ORGANISATION = f"{PROVIDERS}/organisations"
SIGN_IN = "/health-tech/auth/signin"


def create_user(client, **overrides):
    return client.post(
        USERS, json={**NEW_PATIENT, **overrides}, headers=auth_header(UserRole.SUPER_ADMIN)
    )


def stored_users(db) -> list[User]:
    with db() as session:
        return User.get_users(session)


# --- Email format ---

INVALID_EMAILS = [
    "not-an-email",
    "user@",
    "@example.com",
    "user@example",
    "user@@example.com",
    "user@example..com",
    "user.@example.com",
    ".user@example.com",
    "us..er@example.com",
    "user@-example.com",
    "user@example.c",
    "user@exam_ple.com",
    " user@example.com",
    "user@example.com ",
    "user name@example.com",
    "user@example.com,other@example.com",
    "a" * 65 + "@example.com",
    "user@" + "a" * 250 + ".com",
]


@pytest.mark.parametrize("email", INVALID_EMAILS)
def test_create_user_refuses_invalid_email(user_client, db, email):
    resp = create_user(user_client, email=email)

    assert resp.status_code == 400
    assert resp.json() == {"code": "invalid_email", "error": "email must be a valid email address"}
    assert stored_users(db) == []


@pytest.mark.parametrize("email", INVALID_EMAILS[:6])
@pytest.mark.parametrize("path", [PROVIDERS, ADD_ORGANISATION])
def test_provider_endpoints_refuse_invalid_email(user_client, db, email, path):
    body = {
        "email": email,
        "role": "doctor",
        "password": "placeholder-password",
        "userId": str(insert_user(db)),
        "organisationId": ORGANISATION_ID,
    }

    resp = user_client.post(path, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.json()["code"] == "invalid_email"


@pytest.mark.parametrize("email", INVALID_EMAILS[:6])
def test_sign_in_refuses_invalid_email(auth_client, email):
    resp = auth_client.post(SIGN_IN, json={"email": email, "password": "x", "role": "patient"})

    assert resp.status_code == 400
    assert resp.json()["code"] == "invalid_email"


@pytest.mark.parametrize(
    "email",
    ["USER1@Example.COM", "first.last+tag@sub.example.co.uk", "o'brien@example.ie", "a_b@x-y.io"],
)
def test_valid_emails_are_accepted_in_lower_case(user_client, db, email):
    resp = create_user(user_client, email=email)

    assert resp.status_code == 200
    assert [u.email for u in stored_users(db)] == [email.lower()]


# --- Roles ---


@pytest.mark.parametrize("role", ["admin", "Patient", "PATIENT", " patient", "nurse", "root"])
def test_create_user_refuses_unknown_role(user_client, db, role):
    resp = create_user(user_client, role=role)

    assert resp.status_code == 400
    assert resp.json() == {"code": "invalid_role", "error": "unknown role"}
    assert stored_users(db) == []


@pytest.mark.parametrize("role", ["", UserRole.PATIENT, UserRole.SUPER_ADMIN])
def test_create_user_accepts_the_roles_it_creates_logins_for(user_client, role):
    assert create_user(user_client, role=role).status_code == 200


@pytest.mark.parametrize("role", ["nurse", "patient", "super_admin"])
def test_create_provider_refuses_roles_that_are_not_providers(user_client, db, role):
    body = {
        "email": "user2@example.com",
        "role": role,
        "password": "placeholder-password",
        "userId": str(insert_user(db)),
        "organisationId": ORGANISATION_ID,
    }

    resp = user_client.post(PROVIDERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert resp.json() == {
        "code": "not_provider_role",
        "error": "role is not a healthcare provider role",
    }


# --- Required values ---


@pytest.mark.parametrize(
    ("missing", "expected"),
    [
        ("email", errors.EMAIL_REQUIRED),
        ("firstName", errors.FIRST_NAME_REQUIRED),
        ("lastName", errors.LAST_NAME_REQUIRED),
        ("password", errors.PASSWORD_REQUIRED),
    ],
)
@pytest.mark.parametrize("how", ["absent", "empty"])
def test_create_user_requires(user_client, db, missing, expected, how):
    body = dict(NEW_PATIENT)
    if how == "absent":
        del body[missing]
    else:
        body[missing] = ""

    resp = user_client.post(USERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert resp.json() == expected.body()
    assert stored_users(db) == []


def test_date_of_birth_and_contact_are_optional(user_client):
    body = {k: v for k, v in NEW_PATIENT.items() if k not in ("dateOfBirth", "contact")}

    resp = user_client.post(USERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 200


# --- Lengths ---


@pytest.mark.parametrize(
    ("field", "value", "shown_as"),
    [
        ("firstName", "A" * 101, "firstName"),
        ("lastName", "A" * 101, "lastName"),
        ("nationalID", "1" * 33, "nationalID"),
        ("contact", {"phone": "1" * 33}, "contact.phone"),
        ("contact", {"address": {"street": "a" * 201}}, "contact.address.street"),
        ("contact", {"address": {"city": "a" * 101}}, "contact.address.city"),
        ("contact", {"address": {"zipCode": "1" * 17}}, "contact.address.zipCode"),
    ],
)
def test_values_longer_than_their_limit_are_refused(user_client, db, field, value, shown_as):
    resp = create_user(user_client, **{field: value})

    assert resp.status_code == 400
    assert resp.json() == {"code": "value_too_long", "error": f"{shown_as} is too long"}
    assert stored_users(db) == []


def test_values_at_their_limit_are_accepted(user_client):
    resp = create_user(
        user_client,
        firstName="A" * 100,
        lastName="B" * 100,
        nationalID="1" * 32,
        contact={"phone": "1" * 32, "address": {"street": "a" * 200, "zipCode": "1" * 16}},
    )

    assert resp.status_code == 200


@pytest.mark.parametrize(
    ("password", "code"),
    [
        pytest.param("short12", "password_too_short", id="7 characters"),
        pytest.param("a" * 73, "password_too_long", id="73 bytes"),
        # 37 characters, but 74 bytes: bcrypt's limit is in bytes.
        pytest.param("é" * 37, "password_too_long", id="73+ bytes in fewer characters"),
    ],
)
@pytest.mark.parametrize("path", [USERS, PROVIDERS])
def test_new_passwords_must_fit_the_length_rule(user_client, db, password, code, path):
    body = (
        {**NEW_PATIENT, "password": password}
        if path == USERS
        else {
            "email": "user2@example.com",
            "role": "doctor",
            "password": password,
            "userId": str(insert_user(db)),
            "organisationId": ORGANISATION_ID,
        }
    )

    resp = user_client.post(path, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert resp.json()["code"] == code


@pytest.mark.parametrize("password", ["a" * 8, "a" * 72, "é" * 36])
def test_passwords_within_the_rule_are_accepted(user_client, password):
    assert create_user(user_client, password=password).status_code == 200


def test_sign_in_refuses_passwords_no_account_can_have(auth_client):
    resp = auth_client.post(
        SIGN_IN, json={"email": "a@example.com", "password": "a" * 73, "role": "patient"}
    )

    assert resp.status_code == 400
    assert resp.json()["code"] == "password_too_long"


def test_sign_in_has_no_minimum_password_length(auth_client):
    # A short wrong password is just a wrong password.
    resp = auth_client.post(
        SIGN_IN, json={"email": "a@example.com", "password": "abc", "role": "patient"}
    )

    assert resp.json() == errors.INVALID_CREDENTIALS.body()


# --- Date of birth ---


@pytest.mark.parametrize(
    "date_of_birth",
    [
        pytest.param((datetime.now(UTC) + timedelta(days=1)).isoformat(), id="tomorrow"),
        pytest.param((datetime.now(UTC) + timedelta(minutes=5)).isoformat(), id="in 5 minutes"),
        pytest.param("2999-01-01T00:00:00Z", id="far future"),
        pytest.param("1899-12-31T23:59:59Z", id="before 1900"),
        pytest.param(0, id="number"),
        pytest.param(631152000, id="unix timestamp"),
    ],
)
def test_date_of_birth_must_be_in_the_past(user_client, db, date_of_birth):
    resp = create_user(user_client, dateOfBirth=date_of_birth)

    assert resp.status_code == 400
    assert resp.json() == {
        "code": "invalid_date_of_birth",
        "error": "dateOfBirth must be a date in the past",
    }
    assert stored_users(db) == []


@pytest.mark.parametrize(
    "date_of_birth",
    ["1990-05-15", "1990-05-15T00:00:00", "1990-05-15T10:00:00+02:00", "1900-01-01T00:00:00Z"],
)
def test_past_dates_of_birth_are_accepted(user_client, date_of_birth):
    assert create_user(user_client, dateOfBirth=date_of_birth).status_code == 200


def test_date_of_birth_that_is_not_a_date_is_an_invalid_body(user_client):
    resp = create_user(user_client, dateOfBirth="yesterday")

    assert resp.json() == errors.INVALID_REQUEST_BODY.body()


# --- Emails and names are stored in lower case ---


@pytest.mark.parametrize(
    ("first", "last", "stored"),
    [
        ("Sam", "McExample", ("sam", "mcexample")),
        ("ÉLODIE", "O'Brien-Smith", ("élodie", "o'brien-smith")),
        ("ZOË", "D’Artagnan", ("zoë", "d’artagnan")),
        ("张", "伟", ("张", "伟")),  # scripts without case are unchanged
    ],
)
def test_names_are_stored_and_returned_in_lower_case(user_client, db, first, last, stored):
    create_user(user_client, firstName=first, lastName=last, email="Sam@Example.COM")

    (user,) = stored_users(db)
    resp = user_client.get(f"{USERS}/{user.id}", headers=auth_header(UserRole.SUPER_ADMIN))

    assert (user.first_name, user.last_name, user.email) == (*stored, "sam@example.com")
    assert (resp.json()["firstName"], resp.json()["lastName"], resp.json()["email"]) == (
        *stored,
        "sam@example.com",
    )


def test_what_is_not_lower_cased_keeps_its_case(user_client, db, auth_client, mailer):
    create_user(
        user_client,
        password="Case-Sensitive-PW",
        nationalID="AB-12",
        contact={"phone": "1", "address": {"street": "1 High St", "zipCode": "SW1A 1AA"}},
    )

    (user,) = stored_users(db)
    assert user.national_id == "AB-12"
    assert user.contact["address"] == {
        "street": "1 High St",
        "city": "",
        "state": "",
        "zipCode": "SW1A 1AA",
        "country": "",
    }
    # The password was hashed as given: only the exact case signs in.
    user_client.get(f"{USERS}/confirm", params={"token": mailer.sent[0][1]})
    for password, status in [("Case-Sensitive-PW", 200), ("case-sensitive-pw", 401)]:
        resp = auth_client.post(
            SIGN_IN,
            json={"email": NEW_PATIENT["email"], "password": password, "role": "patient"},
        )
        assert resp.status_code == status


def test_name_length_is_checked_on_the_lower_cased_value(user_client, db):
    # "İ" lower-cases to two characters (i + combining dot): 60 become 120, over the limit.
    resp = create_user(user_client, firstName="İ" * 60)

    assert resp.json() == errors.VALUE_TOO_LONG.for_field("firstName").body()
    assert stored_users(db) == []


@pytest.mark.parametrize(
    "name", ["Sam2", " Sam", "Sam ", "-Sam", "Sam_Smith", "Sam@Smith", "Sam/Smith", "Sam,Smith"]
)
def test_names_hold_only_letters_and_name_punctuation(user_client, db, name):
    resp = create_user(user_client, firstName=name)

    assert resp.status_code == 400
    assert resp.json() == errors.INVALID_NAME.for_field("firstName").body()
    assert stored_users(db) == []


# --- Contact details and national ID ---


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({"contact": {"phone": "call me"}}, errors.INVALID_PHONE.for_field("contact.phone")),
        ({"contact": {"phone": "+"}}, errors.INVALID_PHONE.for_field("contact.phone")),
        (
            {"contact": {"address": {"zipCode": "AB/12"}}},
            errors.INVALID_POSTAL_CODE.for_field("contact.address.zipCode"),
        ),
        ({"nationalID": "-123"}, errors.INVALID_NATIONAL_ID.for_field("nationalID")),
        ({"nationalID": "12#34"}, errors.INVALID_NATIONAL_ID.for_field("nationalID")),
    ],
)
def test_contact_details_and_national_id_follow_their_format(user_client, body, expected):
    resp = create_user(user_client, **body)

    assert resp.status_code == 400
    assert resp.json() == expected.body()


# --- Unknown fields are dropped ---


def test_unknown_fields_are_dropped_not_stored(user_client, db):
    client_id = uuid.uuid4()
    resp = create_user(
        user_client,
        id=str(client_id),
        createdAt="2000-01-01T00:00:00Z",
        isAdmin=True,
        passwordHash="x",
        contact={**NEW_PATIENT["contact"], "notes": "kept nowhere"},
    )

    assert resp.status_code == 200
    (user,) = stored_users(db)
    assert user.id != client_id
    assert user.created_at.year != 2000
    assert "notes" not in user.contact
    with db() as session:
        account = session.scalars(select(RoleAccount)).one()
    assert account.password_hash != "x"


def test_sign_in_ignores_unknown_fields(auth_client):
    resp = auth_client.post(
        SIGN_IN,
        json={"email": "a@example.com", "password": "x", "role": "patient", "isAdmin": True},
    )

    assert resp.json() == errors.INVALID_CREDENTIALS.body()
