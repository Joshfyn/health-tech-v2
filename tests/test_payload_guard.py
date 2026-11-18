"""The payload guard: unsafe request bodies are refused before any route, auth check or model."""

import logging

import pytest
from sqlalchemy import select

from health_tech.auth.model import Auth
from health_tech.lib import errors
from health_tech.lib.payload_guard import MAX_BODY_BYTES, MAX_DEPTH
from health_tech.lib.safe_text import unsafe_reason
from health_tech.logger import _TextFormatter
from health_tech.user.model import RoleAccount, User, UserRole
from tests.conftest import auth_header
from tests.test_user import NEW_PATIENT

USERS = "/health-tech/user"
SIGN_IN = "/health-tech/auth/signin"
UNSAFE = {"code": "unsafe_input", "error": errors.UNSAFE_INPUT.for_field("request").message}

UNSAFE_VALUES = [
    # HTML and script
    pytest.param("<html>example_name</>", id="html"),
    pytest.param("<script>alert(1)</script>", id="script tag"),
    pytest.param("<img src=x onerror=alert(1)>", id="img onerror"),
    pytest.param("Sam &lt;b&gt;", id="html entity"),
    pytest.param("javascript:alert(1)", id="javascript scheme"),
    pytest.param("data:text/html,hi", id="data scheme"),
    # SQL
    pytest.param("' OR '1'='1", id="tautology"),
    pytest.param("x' or 1", id="or without equals"),
    pytest.param("admin'--", id="comment"),
    pytest.param("1; DROP TABLE users", id="statement separator"),
    pytest.param("drop table users", id="drop table"),
    pytest.param("x UNION SELECT password FROM role_accounts", id="union select"),
    pytest.param("select name from users", id="select from"),
    pytest.param("insert into users values (1)", id="insert into"),
    pytest.param("delete from users", id="delete from"),
    pytest.param("update users set email", id="update set"),
    pytest.param("pg_sleep(10)", id="pg_sleep"),
    pytest.param("waitfor delay 0", id="waitfor"),
    pytest.param("ＵＮＩＯＮ ＳＥＬＥＣＴ", id="full-width union select"),
    # Links
    pytest.param("https://evil.example", id="https"),
    pytest.param("http://evil.example", id="http"),
    pytest.param("ftp://evil.example", id="ftp"),
    pytest.param("see www.evil.example", id="www"),
    # Characters that are neither text nor digits
    pytest.param("Sam 😀", id="emoji"),
    pytest.param("Sam\x00", id="nul"),
    pytest.param("Sam\nSmith", id="newline"),
    pytest.param("Sam\u200bSmith", id="zero-width space"),
    pytest.param('Sam "the man"', id="double quote"),
    pytest.param("a=b", id="equals"),
    pytest.param("100%", id="percent"),
    pytest.param("${jndi:x}", id="template"),
    pytest.param("a\\b", id="backslash"),
    pytest.param("a|b", id="pipe"),
    pytest.param("`id`", id="backtick"),
]

SAFE_VALUES = [
    "Sam",
    "O'Brien",
    "O’Brien",
    "Jean-Luc",
    "Élodie",
    "Zoë Saldaña",
    "张伟",
    "St. John",
    "12/3 Main St., Apt #4",
    "+1 (555) 010-0000",
    "1990-05-15T00:00:00Z",
    "sam_x+tag@example.com",
    "user@www.example.com",
    "Union Street",
    "Select",
    "Drop Lane",
    "000000-0000",
]


@pytest.mark.parametrize("value", UNSAFE_VALUES)
def test_unsafe_text_is_refused(value):
    assert unsafe_reason(value) is not None


@pytest.mark.parametrize("value", SAFE_VALUES)
def test_real_names_addresses_and_ids_are_safe(value):
    assert unsafe_reason(value) is None


def test_the_example_from_the_requirement_is_refused_early(user_client, db):
    # "user" is not a field of any request: the guard checks fields no route knows too.
    resp = user_client.post(
        USERS,
        json={**NEW_PATIENT, "user": "<html>example_name</>"},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert resp.status_code == 400
    assert resp.json() == UNSAFE
    with db() as session:
        assert User.get_users(session) == []


@pytest.mark.parametrize("value", UNSAFE_VALUES)
@pytest.mark.parametrize(
    "place",
    ["firstName", "unknown field", "nested street", "list item"],
)
def test_unsafe_value_anywhere_in_the_body_is_refused(user_client, db, mailer, value, place):
    body = dict(NEW_PATIENT)
    match place:
        case "firstName":
            body["firstName"] = value
        case "unknown field":
            body["nickname"] = value
        case "nested street":
            body["contact"] = {"address": {"street": value}}
        case "list item":
            body["tags"] = ["ok", {"deeper": [value]}]

    resp = user_client.post(USERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 400
    assert resp.json() == UNSAFE
    assert mailer.sent == []
    with db() as session:
        assert User.get_users(session) == []


@pytest.mark.parametrize("key", ["<b>", "first name", "a;b", "x" * 65, "1abc", ""])
def test_keys_must_be_field_names(user_client, key):
    resp = user_client.post(
        USERS, json={**NEW_PATIENT, key: "x"}, headers=auth_header(UserRole.SUPER_ADMIN)
    )

    assert resp.status_code == 400
    assert resp.json() == UNSAFE


def test_a_key_sent_twice_is_checked_both_times(user_client):
    # json.loads keeps the last value; the first must not slip through unchecked.
    body = b'{"firstName": "<b>x</b>", "firstName": "Sam"}'

    resp = user_client.post(
        USERS,
        content=body,
        headers={**auth_header(UserRole.SUPER_ADMIN), "Content-Type": "application/json"},
    )

    assert resp.json() == UNSAFE


def test_callers_without_access_are_refused_before_their_body_is_checked(user_client):
    # Access control runs before the guard: the body of an unauthorized caller is not read.
    for headers in ({}, auth_header(UserRole.DOCTOR)):
        resp = user_client.post(USERS, json={"user": "<html>example_name</>"}, headers=headers)

        assert resp.status_code == 401


def test_unsafe_sign_in_is_refused_before_any_account_lookup(auth_client, monkeypatch):
    lookups = []
    monkeypatch.setattr(Auth, "get_user_by_email_and_role", lambda *a: lookups.append(a))

    resp = auth_client.post(
        SIGN_IN, json={"email": "admin'--@example.com", "password": "x", "role": "patient"}
    )

    assert resp.status_code == 400
    assert resp.json() == UNSAFE
    assert lookups == []


@pytest.mark.parametrize("password", ["<p@ss>;'--\"", "pass word = 100%!", "🔑🔑🔑🔑🔑🔑🔑🔑"])
def test_passwords_may_hold_any_character(user_client, auth_client, mailer, password):
    # Passwords are hashed, never shown and never in a query: limiting them only weakens them.
    created = user_client.post(
        USERS, json={**NEW_PATIENT, "password": password}, headers=auth_header("super_admin")
    )
    user_client.get(f"{USERS}/confirm", params={"token": mailer.sent[0][1]})

    signed_in = auth_client.post(
        SIGN_IN, json={"email": NEW_PATIENT["email"], "password": password, "role": "patient"}
    )

    assert created.status_code == 200
    assert signed_in.status_code == 200


def test_a_password_field_holding_an_object_is_still_checked(user_client):
    resp = user_client.post(
        USERS,
        json={**NEW_PATIENT, "password": {"x": "<script>"}},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    assert resp.json() == UNSAFE


@pytest.mark.parametrize("value", SAFE_VALUES)
def test_safe_values_reach_the_route(user_client, db, value):
    # In the street, which takes free text; the route stores it unchanged.
    body = {**NEW_PATIENT, "contact": {"address": {"street": value}}}

    resp = user_client.post(USERS, json=body, headers=auth_header(UserRole.SUPER_ADMIN))

    assert resp.status_code == 200
    with db() as session:
        assert session.scalars(select(User.contact)).one()["address"]["street"] == value


# --- Bodies that are not reasonable JSON ---


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(b"{not json", id="not json"),
        pytest.param(b'{"a": NaN}', id="NaN"),
        pytest.param(b'{"a": Infinity}', id="Infinity"),
        pytest.param(b'{"a": 1e999}', id="overflows to infinity"),
        pytest.param(b'{"a": "\xff"}', id="not utf-8"),
        pytest.param(b"[" * (MAX_DEPTH + 2) + b"]" * (MAX_DEPTH + 2), id="nested too deeply"),
        # Parses, but far deeper than the recursion limit: the depth cap stops the walk first.
        pytest.param(b"[" * 30_000 + b"]" * 30_000, id="nesting bomb"),
        pytest.param(b'{"a": ' + b"9" * 5000 + b"}", id="integer too long to parse"),
    ],
)
def test_malformed_body_is_invalid(user_client, content):
    resp = user_client.post(
        USERS,
        content=content,
        headers={**auth_header(UserRole.SUPER_ADMIN), "Content-Type": "application/json"},
    )

    assert resp.status_code == 400
    assert resp.json() == errors.INVALID_REQUEST_BODY.body()


def test_body_larger_than_the_limit_is_refused(user_client):
    content = b'{"a": "' + b"x" * MAX_BODY_BYTES + b'"}'

    resp = user_client.post(
        USERS,
        content=content,
        headers={**auth_header(UserRole.SUPER_ADMIN), "Content-Type": "application/json"},
    )

    assert resp.status_code == 413
    assert resp.json() == errors.PAYLOAD_TOO_LARGE.body()


def test_empty_body_reaches_the_route(auth_client):
    resp = auth_client.post(SIGN_IN)

    assert resp.json() == errors.INVALID_REQUEST_BODY.body()  # the route's own answer


# --- What is logged ---


@pytest.fixture
def service_log():
    """Lines the user service logs, formatted as in production."""
    lines: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record):
            lines.append(self.format(record))

    handler = Collect()
    handler.setFormatter(_TextFormatter())
    logger = logging.getLogger("health_tech")
    logger.addHandler(handler)
    yield lines
    logger.removeHandler(handler)


def test_refusal_is_logged_with_where_and_why_but_not_the_value(user_client, service_log):
    secret = "<b>do-not-log-this</b>"

    user_client.post(
        USERS,
        json={"contact": {"address": {"street": secret}}},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    (line,) = [line for line in service_log if "Request refused" in line]
    assert "code=unsafe_input" in line
    assert "$.contact.address.street" in line
    assert "U+003C" in line  # the character that was refused
    assert "do-not-log-this" not in "\n".join(service_log)


def test_refused_keys_cannot_forge_log_lines(user_client, service_log):
    user_client.post(USERS, json={"x\nlevel=error msg=forged": "y"})

    assert all("\n" not in line for line in service_log)
    assert not any(line.startswith("level=error") for line in service_log)


def test_role_accounts_are_untouched_by_refused_requests(user_client, db):
    user_client.post(
        "/health-tech/user/healthcare-providers",
        json={"email": "a@example.com", "role": "doctor<script>", "password": "longenough"},
        headers=auth_header(UserRole.SUPER_ADMIN),
    )

    with db() as session:
        assert session.scalars(select(RoleAccount)).all() == []
