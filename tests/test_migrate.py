import os
import subprocess
import sys
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, insert, inspect, make_url, select, update
from sqlalchemy.exc import IntegrityError

from health_tech.lib.db import Base
from health_tech.lib.ids import NIL_UUID
from health_tech.migrate import migrations
from health_tech.migrate.migrations import MigrationError, run_migrations
from health_tech.user.model import (
    MEMBERSHIP_UNIQUE,
    ORGANISATION_MEMBERSHIPS_TABLE,
    ROLE_ACCOUNT_EMAIL_ROLE_UNIQUE,
    RoleAccount,
    User,
)
from tests.conftest import create_legacy_role_accounts

ACCOUNTS = RoleAccount.__table__
MIGRATION = "20261114170306_role_account_id_not_nil.sql"
EMAIL_ROLE_MIGRATION = "20261117201625_role_accounts_email_role_unique.sql"
LOWERCASE_MIGRATION = "20261117204659_lowercase_emails_and_names.sql"
MIGRATIONS = [MIGRATION, EMAIL_ROLE_MIGRATION, LOWERCASE_MIGRATION]


@pytest.fixture(params=["sqlite", "postgresql"])
def engine(request, tmp_path) -> Iterator[Engine]:
    """Empty database. PostgreSQL runs only when TEST_POSTGRES_URL is set."""
    if request.param == "sqlite":
        engine = create_engine(f"sqlite:///{tmp_path}/migrate.db")
        yield engine
        engine.dispose()
        return

    admin_url = os.environ.get("TEST_POSTGRES_URL")
    if not admin_url:
        pytest.skip("set TEST_POSTGRES_URL to run against PostgreSQL")
    name = f"health_tech_test_{uuid.uuid4().hex}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.exec_driver_sql(f'CREATE DATABASE "{name}"')
    engine = create_engine(make_url(admin_url).set(database=name))
    yield engine
    engine.dispose()
    with admin.connect() as conn:
        conn.exec_driver_sql(f'DROP DATABASE "{name}"')
    admin.dispose()


@pytest.fixture
def legacy_engine(engine) -> Engine:
    create_legacy_role_accounts(engine)
    return engine


@pytest.fixture
def new_engine(engine) -> Engine:
    Base.metadata.create_all(engine)
    return engine


def add_account(
    engine: Engine, email: str, role_account_id: uuid.UUID | None, role: str = "patient"
) -> None:
    with engine.begin() as conn:
        conn.execute(
            insert(ACCOUNTS).values(
                role_account_id=role_account_id,
                user_id=uuid.uuid4(),
                email=email,
                role=role,
                is_active=True,
                is_confirmed=True,
                confirmation_token="",
                password_hash="",
            )
        )


def account_ids(engine: Engine) -> dict[str, uuid.UUID]:
    with engine.connect() as conn:
        rows = conn.execute(select(ACCOUNTS.c.email, ACCOUNTS.c.role_account_id)).all()
    return {email: account_id for email, account_id in rows}


def test_migration_gives_each_account_without_id_its_own_id(legacy_engine):
    existing_id = uuid.uuid4()
    add_account(legacy_engine, "user1@example.com", NIL_UUID)
    add_account(legacy_engine, "user2@example.com", NIL_UUID)
    add_account(legacy_engine, "user3@example.com", existing_id)

    assert run_migrations(legacy_engine) == MIGRATIONS

    ids = account_ids(legacy_engine)
    assert ids["user3@example.com"] == existing_id
    assert NIL_UUID not in ids.values()
    assert len(set(ids.values())) == 3
    assert ids["user1@example.com"].version == ids["user2@example.com"].version == 4


def test_migration_is_safe_to_rerun(legacy_engine):
    add_account(legacy_engine, "user1@example.com", NIL_UUID)
    run_migrations(legacy_engine)
    before = account_ids(legacy_engine)

    assert run_migrations(legacy_engine) == MIGRATIONS

    assert account_ids(legacy_engine) == before


def test_migration_runs_on_new_database(new_engine):
    add_account(new_engine, "user1@example.com", uuid.uuid4())
    before = account_ids(new_engine)

    assert run_migrations(new_engine) == MIGRATIONS

    assert account_ids(new_engine) == before


def write_nil_id(engine: Engine, operation: str) -> None:
    match operation:
        case "insert nil":
            add_account(engine, "user9@example.com", NIL_UUID)
        case "insert null":
            add_account(engine, "user9@example.com", None)
        case "update to nil" | "update to null":
            value = NIL_UUID if operation == "update to nil" else None
            with engine.begin() as conn:
                conn.execute(update(ACCOUNTS).values(role_account_id=value))


WRITES = ["insert nil", "insert null", "update to nil", "update to null"]


@pytest.mark.parametrize("operation", WRITES)
def test_migrated_database_rejects_account_without_id(legacy_engine, operation):
    add_account(legacy_engine, "user1@example.com", NIL_UUID)
    run_migrations(legacy_engine)
    before = account_ids(legacy_engine)

    with pytest.raises(IntegrityError):
        write_nil_id(legacy_engine, operation)

    assert account_ids(legacy_engine) == before


@pytest.mark.parametrize("operation", WRITES)
def test_new_database_rejects_account_without_id(new_engine, operation):
    add_account(new_engine, "user1@example.com", uuid.uuid4())
    before = account_ids(new_engine)

    with pytest.raises(IntegrityError):
        write_nil_id(new_engine, operation)

    assert account_ids(new_engine) == before


def test_failed_migration_is_rolled_back(legacy_engine, monkeypatch):
    add_account(legacy_engine, "user1@example.com", NIL_UUID)
    broken = "UPDATE role_accounts SET email = 'changed@example.com';\nSELECT * FROM no_such_table;"
    monkeypatch.setattr(migrations, "migration_scripts", lambda _: [("broken.sql", broken)])

    with pytest.raises(MigrationError, match="broken.sql"):
        run_migrations(legacy_engine)

    assert list(account_ids(legacy_engine)) == ["user1@example.com"]


def test_sqlite_and_postgresql_have_the_same_migrations():
    sqlite = [name for name, _ in migrations.migration_scripts("sqlite")]
    postgresql = [name for name, _ in migrations.migration_scripts("postgresql")]

    assert sqlite == postgresql


@pytest.mark.parametrize(
    "name",
    [
        "001_role_account_id_not_nil.sql",
        "2026-11-14_x.sql",
        "20261114170306.sql",
        "2026111417_x.sql",
    ],
)
def test_script_without_timestamp_name_is_rejected(tmp_path, monkeypatch, name):
    (tmp_path / "sql" / "sqlite").mkdir(parents=True)
    (tmp_path / "sql" / "sqlite" / name).write_text("SELECT 1;")
    monkeypatch.setattr(migrations.resources, "files", lambda _: tmp_path)

    with pytest.raises(MigrationError, match="YYYYMMDDHHMMSS"):
        migrations.migration_scripts("sqlite")


def test_scripts_run_in_timestamp_order(tmp_path, monkeypatch):
    folder = tmp_path / "sql" / "sqlite"
    folder.mkdir(parents=True)
    names = ["20270101000000_c.sql", "20261114170306_a.sql", "20261201093000_b.sql"]
    for name in names:
        (folder / name).write_text("SELECT 1;")
    monkeypatch.setattr(migrations.resources, "files", lambda _: tmp_path)

    assert [name for name, _ in migrations.migration_scripts("sqlite")] == sorted(names)


def test_unknown_database_has_no_migrations():
    with pytest.raises(MigrationError, match="no migrations"):
        migrations.migration_scripts("oracle")


def test_migrate_db_command_works_on_empty_database(tmp_path):
    url = f"sqlite:///{tmp_path}/empty.db"
    env = {**os.environ, "DATABASE_URL": url, "ENV": ""}

    result = subprocess.run(
        [sys.executable, "-m", "health_tech.migrate.migrations"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert result.stdout == "".join(f"Applied {name}\n" for name in MIGRATIONS)
    migrated = create_engine(url)
    with pytest.raises(IntegrityError):
        add_account(migrated, "user1@example.com", NIL_UUID)
    add_account(migrated, "user1@example.com", uuid.uuid4())
    with pytest.raises(IntegrityError):
        add_account(migrated, "user1@example.com", uuid.uuid4())


# --- One login per email and role ---


def email_role_index(engine: Engine) -> dict | None:
    """The unique email-and-role index of role_accounts, if there is one."""
    for index in inspect(engine).get_indexes(ACCOUNTS.name):
        if index["name"] == ROLE_ACCOUNT_EMAIL_ROLE_UNIQUE:
            return index
    return None


def accounts(engine: Engine) -> list[tuple[str, str]]:
    with engine.connect() as conn:
        rows = conn.execute(select(ACCOUNTS.c.email, ACCOUNTS.c.role)).all()
    return sorted((email, role) for email, role in rows)


def test_migrated_and_new_databases_have_the_same_email_role_index(legacy_engine, tmp_path):
    assert email_role_index(legacy_engine) is None
    run_migrations(legacy_engine)

    new = create_engine(f"sqlite:///{tmp_path}/new.db")
    Base.metadata.create_all(new)

    for engine in (legacy_engine, new):
        index = email_role_index(engine)
        assert index is not None
        assert index["column_names"] == ["email", "role"]
        assert index["unique"]
    new.dispose()


@pytest.fixture(params=["migrated", "new"])
def guarded_engine(request, engine) -> Engine:
    """Database with the email-and-role rule, from migrate-db or from create_all."""
    if request.param == "migrated":
        create_legacy_role_accounts(engine)
        run_migrations(engine)
    else:
        Base.metadata.create_all(engine)
    return engine


def test_database_rejects_second_login_with_same_email_and_role(guarded_engine):
    add_account(guarded_engine, "user1@example.com", uuid.uuid4())

    with pytest.raises(IntegrityError):
        add_account(guarded_engine, "user1@example.com", uuid.uuid4())

    assert accounts(guarded_engine) == [("user1@example.com", "patient")]


def test_database_rejects_update_into_a_taken_email_and_role(guarded_engine):
    add_account(guarded_engine, "user1@example.com", uuid.uuid4())
    add_account(guarded_engine, "user2@example.com", uuid.uuid4())

    with pytest.raises(IntegrityError), guarded_engine.begin() as conn:
        conn.execute(
            update(ACCOUNTS)
            .where(ACCOUNTS.c.email == "user2@example.com")
            .values(email="user1@example.com")
        )

    assert accounts(guarded_engine) == [
        ("user1@example.com", "patient"),
        ("user2@example.com", "patient"),
    ]


def test_same_email_in_other_roles_and_same_role_with_other_emails_are_allowed(guarded_engine):
    add_account(guarded_engine, "user1@example.com", uuid.uuid4(), "patient")
    add_account(guarded_engine, "user1@example.com", uuid.uuid4(), "doctor")
    add_account(guarded_engine, "user2@example.com", uuid.uuid4(), "patient")

    assert accounts(guarded_engine) == [
        ("user1@example.com", "doctor"),
        ("user1@example.com", "patient"),
        ("user2@example.com", "patient"),
    ]


def test_email_role_migration_refuses_existing_duplicates_and_changes_nothing(legacy_engine):
    add_account(legacy_engine, "user1@example.com", uuid.uuid4())
    add_account(legacy_engine, "user1@example.com", uuid.uuid4())
    before = accounts(legacy_engine)

    with pytest.raises(MigrationError, match=EMAIL_ROLE_MIGRATION):
        run_migrations(legacy_engine)

    assert accounts(legacy_engine) == before
    assert email_role_index(legacy_engine) is None


def test_email_role_migration_applies_once_duplicates_are_resolved(legacy_engine):
    add_account(legacy_engine, "user1@example.com", uuid.uuid4())
    add_account(legacy_engine, "user1@example.com", uuid.uuid4())
    with pytest.raises(MigrationError):
        run_migrations(legacy_engine)

    with legacy_engine.begin() as conn:
        kept = conn.execute(select(ACCOUNTS.c.id).order_by(ACCOUNTS.c.id).limit(1)).scalar()
        conn.execute(ACCOUNTS.delete().where(ACCOUNTS.c.id != kept))

    assert run_migrations(legacy_engine) == MIGRATIONS
    assert email_role_index(legacy_engine) is not None


# --- Emails and names in lower case ---

USERS = User.__table__


def add_user(engine: Engine, email: str, first_name: str, last_name: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            insert(USERS).values(
                id=uuid.uuid4(),
                email=email,
                first_name=first_name,
                last_name=last_name,
                contact={"address": {"state": "EX"}},
                national_id="AB-12",
            )
        )


def users(engine: Engine) -> list[tuple]:
    with engine.connect() as conn:
        rows = conn.execute(
            select(
                USERS.c.email,
                USERS.c.first_name,
                USERS.c.last_name,
                USERS.c.national_id,
                USERS.c.contact,
            )
        ).all()
    return sorted(tuple(row) for row in rows)


def test_lowercase_migration_lowers_emails_and_names_only(legacy_engine):
    add_user(legacy_engine, "Sam@Example.COM", "SAM", "McExample")
    add_user(legacy_engine, "élodie@example.com", "ÉLODIE", "ØRSTED")
    add_user(legacy_engine, "ann@example.com", "ann", "lee")
    add_account(legacy_engine, "Sam@Example.COM", uuid.uuid4(), "doctor")

    assert run_migrations(legacy_engine) == MIGRATIONS

    assert users(legacy_engine) == [
        ("ann@example.com", "ann", "lee", "AB-12", {"address": {"state": "EX"}}),
        ("sam@example.com", "sam", "mcexample", "AB-12", {"address": {"state": "EX"}}),
        ("élodie@example.com", "élodie", "ørsted", "AB-12", {"address": {"state": "EX"}}),
    ]
    assert accounts(legacy_engine) == [("sam@example.com", "doctor")]


def test_lowercase_migration_refuses_emails_that_would_collide_and_changes_nothing(
    legacy_engine,
):
    add_user(legacy_engine, "Sam@Example.com", "SAM", "EXAMPLE")
    add_account(legacy_engine, "Sam@Example.com", uuid.uuid4(), "doctor")
    add_account(legacy_engine, "sam@example.com", uuid.uuid4(), "doctor")
    users_before, accounts_before = users(legacy_engine), accounts(legacy_engine)

    with pytest.raises(MigrationError, match=LOWERCASE_MIGRATION):
        run_migrations(legacy_engine)

    # users was updated first in the same transaction; it is rolled back too.
    assert users(legacy_engine) == users_before
    assert accounts(legacy_engine) == accounts_before


def test_same_email_in_different_case_for_different_roles_is_lowered(legacy_engine):
    add_account(legacy_engine, "Sam@Example.com", uuid.uuid4(), "doctor")
    add_account(legacy_engine, "sam@example.com", uuid.uuid4(), "patient")

    assert run_migrations(legacy_engine) == MIGRATIONS

    assert accounts(legacy_engine) == [
        ("sam@example.com", "doctor"),
        ("sam@example.com", "patient"),
    ]


def test_sqlite_lower_override_does_not_outlive_the_migration(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path}/pool.db")
    Base.metadata.create_all(engine)
    run_migrations(engine)

    with engine.connect() as conn:
        # The built-in again: ASCII only.
        assert conn.exec_driver_sql("SELECT lower('ÉX')").scalar() == "Éx"
    engine.dispose()


def test_migrate_db_command_creates_the_membership_table(tmp_path):
    url = f"sqlite:///{tmp_path}/old.db"
    create_legacy_role_accounts(create_engine(url))
    env = {**os.environ, "DATABASE_URL": url, "ENV": ""}

    result = subprocess.run(
        [sys.executable, "-m", "health_tech.migrate.migrations"],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    migrated = inspect(create_engine(url))
    assert ORGANISATION_MEMBERSHIPS_TABLE in migrated.get_table_names()
    assert any(
        index["name"] == MEMBERSHIP_UNIQUE and index["unique"]
        for index in migrated.get_indexes(ORGANISATION_MEMBERSHIPS_TABLE)
    )
