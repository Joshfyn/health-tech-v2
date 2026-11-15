import os
import subprocess
import sys
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import Engine, create_engine, insert, make_url, select, update
from sqlalchemy.exc import IntegrityError

from health_tech.lib.db import Base
from health_tech.lib.ids import NIL_UUID
from health_tech.migrate import migrations
from health_tech.migrate.migrations import MigrationError, run_migrations
from health_tech.user.model import RoleAccount
from tests.conftest import create_legacy_role_accounts

ACCOUNTS = RoleAccount.__table__
MIGRATION = "20261114170306_role_account_id_not_nil.sql"


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


def add_account(engine: Engine, email: str, role_account_id: uuid.UUID | None) -> None:
    with engine.begin() as conn:
        conn.execute(
            insert(ACCOUNTS).values(
                role_account_id=role_account_id,
                user_id=uuid.uuid4(),
                email=email,
                role="patient",
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

    assert run_migrations(legacy_engine) == [MIGRATION]

    ids = account_ids(legacy_engine)
    assert ids["user3@example.com"] == existing_id
    assert NIL_UUID not in ids.values()
    assert len(set(ids.values())) == 3
    assert ids["user1@example.com"].version == ids["user2@example.com"].version == 4


def test_migration_is_safe_to_rerun(legacy_engine):
    add_account(legacy_engine, "user1@example.com", NIL_UUID)
    run_migrations(legacy_engine)
    before = account_ids(legacy_engine)

    assert run_migrations(legacy_engine) == [MIGRATION]

    assert account_ids(legacy_engine) == before


def test_migration_runs_on_new_database(new_engine):
    add_account(new_engine, "user1@example.com", uuid.uuid4())
    before = account_ids(new_engine)

    assert run_migrations(new_engine) == [MIGRATION]

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
    assert result.stdout == f"Applied {MIGRATION}\n"
    with pytest.raises(IntegrityError):
        add_account(create_engine(url), "user1@example.com", NIL_UUID)
