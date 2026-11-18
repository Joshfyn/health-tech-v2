"""Apply the SQL migrations in migrate/sql/<dialect>/ in filename order."""

import re
from importlib import resources

from sqlalchemy import Engine

from health_tech.lib.db import connect_to_db
from health_tech.lib.normalize import lower_case
from health_tech.user import model as _models  # noqa: F401  registers tables for create_all

SQL_PACKAGE = "health_tech.migrate"
SQL_DIR = "sql"
# UTC creation time, then a name: 20261114170306_role_account_id_not_nil.sql
SCRIPT_NAME = re.compile(r"\d{14}_[a-z0-9_]+\.sql")


class MigrationError(Exception):
    """A migration script failed and was rolled back."""


def migration_scripts(dialect: str) -> list[tuple[str, str]]:
    """Return (filename, sql) for every script of dialect, in filename order."""
    folder = resources.files(SQL_PACKAGE) / SQL_DIR / dialect
    if not folder.is_dir():
        raise MigrationError(f"no migrations for database {dialect!r}")
    scripts = [f for f in folder.iterdir() if f.name.endswith(".sql")]
    for script in scripts:
        if not SCRIPT_NAME.fullmatch(script.name):
            raise MigrationError(f"{script.name}: name must be <YYYYMMDDHHMMSS>_<name>.sql")
    return [(f.name, f.read_text()) for f in sorted(scripts, key=lambda f: f.name)]


def run_migrations(engine: Engine) -> list[str]:
    """Apply every script, each in its own transaction; return the filenames applied."""
    applied = []
    for name, sql in migration_scripts(engine.dialect.name):
        try:
            _execute_script(engine, sql)
        except engine.dialect.loaded_dbapi.Error as exc:
            raise MigrationError(f"{name}: {exc}") from exc
        applied.append(name)
    return applied


def _unicode_lower(value: object) -> object:
    # The services' own handler, so scripts lower-case exactly as the services do.
    return lower_case(value) if isinstance(value, str) else value


def _execute_script(engine: Engine, sql: str) -> None:
    raw = engine.raw_connection()
    try:
        driver = raw.driver_connection
        if engine.dialect.name == "sqlite":
            # SQLite's lower() changes only ASCII letters; the services lower-case with Python,
            # so scripts get the same result ("ÉLODIE" -> "élodie", not "Élodie"). The
            # connection is discarded afterwards rather than pooled with the override.
            driver.create_function("lower", 1, _unicode_lower, deterministic=True)
            # sqlite3 runs one statement per execute(); executescript runs them all.
            try:
                driver.executescript(f"BEGIN;\n{sql}\nCOMMIT;")
            except Exception:
                if driver.in_transaction:
                    driver.execute("ROLLBACK")
                raise
        else:
            try:
                with raw.cursor() as cursor:
                    cursor.execute(sql)
                raw.commit()
            except Exception:
                raw.rollback()
                raise
    finally:
        if engine.dialect.name == "sqlite":
            raw.invalidate()
        raw.close()


def main() -> None:
    """Create missing tables, then apply the migrations."""
    with connect_to_db()() as session:
        engine = session.get_bind()
    try:
        applied = run_migrations(engine)
    except MigrationError as exc:
        raise SystemExit(f"Migration failed: {exc}") from exc
    for name in applied:
        print(f"Applied {name}")


if __name__ == "__main__":
    main()
