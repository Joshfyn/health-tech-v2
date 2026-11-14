"""Database engine, sessions and the declarative base."""

from sqlalchemy import URL, create_engine, make_url
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from health_tech.lib.config import Settings, get_settings

POSTGRES_DRIVER = "postgresql+psycopg"


class Base(DeclarativeBase):
    """Declarative base for every table."""


class NotFoundError(LookupError):
    """No row matched the query."""


def database_url(settings: Settings) -> URL:
    """Return DATABASE_URL, or a PostgreSQL URL built from DB_* settings in production."""
    if settings.is_production:
        return URL.create(
            POSTGRES_DRIVER,
            username=settings.db_user,
            password=settings.db_password,
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
        )
    return make_url(settings.database_url)


def connect_to_db(settings: Settings | None = None) -> sessionmaker[Session]:
    """Connect to the database, create missing tables and return a session factory."""
    url = database_url(settings or get_settings())
    connect_args = {"check_same_thread": False} if url.get_backend_name() == "sqlite" else {}
    engine = create_engine(url, connect_args=connect_args)
    # Creates the tables of every model imported so far.
    Base.metadata.create_all(engine)
    return sessionmaker(engine, expire_on_commit=False)
