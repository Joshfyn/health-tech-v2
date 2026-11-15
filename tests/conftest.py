import os

os.environ["JWT_SECRET"] = "test-only-secret-not-used-anywhere-else-0123456789"
os.environ["MAIL_BACKEND"] = "console"
os.environ["ENV"] = ""

from collections.abc import Iterator
from dataclasses import dataclass, field

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import CheckConstraint, Engine, MetaData, create_engine
from sqlalchemy.orm import Session, sessionmaker

from health_tech import logger as clog
from health_tech.auth.router import new_auth_router
from health_tech.auth.service import AuthService
from health_tech.lib.config import Settings, get_settings
from health_tech.lib.db import connect_to_db
from health_tech.lib.tokenmaker import TokenPurpose, TokenRequirements, generate_token
from health_tech.user.model import RoleAccount
from health_tech.user.router import new_user_router
from health_tech.user.service import UserService

get_settings.cache_clear()


@dataclass
class FakeMailer:
    """Records confirmation emails instead of sending them."""

    sent: list[tuple[str, str]] = field(default_factory=list)
    error: Exception | None = None

    def send_confirmation_email(self, recipient_email: str, jwt_token: str) -> None:
        if self.error is not None:
            raise self.error
        self.sent.append((recipient_email, jwt_token))


@pytest.fixture
def db(tmp_path) -> sessionmaker[Session]:
    """Throwaway SQLite database per test."""
    return connect_to_db(Settings(_env_file=None, database_url=f"sqlite:///{tmp_path}/test.db"))


def create_legacy_role_accounts(engine: Engine) -> None:
    """Create role_accounts as it was before the not-nil rule."""
    metadata = MetaData()
    table = RoleAccount.__table__.to_metadata(metadata)
    table.constraints = {c for c in table.constraints if not isinstance(c, CheckConstraint)}
    metadata.create_all(engine)


@pytest.fixture
def legacy_db(tmp_path) -> sessionmaker[Session]:
    """Database whose role_accounts table predates the not-nil rule."""
    url = f"sqlite:///{tmp_path}/legacy.db"
    create_legacy_role_accounts(create_engine(url))
    return connect_to_db(Settings(_env_file=None, database_url=url))


@pytest.fixture
def mailer() -> FakeMailer:
    return FakeMailer()


@pytest.fixture
def user_client(db, mailer) -> Iterator[TestClient]:
    svc = UserService(db=db, logger=clog.must_new("user"), mailer=mailer)
    with TestClient(new_user_router(svc)) as client:
        yield client


@pytest.fixture
def auth_client(db) -> Iterator[TestClient]:
    svc = AuthService(db=db, logger=clog.must_new("auth"))
    with TestClient(new_auth_router(svc)) as client:
        yield client


def make_token(role: str, user_id: str = "", purpose: TokenPurpose = TokenPurpose.ACCESS) -> str:
    """Return a token for purpose."""
    return generate_token(
        TokenRequirements(email="admin@example.com", user_id=user_id, role=role), purpose
    )


def auth_header(role: str, user_id: str = "") -> dict[str, str]:
    """Return an X-USER-TOKEN header with an access token."""
    return {"X-USER-TOKEN": make_token(role, user_id)}


def refresh_header(role: str, user_id: str = "") -> dict[str, str]:
    """Return an X-REFRESH-TOKEN header with a refresh token."""
    return {"X-REFRESH-TOKEN": make_token(role, user_id, TokenPurpose.REFRESH)}
