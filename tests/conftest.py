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
from health_tech.user.model import (
    ORGANISATION_ROLES,
    ROLE_ACCOUNT_EMAIL_ROLE_UNIQUE,
    RoleAccount,
    User,
)
from health_tech.user.router import new_user_router
from health_tech.user.service import UserService

get_settings.cache_clear()

# The organisation test tokens for organisation roles are signed in to, unless a test says.
ORGANISATION_ID = "7d4c2e1a-3b5f-4a6e-9d8c-1f2e3a4b5c6d"
OTHER_ORGANISATION_ID = "0b9a8c7d-6e5f-4a3b-8c2d-1e0f9a8b7c6d"


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
    """Create role_accounts as it was before the not-nil rule and the email-and-role index,
    beside users, whose shape has not changed."""
    metadata = MetaData()
    User.__table__.to_metadata(metadata)
    table = RoleAccount.__table__.to_metadata(metadata)
    table.constraints = {c for c in table.constraints if not isinstance(c, CheckConstraint)}
    table.indexes = {i for i in table.indexes if i.name != ROLE_ACCOUNT_EMAIL_ROLE_UNIQUE}
    metadata.create_all(engine)


@pytest.fixture
def legacy_db(tmp_path) -> sessionmaker[Session]:
    """Database whose role_accounts table predates the migrations."""
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


def make_token(
    role: str,
    user_id: str = "",
    purpose: TokenPurpose = TokenPurpose.ACCESS,
    role_account_id: str = "",
    organisation_id: str | None = None,
) -> str:
    """Return a token for purpose. user_id is the person, role_account_id the login.

    Organisation roles are signed in to ORGANISATION_ID unless organisation_id says otherwise;
    other roles to none.
    """
    if organisation_id is None:
        organisation_id = ORGANISATION_ID if role in ORGANISATION_ROLES else ""
    return generate_token(
        TokenRequirements(
            email="admin@example.com",
            user_id=user_id,
            role_account_id=role_account_id,
            role=role,
            organisation_id=organisation_id,
        ),
        purpose,
    )


def auth_header(
    role: str, user_id: str = "", role_account_id: str = "", organisation_id: str | None = None
) -> dict[str, str]:
    """Return an X-USER-TOKEN header with an access token."""
    return {
        "X-USER-TOKEN": make_token(
            role, user_id, role_account_id=role_account_id, organisation_id=organisation_id
        )
    }


def refresh_header(role: str, user_id: str = "", role_account_id: str = "") -> dict[str, str]:
    """Return an X-REFRESH-TOKEN header with a refresh token."""
    return {
        "X-REFRESH-TOKEN": make_token(
            role, user_id, TokenPurpose.REFRESH, role_account_id=role_account_id
        )
    }
