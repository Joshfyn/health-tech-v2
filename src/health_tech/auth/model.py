"""Sign-in lookups over role accounts."""

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from health_tech.lib.ids import NIL_UUID
from health_tech.user.model import RoleAccount


class UserNotFoundError(LookupError):
    """No confirmed role account has the email."""


class MissingAccountIdError(ValueError):
    """The role account has no ID yet; run migrate-db."""


@dataclass(slots=True)
class Auth:
    """Credentials of a role account, loaded by email."""

    email: str
    role_account_id: str = ""
    role: str = ""
    password_hash: str = ""

    def get_user_by_email(self, session: Session) -> None:
        """Load the confirmed role account for self.email."""
        account = session.scalars(
            select(RoleAccount)
            .where(RoleAccount.email == self.email, RoleAccount.is_confirmed.is_(True))
            .limit(1)
        ).first()
        if account is None:
            raise UserNotFoundError("user not found")
        if account.role_account_id == NIL_UUID:
            raise MissingAccountIdError("role account has no id")
        self.role_account_id = str(account.role_account_id)
        self.password_hash = account.password_hash
        self.role = account.role
