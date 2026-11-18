"""Sign-in lookups over role accounts."""

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from health_tech.lib.ids import NIL_UUID
from health_tech.user.model import OrganisationMembership, RoleAccount


class UserNotFoundError(LookupError):
    """No confirmed role account has the email and role, or it does not work for the
    organisation."""


class AmbiguousAccountError(LookupError):
    """More than one confirmed role account has the email and role."""


class MissingAccountIdError(ValueError):
    """The role account has no ID yet (run migrate-db), or is not linked to a user."""


@dataclass(slots=True)
class Auth:
    """Credentials and identity of a role account, loaded by email, role and organisation."""

    email: str
    role: str
    # Set for roles that work for organisations: the account must work for this one.
    organisation_id: uuid.UUID | None = None
    role_account_id: str = ""
    user_id: str = ""
    password_hash: str = ""

    def get_user_by_email_and_role(self, session: Session) -> None:
        """Load the one confirmed role account with self.email and self.role."""
        # Two rows are enough to tell one account from several.
        accounts = session.scalars(
            select(RoleAccount)
            .where(
                RoleAccount.email == self.email,
                RoleAccount.role == self.role,
                RoleAccount.is_confirmed.is_(True),
            )
            .limit(2)
        ).all()
        if not accounts:
            raise UserNotFoundError("user not found")
        if len(accounts) > 1:
            # Never guess which login is meant.
            raise AmbiguousAccountError("several confirmed accounts have this email and role")
        account = accounts[0]
        if account.role_account_id in (None, NIL_UUID):
            raise MissingAccountIdError("role account has no id")
        if account.user_id in (None, NIL_UUID):
            raise MissingAccountIdError("role account is not linked to a user")
        if self.organisation_id is not None and not OrganisationMembership.is_member(
            session, role_account_id=account.role_account_id, organisation_id=self.organisation_id
        ):
            raise UserNotFoundError("role account does not work for this organisation")
        # Identity claims come from the stored account, never from the request.
        self.email = account.email
        self.role_account_id = str(account.role_account_id)
        self.user_id = str(account.user_id)
        self.password_hash = account.password_hash
        self.role = account.role
