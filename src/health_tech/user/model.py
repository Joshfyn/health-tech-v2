"""User and role account tables and their queries."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    Index,
    String,
    Text,
    Uuid,
    func,
    select,
    update,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, validates

from health_tech.lib.db import Base, NotFoundError
from health_tech.lib.ids import NIL_UUID

USERS_TABLE = "users"
ROLE_ACCOUNTS_TABLE = "role_accounts"
ORGANISATION_MEMBERSHIPS_TABLE = "organisation_memberships"
ROLE_ACCOUNT_ID_NOT_NIL = "ck_role_accounts_role_account_id_not_nil"
# Sign in names an email and a role, so each pair may belong to one login only.
ROLE_ACCOUNT_EMAIL_ROLE_UNIQUE = "uq_role_accounts_email_role"
MEMBERSHIP_UNIQUE = "uq_organisation_memberships_account_organisation"
MEMBERSHIP_ORGANISATION_ID_NOT_NIL = "ck_organisation_memberships_organisation_id_not_nil"


class UserRole(StrEnum):
    """Role a role account signs in with."""

    PATIENT = "patient"
    DOCTOR = "doctor"
    PHARMACIST = "pharmacist"
    HOSPITAL_ADMIN = "hospital_admin"
    PHARMACY_ADMIN = "pharmacy_admin"
    SUPER_ADMIN = "super_admin"


# Roles that work for organisations. A person may hold one of these in several organisations,
# and signs in to one of them at a time.
ORGANISATION_ROLES = frozenset(
    {UserRole.DOCTOR, UserRole.PHARMACIST, UserRole.HOSPITAL_ADMIN, UserRole.PHARMACY_ADMIN}
)


def to_lower(value: str | None) -> str | None:
    """Emails and names are stored in lower case, so they compare without regard to case."""
    return value.lower() if value is not None else None


class EntityType(StrEnum):
    """Type of organisation a provider is affiliated with."""

    HOSPITAL = "Hospital"
    PHARMACY = "Pharmacy"


class MissingLookupKeyError(ValueError):
    """Neither an email nor an id was given for a user lookup."""


class RoleExistsError(Exception):
    """The user already holds the requested role."""


class AccountExistsError(Exception):
    """A role account with the same email and role already exists."""


class Address(BaseModel):
    """Physical address."""

    model_config = ConfigDict(populate_by_name=True)

    street: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = Field("", alias="zipCode")
    country: str = ""


class Contact(BaseModel):
    """Contact information for a user."""

    phone: str = ""
    address: Address = Field(default_factory=Address)


class User(Base):
    """A person: demographics and national ID."""

    __tablename__ = USERS_TABLE

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    email: Mapped[str] = mapped_column(String, default="", index=True)
    first_name: Mapped[str] = mapped_column(String, default="")
    last_name: Mapped[str] = mapped_column(String, default="")
    date_of_birth: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    contact: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    national_id: Mapped[str] = mapped_column(String, default="")
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    @validates("email", "first_name", "last_name")
    def _store_lower(self, _: str, value: str | None) -> str | None:
        return to_lower(value)

    def to_json(self, *, include_national_id: bool = True) -> dict[str, Any]:
        """Serialize the user with the API field names.

        Listings leave the national ID out; it is shown only when one record is read.
        """
        data: dict[str, Any] = {
            "id": str(self.id),
            "email": self.email,
            "firstName": self.first_name,
            "lastName": self.last_name,
        }
        if self.date_of_birth is not None:
            data["dateOfBirth"] = self.date_of_birth.isoformat()
        data["contact"] = self.contact
        if include_national_id:
            data["nationalID"] = self.national_id
        data |= {
            "createdAt": _isoformat(self.created_at),
            "updatedAt": _isoformat(self.updated_at),
        }
        return data

    def create_new_user(self, session: Session) -> None:
        """Insert the user within the session's transaction."""
        session.add(self)
        session.flush()

    @classmethod
    def get_users(cls, session: Session) -> list[Self]:
        """Return every user."""
        return list(session.scalars(select(cls)))

    @classmethod
    def get_users_page(cls, session: Session, *, offset: int, limit: int) -> tuple[list[Self], int]:
        """Return one page of users, oldest first, and the total number of users."""
        total = session.scalar(select(func.count()).select_from(cls)) or 0
        if offset >= total:
            # Nothing to fetch; also keeps huge page numbers away from the database.
            return [], total
        # id breaks created_at ties so every row lands on exactly one page.
        stmt = select(cls).order_by(cls.created_at, cls.id).offset(offset).limit(limit)
        return list(session.scalars(stmt)), total

    @classmethod
    def get_user(cls, session: Session, user_id: uuid.UUID) -> Self:
        """Return the user with user_id; raise NotFoundError if there is none."""
        user = session.get(cls, user_id)
        if user is None:
            raise NotFoundError("no documents in result")
        return user

    @classmethod
    def get_single_user(
        cls,
        session: Session,
        *,
        email: str = "",
        user_id: uuid.UUID = NIL_UUID,
    ) -> None:
        """Raise NotFoundError unless a user matches email and/or user_id."""
        if not email and user_id == NIL_UUID:
            raise MissingLookupKeyError("email and/or id must be provided")
        stmt = select(cls.id)
        if email:
            stmt = stmt.where(cls.email == email)
        if user_id != NIL_UUID:
            stmt = stmt.where(cls.id == user_id)
        if session.scalars(stmt.limit(1)).first() is None:
            raise NotFoundError("no documents in result")


class RoleAccount(Base):
    """One login for a user in one role."""

    __tablename__ = ROLE_ACCOUNTS_TABLE

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    role_account_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, index=True)
    email: Mapped[str] = mapped_column(String, index=True)
    role: Mapped[str] = mapped_column(String)
    is_active: Mapped[bool] = mapped_column(Boolean, default=False)
    is_confirmed: Mapped[bool] = mapped_column(Boolean, default=False)
    confirmation_token: Mapped[str] = mapped_column(Text, default="")
    password_hash: Mapped[str] = mapped_column(String, default="")
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(role_account_id != NIL_UUID, name=ROLE_ACCOUNT_ID_NOT_NIL),
        # A named unique index, not a table constraint, so new databases and migrate-db
        # create the same object and the migration is a no-op on new databases.
        Index(ROLE_ACCOUNT_EMAIL_ROLE_UNIQUE, "email", "role", unique=True),
    )

    @validates("email")
    def _store_lower(self, _: str, value: str | None) -> str | None:
        return to_lower(value)

    def create_new_user_account(self, session: Session) -> None:
        """Insert the role account within the session's transaction."""
        session.add(self)
        session.flush()

    @classmethod
    def get_by_email_and_role(cls, session: Session, *, email: str, role: str) -> Self:
        """Return the login with this email and role; raise NotFoundError if there is none."""
        stmt = select(cls).where(cls.email == to_lower(email), cls.role == role)
        account = session.scalars(stmt.limit(1)).first()
        if account is None:
            raise NotFoundError("no role account has this email and role")
        return account

    @classmethod
    def email_role_taken(cls, session: Session, *, email: str, role: str) -> bool:
        """Report whether a role account already has this email and role."""
        stmt = select(cls.id).where(cls.email == to_lower(email), cls.role == role).limit(1)
        return session.scalars(stmt).first() is not None

    @classmethod
    def get_all_user_roles(cls, session: Session, user_id: uuid.UUID) -> set[str]:
        """Return the roles the user already holds."""
        return set(session.scalars(select(cls.role).where(cls.user_id == user_id)))

    @classmethod
    def confirm_user(
        cls,
        session: Session,
        *,
        email: str,
        user_id: uuid.UUID,
        role: str,
        role_account_id: uuid.UUID | None = None,
    ) -> bool:
        """Mark the matching role account as confirmed; return whether one matched.

        role_account_id pins the exact account. Links emailed before it was added to the
        confirmation token omit it and match on email, user and role only.
        """
        stmt = update(cls).where(cls.email == email, cls.user_id == user_id, cls.role == role)
        if role_account_id is not None:
            stmt = stmt.where(cls.role_account_id == role_account_id)
        return session.execute(stmt.values(is_confirmed=True)).rowcount > 0


class OrganisationMembership(Base):
    """A role account working for an organisation. One account can have several."""

    __tablename__ = ORGANISATION_MEMBERSHIPS_TABLE

    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    role_account_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    organisation_id: Mapped[uuid.UUID] = mapped_column(Uuid, nullable=False)
    created_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    __table_args__ = (
        CheckConstraint(organisation_id != NIL_UUID, name=MEMBERSHIP_ORGANISATION_ID_NOT_NIL),
        # Also serves lookups by role account, its leading column.
        Index(MEMBERSHIP_UNIQUE, "role_account_id", "organisation_id", unique=True),
    )

    @classmethod
    def is_member(
        cls, session: Session, *, role_account_id: uuid.UUID, organisation_id: uuid.UUID
    ) -> bool:
        """Report whether the role account works for the organisation."""
        stmt = select(cls.id).where(
            cls.role_account_id == role_account_id, cls.organisation_id == organisation_id
        )
        return session.scalars(stmt.limit(1)).first() is not None

    def add(self, session: Session) -> None:
        """Insert the membership within the session's transaction."""
        session.add(self)
        session.flush()


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
