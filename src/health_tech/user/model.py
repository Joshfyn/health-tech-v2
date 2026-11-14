"""User and role account tables and their queries."""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import JSON, Boolean, DateTime, String, Text, Uuid, select, update
from sqlalchemy.orm import Mapped, Session, mapped_column

from health_tech.lib.db import Base, NotFoundError
from health_tech.lib.ids import NIL_UUID

USERS_TABLE = "users"
ROLE_ACCOUNTS_TABLE = "role_accounts"


class UserRole(StrEnum):
    """Role a role account signs in with."""

    PATIENT = "patient"
    DOCTOR = "doctor"
    PHARMACIST = "pharmacist"
    HOSPITAL_ADMIN = "hospital_admin"
    PHARMACY_ADMIN = "pharmacy_admin"
    SUPER_ADMIN = "super_admin"


class EntityType(StrEnum):
    """Type of organisation a provider is affiliated with."""

    HOSPITAL = "Hospital"
    PHARMACY = "Pharmacy"


class MissingLookupKeyError(ValueError):
    """Neither an email nor an id was given for a user lookup."""


class RoleExistsError(Exception):
    """The user already holds the requested role."""


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

    def to_json(self) -> dict[str, Any]:
        """Serialize the user with the API field names."""
        data: dict[str, Any] = {
            "id": str(self.id),
            "email": self.email,
            "firstName": self.first_name,
            "lastName": self.last_name,
        }
        if self.date_of_birth is not None:
            data["dateOfBirth"] = self.date_of_birth.isoformat()
        data |= {
            "contact": self.contact,
            "nationalID": self.national_id,
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

    # Surrogate key; role_account_id is not set on every account.
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    role_account_id: Mapped[uuid.UUID] = mapped_column(Uuid, default=NIL_UUID)
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

    def create_new_user_account(self, session: Session) -> None:
        """Insert the role account within the session's transaction."""
        session.add(self)
        session.flush()

    @classmethod
    def get_all_user_roles(cls, session: Session, user_id: uuid.UUID) -> set[str]:
        """Return the roles the user already holds."""
        return set(session.scalars(select(cls.role).where(cls.user_id == user_id)))

    @classmethod
    def confirm_user(cls, session: Session, *, email: str, user_id: uuid.UUID, role: str) -> None:
        """Mark the matching role account as confirmed."""
        session.execute(
            update(cls)
            .where(cls.email == email, cls.user_id == user_id, cls.role == role)
            .values(is_confirmed=True)
        )


def _isoformat(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None
