"""User service request and response models."""

import uuid
from dataclasses import dataclass
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from health_tech.lib.ids import NIL_UUID
from health_tech.user.model import Contact


class CreateNewUserNoPwdRequest(BaseModel):
    """Body of POST /health-tech/user."""

    model_config = ConfigDict(populate_by_name=True)

    email: str = ""
    role: str = ""
    first_name: str = Field("", alias="firstName")
    last_name: str = Field("", alias="lastName")
    date_of_birth: datetime | None = Field(None, alias="dateOfBirth")
    contact: Contact = Field(default_factory=Contact)
    national_id: str = Field("", alias="nationalID")
    password: str = ""


@dataclass(frozen=True, slots=True)
class NewUserAccount:
    """A validated create-user request with its generated user ID and password hash."""

    req: CreateNewUserNoPwdRequest
    user_id: uuid.UUID
    password_hash: str


class CreateNewUserNoPwdResponse(BaseModel):
    """Response of POST /health-tech/user."""

    message: str


class CreateProviderAccountRequest(BaseModel):
    """Body of POST /health-tech/user/healthcare-providers."""

    model_config = ConfigDict(populate_by_name=True)

    email: str = ""
    role: str = ""
    password: str = ""
    user_id: uuid.UUID = Field(NIL_UUID, alias="userId")


@dataclass(frozen=True, slots=True)
class NewProviderAccount:
    """A validated provider request with its generated role account ID and password hash."""

    req: CreateProviderAccountRequest
    role_account_id: uuid.UUID
    password_hash: str


class CreateProviderAccountResponse(BaseModel):
    """Response of POST /health-tech/user/healthcare-providers."""

    message: str


class PutNewPasswordResponse(BaseModel):
    """Response of a password change."""

    message: str


@dataclass(frozen=True, slots=True)
class ConfirmUserRequest:
    """Token from the confirmation link."""

    token: str


class ConfirmUserResponse(BaseModel):
    """Response of GET /health-tech/user/confirm."""

    message: str
