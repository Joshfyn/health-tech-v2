"""User service request and response models."""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from health_tech.lib.ids import NIL_UUID
from health_tech.user.model import Contact, to_lower


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

    # Emails and names are stored in lower case; lowering here also keeps the emailed
    # confirmation token in step with the stored account.
    _lower = field_validator("email", "first_name", "last_name")(to_lower)


@dataclass(frozen=True, slots=True)
class NewUserAccount:
    """A validated create-user request with its generated user ID and password hash."""

    req: CreateNewUserNoPwdRequest
    user_id: uuid.UUID
    role_account_id: uuid.UUID
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
    # Required from super admins; hospital and pharmacy admins add to their own organisation.
    organisation_id: uuid.UUID = Field(NIL_UUID, alias="organisationId")

    _lower_email = field_validator("email")(to_lower)


@dataclass(frozen=True, slots=True)
class NewProviderAccount:
    """A validated provider request with its generated role account ID, password hash and
    the organisation the provider will work for."""

    req: CreateProviderAccountRequest
    role_account_id: uuid.UUID
    password_hash: str
    organisation_id: uuid.UUID


class AddProviderOrganisationRequest(BaseModel):
    """Body of POST /health-tech/user/healthcare-providers/organisations."""

    model_config = ConfigDict(populate_by_name=True)

    email: str = ""
    role: str = ""
    # Required from super admins; hospital and pharmacy admins add to their own organisation.
    organisation_id: uuid.UUID = Field(NIL_UUID, alias="organisationId")

    _lower_email = field_validator("email")(to_lower)


@dataclass(frozen=True, slots=True)
class ProviderOrganisation:
    """A validated request to let an existing provider login work for another organisation."""

    email: str
    role: str
    organisation_id: uuid.UUID


class AddProviderOrganisationResponse(BaseModel):
    """Response of POST /health-tech/user/healthcare-providers/organisations."""

    message: str


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


DEFAULT_PAGE_SIZE = 20
MAX_PAGE_SIZE = 100


@dataclass(frozen=True, slots=True)
class ListUsersRequest:
    """Validated paging parameters of GET /health-tech/user."""

    page: int
    page_size: int

    @property
    def offset(self) -> int:
        """Number of users before this page."""
        return (self.page - 1) * self.page_size


class ListUsersResponse(BaseModel):
    """Response of GET /health-tech/user: one page of users."""

    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)

    users: list[dict[str, Any]]
    page: int
    page_size: int = Field(alias="pageSize")
    total: int
    total_pages: int = Field(alias="totalPages")
