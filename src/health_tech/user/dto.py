"""User service request and response models.

Requests are validated by the field types in lib/validation.py and drop unknown fields.
Responses are built field by field from the database models and never are those models.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Self

from pydantic import Field, ValidationError

from health_tech.lib.ids import NIL_UUID
from health_tech.lib.validation import (
    AddressPart,
    DateOfBirth,
    Email,
    NationalId,
    NewPassword,
    PersonName,
    Phone,
    PostalCode,
    RequestModel,
    ResponseModel,
    Street,
)
from health_tech.user.model import User


class AddressRequest(RequestModel):
    """Physical address in a request."""

    street: Street = ""
    city: AddressPart = ""
    state: AddressPart = ""
    zip_code: PostalCode = Field("", alias="zipCode")
    country: AddressPart = ""


class ContactRequest(RequestModel):
    """Contact information in a request."""

    phone: Phone = ""
    address: AddressRequest = Field(default_factory=AddressRequest)


class CreateNewUserNoPwdRequest(RequestModel):
    """Body of POST /health-tech/user.

    The email and names are lower-cased (lib/normalize.py), as they are stored, which also
    keeps the emailed confirmation token in step with the stored account. Which values are
    required is checked by the middleware.
    """

    email: Email = ""
    role: str = ""
    first_name: PersonName = Field("", alias="firstName")
    last_name: PersonName = Field("", alias="lastName")
    date_of_birth: DateOfBirth = Field(None, alias="dateOfBirth")
    contact: ContactRequest = Field(default_factory=ContactRequest)
    national_id: NationalId = Field("", alias="nationalID")
    password: NewPassword = ""


@dataclass(frozen=True, slots=True)
class NewUserAccount:
    """A validated create-user request with its generated user ID and password hash."""

    req: CreateNewUserNoPwdRequest
    user_id: uuid.UUID
    role_account_id: uuid.UUID
    password_hash: str


class CreateNewUserNoPwdResponse(ResponseModel):
    """Response of POST /health-tech/user."""

    message: str


class CreateProviderAccountRequest(RequestModel):
    """Body of POST /health-tech/user/healthcare-providers."""

    email: Email = ""
    role: str = ""
    password: NewPassword = ""
    user_id: uuid.UUID = Field(NIL_UUID, alias="userId")
    # Required from super admins; hospital and pharmacy admins add to their own organisation.
    organisation_id: uuid.UUID = Field(NIL_UUID, alias="organisationId")


@dataclass(frozen=True, slots=True)
class NewProviderAccount:
    """A validated provider request with its generated role account ID, password hash and
    the organisation the provider will work for."""

    req: CreateProviderAccountRequest
    role_account_id: uuid.UUID
    password_hash: str
    organisation_id: uuid.UUID


class AddProviderOrganisationRequest(RequestModel):
    """Body of POST /health-tech/user/healthcare-providers/organisations."""

    email: Email = ""
    role: str = ""
    # Required from super admins; hospital and pharmacy admins add to their own organisation.
    organisation_id: uuid.UUID = Field(NIL_UUID, alias="organisationId")


@dataclass(frozen=True, slots=True)
class ProviderOrganisation:
    """A validated request to let an existing provider login work for another organisation."""

    email: str
    role: str
    organisation_id: uuid.UUID


class AddProviderOrganisationResponse(ResponseModel):
    """Response of POST /health-tech/user/healthcare-providers/organisations."""

    message: str


class CreateProviderAccountResponse(ResponseModel):
    """Response of POST /health-tech/user/healthcare-providers."""

    message: str


class PutNewPasswordResponse(ResponseModel):
    """Response of a password change."""

    message: str


@dataclass(frozen=True, slots=True)
class ConfirmUserRequest:
    """Token from the confirmation link."""

    token: str


class ConfirmUserResponse(ResponseModel):
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


class AddressResponse(ResponseModel):
    """Physical address in a response."""

    street: str = ""
    city: str = ""
    state: str = ""
    zip_code: str = Field("", alias="zipCode")
    country: str = ""


class ContactResponse(ResponseModel):
    """Contact information in a response."""

    phone: str = ""
    address: AddressResponse = Field(default_factory=AddressResponse)

    @classmethod
    def from_stored(cls, stored: dict[str, Any] | None) -> Self:
        """Return the known fields of a stored contact; anything else stored is left out."""
        try:
            return cls.model_validate(stored or {})
        except ValidationError:
            # Written before requests were validated; show nothing rather than fail the read.
            return cls()


class UserSummaryResponse(ResponseModel):
    """A user in a listing: everything but the national ID."""

    id: uuid.UUID
    email: str
    first_name: str = Field(alias="firstName")
    last_name: str = Field(alias="lastName")
    date_of_birth: datetime | None = Field(alias="dateOfBirth")
    contact: ContactResponse
    created_at: datetime | None = Field(alias="createdAt")
    updated_at: datetime | None = Field(alias="updatedAt")

    @classmethod
    def from_user(cls, user: User) -> Self:
        """Copy the fields a listing shows from user."""
        return cls(**_user_fields(user))


class UserResponse(UserSummaryResponse):
    """Response of GET /health-tech/user/{user_id}: one user's record."""

    national_id: str = Field(alias="nationalID")

    @classmethod
    def from_user(cls, user: User) -> Self:
        """Copy the fields a record shows from user."""
        return cls(**_user_fields(user), national_id=user.national_id)


def _user_fields(user: User) -> dict[str, Any]:
    return {
        "id": user.id,
        "email": user.email,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "date_of_birth": user.date_of_birth,
        "contact": ContactResponse.from_stored(user.contact),
        "created_at": user.created_at,
        "updated_at": user.updated_at,
    }


class ListUsersResponse(ResponseModel):
    """Response of GET /health-tech/user: one page of users."""

    users: list[UserSummaryResponse]
    page: int
    page_size: int = Field(alias="pageSize")
    total: int
    total_pages: int = Field(alias="totalPages")
