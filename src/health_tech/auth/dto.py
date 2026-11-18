"""Auth service request and response models."""

import uuid
from dataclasses import dataclass

from pydantic import BaseModel, field_validator

from health_tech.user.model import to_lower


class SignInUserRequest(BaseModel):
    """Body of POST /health-tech/auth/signin.

    role picks which of the person's logins to sign in to when one email has several.
    """

    email: str = ""
    password: str = ""
    role: str = ""

    # Stored emails are lower case; so is the one looked up.
    _lower_email = field_validator("email")(to_lower)


@dataclass(frozen=True, slots=True)
class SignInAttempt:
    """A validated sign in: the body plus the organisation from the query string.

    organisation_id is set exactly when role works for organisations.
    """

    email: str
    password: str
    role: str
    organisation_id: uuid.UUID | None


class SignInUserResponse(BaseModel):
    """Response of POST /health-tech/auth/signin."""

    message: str
    token: str
    refresh_token: str


@dataclass(frozen=True, slots=True)
class ValidateTokenRequest:
    """Token read from the X-USER-TOKEN header."""

    token: str


@dataclass(frozen=True, slots=True)
class RefreshTokenRequest:
    """Refresh token read from the X-REFRESH-TOKEN header."""

    token: str


class ValidateTokenResponse(BaseModel):
    """Response of GET /health-tech/auth/validate.

    user_id is the person (users.id); role_account_id is the login the token was issued to.
    """

    email: str
    role: str
    user_id: str
    role_account_id: str
    organisation_id: str


class RefreshTokenResponse(BaseModel):
    """Response of POST /health-tech/auth/refresh."""

    token: str
