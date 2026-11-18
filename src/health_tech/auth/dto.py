"""Auth service request and response models."""

import uuid
from dataclasses import dataclass

from health_tech.lib.validation import Email, Password, RequestModel, ResponseModel


class SignInUserRequest(RequestModel):
    """Body of POST /health-tech/auth/signin.

    role picks which of the person's logins to sign in to when one email has several. The
    email is lower-cased, as stored emails are. The password has no minimum length here, so a
    short wrong password is refused like any other wrong password.
    """

    email: Email = ""
    password: Password = ""
    role: str = ""


@dataclass(frozen=True, slots=True)
class SignInAttempt:
    """A validated sign in: the body plus the organisation from the query string.

    organisation_id is set exactly when role works for organisations.
    """

    email: str
    password: str
    role: str
    organisation_id: uuid.UUID | None


class SignInUserResponse(ResponseModel):
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


class ValidateTokenResponse(ResponseModel):
    """Response of GET /health-tech/auth/validate.

    user_id is the person (users.id); role_account_id is the login the token was issued to.
    """

    email: str
    role: str
    user_id: str
    role_account_id: str
    organisation_id: str


class RefreshTokenResponse(ResponseModel):
    """Response of POST /health-tech/auth/refresh."""

    token: str
