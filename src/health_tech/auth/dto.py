"""Auth service request and response models."""

from dataclasses import dataclass

from pydantic import BaseModel


class SignInUserRequest(BaseModel):
    """Body of POST /health-tech/auth/signin."""

    email: str = ""
    password: str = ""


class SignInUserResponse(BaseModel):
    """Response of POST /health-tech/auth/signin."""

    token: str


@dataclass(frozen=True, slots=True)
class ValidateTokenRequest:
    """Token read from the X-USER-TOKEN header."""

    token: str


class ValidateTokenResponse(BaseModel):
    """Response of GET /health-tech/auth/validate."""

    email: str
    role: str
    user_id: str


class RefreshTokenResponse(BaseModel):
    """Response of POST /health-tech/auth/refresh."""

    token: str
