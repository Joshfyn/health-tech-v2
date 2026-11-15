"""HS256 JWTs that are each valid for a single purpose."""

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass
from enum import StrEnum

import jwt

from health_tech.lib.config import get_settings

SIGNING_ALGORITHM = "HS256"
KEY_DERIVATION_LABEL = "health-tech/jwt/"

CLAIM_EMAIL = "Email"
CLAIM_USER_ID = "UserID"
CLAIM_ROLE = "Role"
CLAIM_PURPOSE = "Purpose"
REQUIRED_CLAIMS = ["exp", "iat", CLAIM_PURPOSE]

log = logging.getLogger(__name__)


class TokenPurpose(StrEnum):
    """What a token may be used for."""

    ACCESS = "access"
    REFRESH = "refresh"
    EMAIL_CONFIRMATION = "email_confirmation"


TOKEN_LIFETIME_SECONDS: dict[TokenPurpose, int] = {
    TokenPurpose.ACCESS: 15 * 60,
    TokenPurpose.REFRESH: 8 * 60 * 60,
    TokenPurpose.EMAIL_CONFIRMATION: 2 * 60 * 60,
}


class TokenError(Exception):
    """A token could not be signed or failed validation."""


@dataclass(frozen=True, slots=True)
class TokenRequirements:
    """Values carried in a token."""

    email: str = ""
    user_id: str = ""
    role: str = ""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Claims read from a valid token."""

    email: str
    user_id: str
    role: str
    purpose: TokenPurpose
    expires_at: int
    issued_at: int


def _signing_key(purpose: TokenPurpose) -> bytes:
    """Derive the signing key for purpose from JWT_SECRET."""
    secret = get_settings().jwt_secret
    if not secret:
        # A key derived from an empty secret would be public.
        raise TokenError("JWT_SECRET is not set")
    label = f"{KEY_DERIVATION_LABEL}{purpose.value}".encode()
    return hmac.new(secret.encode(), label, hashlib.sha256).digest()


def generate_token(requirements: TokenRequirements, purpose: TokenPurpose) -> str:
    """Create a JWT that is valid only for purpose."""
    purpose = TokenPurpose(purpose)
    now = int(time.time())
    claims = {
        CLAIM_EMAIL: requirements.email,
        CLAIM_USER_ID: requirements.user_id,
        CLAIM_ROLE: requirements.role,
        CLAIM_PURPOSE: purpose.value,
        "exp": now + TOKEN_LIFETIME_SECONDS[purpose],
        "iat": now,
    }
    try:
        return jwt.encode(claims, _signing_key(purpose), algorithm=SIGNING_ALGORITHM)
    except (jwt.PyJWTError, TypeError) as exc:
        log.error("Error signing %s JWT token: %s", purpose.value, exc)
        raise TokenError(f"error signing JWT token: {exc}") from exc


def validate_token(token: str, purpose: TokenPurpose) -> TokenClaims:
    """Return the claims of a valid token minted for purpose."""
    purpose = TokenPurpose(purpose)
    try:
        payload = jwt.decode(
            token,
            _signing_key(purpose),
            algorithms=[SIGNING_ALGORITHM],
            options={"require": REQUIRED_CLAIMS},
        )
    except jwt.PyJWTError as exc:
        raise TokenError(f"token validation failed: {exc}") from exc
    # Second check, independent of the signing key.
    if payload[CLAIM_PURPOSE] != purpose.value:
        raise TokenError("token validation failed: token was not issued for this purpose")
    return TokenClaims(
        email=payload.get(CLAIM_EMAIL, ""),
        user_id=payload.get(CLAIM_USER_ID, ""),
        role=payload.get(CLAIM_ROLE, ""),
        purpose=purpose,
        expires_at=payload["exp"],
        issued_at=payload["iat"],
    )
