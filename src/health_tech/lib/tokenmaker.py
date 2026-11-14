"""HS256 JWTs used as session and email confirmation tokens."""

import logging
import time
from dataclasses import dataclass

import jwt

from health_tech.lib.config import get_settings

TOKEN_EXPIRY_SECONDS = 2 * 60 * 60
TOKEN_SUBJECT = "email_verification"
SIGNING_ALGORITHM = "HS256"
HMAC_ALGORITHMS = ["HS256", "HS384", "HS512"]

log = logging.getLogger(__name__)


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
    expires_at: int
    issued_at: int
    subject: str


def generate_token(requirements: TokenRequirements) -> str:
    """Create a JWT that expires in two hours."""
    now = int(time.time())
    claims = {
        "Email": requirements.email,
        "UserID": requirements.user_id,
        "Role": requirements.role,
        "exp": now + TOKEN_EXPIRY_SECONDS,
        "iat": now,
        "sub": TOKEN_SUBJECT,
    }
    try:
        return jwt.encode(claims, get_settings().jwt_secret, algorithm=SIGNING_ALGORITHM)
    except (jwt.PyJWTError, TypeError) as exc:
        log.error("Error signing JWT token: %s", exc)
        raise TokenError(f"error signing JWT token: {exc}") from exc


def validate_verification_token(token: str) -> TokenClaims:
    """Check the token's signature and expiry and return its claims."""
    try:
        payload = jwt.decode(token, get_settings().jwt_secret, algorithms=HMAC_ALGORITHMS)
    except jwt.PyJWTError as exc:
        raise TokenError(f"token validation failed: {exc}") from exc
    return TokenClaims(
        email=payload.get("Email", ""),
        user_id=payload.get("UserID", ""),
        role=payload.get("Role", ""),
        expires_at=payload.get("exp", 0),
        issued_at=payload.get("iat", 0),
        subject=payload.get("sub", ""),
    )
