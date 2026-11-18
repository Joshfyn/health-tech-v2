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
# The person: users.id. Per-patient authorization compares this claim with the record's owner.
CLAIM_USER_ID = "UserID"
# The login the token was issued to: role_accounts.role_account_id.
CLAIM_ROLE_ACCOUNT_ID = "RoleAccountID"
# The organisation the login signed in to; empty for roles that work for no organisation.
CLAIM_ORGANISATION_ID = "OrganisationID"
CLAIM_ROLE = "Role"
CLAIM_PURPOSE = "Purpose"
BASE_REQUIRED_CLAIMS = ["exp", "iat", CLAIM_PURPOSE]

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


# Session tokens must name both the person and the login. Tokens minted before UserID meant
# users.id (it used to carry the role account ID) lack RoleAccountID and are rejected, so an old
# token's UserID is never read as a person's ID.
SESSION_REQUIRED_CLAIMS = [
    *BASE_REQUIRED_CLAIMS,
    CLAIM_EMAIL,
    CLAIM_USER_ID,
    CLAIM_ROLE_ACCOUNT_ID,
    CLAIM_ROLE,
    CLAIM_ORGANISATION_ID,
]

REQUIRED_CLAIMS: dict[TokenPurpose, list[str]] = {
    TokenPurpose.ACCESS: SESSION_REQUIRED_CLAIMS,
    TokenPurpose.REFRESH: SESSION_REQUIRED_CLAIMS,
    # Confirmation links emailed before RoleAccountID existed stay usable until they expire.
    TokenPurpose.EMAIL_CONFIRMATION: [
        *BASE_REQUIRED_CLAIMS,
        CLAIM_EMAIL,
        CLAIM_USER_ID,
        CLAIM_ROLE,
    ],
}


class TokenError(Exception):
    """A token could not be signed or failed validation."""


@dataclass(frozen=True, slots=True)
class TokenRequirements:
    """Values carried in a token.

    user_id is the person (users.id); role_account_id is the login (role_accounts.role_account_id);
    organisation_id is the organisation the login signed in to, if its role works for one.
    """

    email: str = ""
    user_id: str = ""
    role: str = ""
    role_account_id: str = ""
    organisation_id: str = ""


@dataclass(frozen=True, slots=True)
class TokenClaims:
    """Claims read from a valid token."""

    email: str
    user_id: str
    role: str
    role_account_id: str
    organisation_id: str
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
        CLAIM_ROLE_ACCOUNT_ID: requirements.role_account_id,
        CLAIM_ROLE: requirements.role,
        CLAIM_ORGANISATION_ID: requirements.organisation_id,
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
            options={"require": REQUIRED_CLAIMS[purpose]},
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
        role_account_id=payload.get(CLAIM_ROLE_ACCOUNT_ID, ""),
        organisation_id=payload.get(CLAIM_ORGANISATION_ID, ""),
        purpose=purpose,
        expires_at=payload["exp"],
        issued_at=payload["iat"],
    )
