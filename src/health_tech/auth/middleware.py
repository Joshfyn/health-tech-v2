"""Request validation for the auth service."""

import logging
import uuid
from typing import Annotated

from fastapi import Header, Query, Request

from health_tech.auth import messages
from health_tech.auth.dto import (
    RefreshTokenRequest,
    SignInAttempt,
    SignInUserRequest,
    ValidateTokenRequest,
)
from health_tech.lib.http import AbortError, BindError, bind_json
from health_tech.lib.ids import NIL_UUID
from health_tech.user.model import ORGANISATION_ROLES, UserRole

AUTH_HEADER = "X-USER-TOKEN"
REFRESH_HEADER = "X-REFRESH-TOKEN"

log = logging.getLogger(__name__)


def validate_token_request(
    x_user_token: Annotated[str, Header(alias=AUTH_HEADER)] = "",
) -> ValidateTokenRequest:
    """Read the token from the X-USER-TOKEN header."""
    if not x_user_token:
        raise AbortError(401, {"error": messages.UNAUTHORIZED})
    return ValidateTokenRequest(token=x_user_token)


def validate_refresh_token_request(
    x_refresh_token: Annotated[str, Header(alias=REFRESH_HEADER)] = "",
) -> RefreshTokenRequest:
    """Read the refresh token from the X-REFRESH-TOKEN header."""
    if not x_refresh_token:
        raise AbortError(401, {"error": messages.UNAUTHORIZED})
    return RefreshTokenRequest(token=x_refresh_token)


async def validate_sign_in_user_request(
    request: Request,
    organisation_id: Annotated[
        str,
        Query(
            alias="organisationId",
            description="Organisation to sign in to. Required for roles that work for "
            "organisations (doctors, pharmacists, hospital and pharmacy admins), "
            "refused for other roles.",
        ),
    ] = "",
) -> SignInAttempt:
    """Validate the sign-in body and the organisation in the query string."""
    try:
        req = await bind_json(request, SignInUserRequest)
    except BindError as exc:
        raise AbortError(400, {"error": messages.INVALID_REQUEST_BODY}) from exc
    if not req.email:
        log.info("Email is required")
        raise AbortError(400, {"error": messages.EMAIL_REQUIRED})
    if not req.password:
        log.info("Password is required")
        raise AbortError(400, {"error": messages.PASSWORD_REQUIRED})
    if not req.role:
        log.info("Role is required")
        raise AbortError(400, {"error": messages.ROLE_REQUIRED})
    if not is_known_role(req.role):
        log.info("Unknown role: %r", req.role)
        raise AbortError(400, {"error": messages.INVALID_ROLE})
    return SignInAttempt(
        email=req.email,
        password=req.password,
        role=req.role,
        organisation_id=_organisation_for_role(req.role, organisation_id),
    )


def _organisation_for_role(role: str, organisation_id: str) -> uuid.UUID | None:
    """Return the organisation to sign in to, or None for roles that work for none."""
    if role not in ORGANISATION_ROLES:
        if organisation_id:
            log.info("Organisation id given for role %s", role)
            raise AbortError(400, {"error": messages.ORGANISATION_ID_NOT_ALLOWED})
        return None
    if not organisation_id:
        log.info("Organisation id is required for role %s", role)
        raise AbortError(400, {"error": messages.ORGANISATION_ID_REQUIRED})
    try:
        parsed = uuid.UUID(organisation_id)
    except ValueError:
        parsed = NIL_UUID
    if parsed == NIL_UUID:
        log.info("Invalid organisation id: %r", organisation_id)
        raise AbortError(400, {"error": messages.INVALID_ORGANISATION_ID})
    return parsed


def is_known_role(value: str) -> bool:
    """Report whether value is exactly one of the UserRole values."""
    try:
        UserRole(value)
    except ValueError:
        return False
    return True
