"""Request validation for the auth service."""

import logging
from typing import Annotated

from fastapi import Header, Request

from health_tech.auth import messages
from health_tech.auth.dto import RefreshTokenRequest, SignInUserRequest, ValidateTokenRequest
from health_tech.lib.http import AbortError, BindError, bind_json

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


async def validate_sign_in_user_request(request: Request) -> SignInUserRequest:
    """Validate the sign-in body."""
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
    return req
