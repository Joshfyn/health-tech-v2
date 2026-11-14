"""Request validation for the auth service."""

import logging
from typing import Annotated

from fastapi import Header, Request

from health_tech.auth.dto import SignInUserRequest, ValidateTokenRequest
from health_tech.lib.http import AbortError, BindError, bind_json

AUTH_HEADER = "X-USER-TOKEN"

log = logging.getLogger(__name__)


def validate_token_request(
    x_user_token: Annotated[str, Header(alias=AUTH_HEADER)] = "",
) -> ValidateTokenRequest:
    """Read the token from the X-USER-TOKEN header."""
    if not x_user_token:
        raise AbortError(401, {"error": "Unauthorized"})
    return ValidateTokenRequest(token=x_user_token)


async def validate_sign_in_user_request(request: Request) -> SignInUserRequest:
    """Validate the sign-in body."""
    try:
        req = await bind_json(request, SignInUserRequest)
    except BindError as exc:
        raise AbortError(400, {"error": "invalid request body"}) from exc
    if not req.email:
        log.info("Email is required")
        raise AbortError(400, {"error": "email is required"})
    if not req.password:
        log.info("Password is required")
        raise AbortError(400, {"error": "password is required"})
    return req
