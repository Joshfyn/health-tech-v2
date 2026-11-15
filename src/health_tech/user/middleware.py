"""Auth guards and request validation for the user service."""

import logging
import uuid
from typing import Annotated

from fastapi import Depends, Header, Query, Request
from starlette.concurrency import run_in_threadpool

from health_tech.lib.http import AbortError, BindError, bind_json
from health_tech.lib.ids import NIL_UUID
from health_tech.lib.password import PasswordError, generate_from_password
from health_tech.lib.tokenmaker import TokenClaims, TokenError, TokenPurpose, validate_token
from health_tech.user.dto import (
    ConfirmUserRequest,
    CreateNewUserNoPwdRequest,
    CreateProviderAccountRequest,
    NewProviderAccount,
    NewUserAccount,
)
from health_tech.user.model import UserRole

AUTH_HEADER = "X-USER-TOKEN"
ADMIN_ROLES = frozenset({UserRole.HOSPITAL_ADMIN, UserRole.PHARMACY_ADMIN, UserRole.SUPER_ADMIN})
PROVIDER_ROLES = frozenset(
    {UserRole.DOCTOR, UserRole.PHARMACIST, UserRole.HOSPITAL_ADMIN, UserRole.PHARMACY_ADMIN}
)

UserToken = Annotated[str, Header(alias=AUTH_HEADER)]

log = logging.getLogger(__name__)


def _verify_token(auth_token: str) -> TokenClaims:
    if not auth_token:
        log.info("No token provided")
        raise AbortError(401, {"error": "Unauthorized"})
    try:
        return validate_token(auth_token, TokenPurpose.ACCESS)
    except TokenError as exc:
        log.info("Error validating token: %s", exc)
        raise AbortError(401, {"error": "Unauthorized"}) from exc


def super_admin_only(x_user_token: UserToken = "") -> TokenClaims:
    """Allow only super admins."""
    auth_user = _verify_token(x_user_token)
    if auth_user.role != UserRole.SUPER_ADMIN:
        log.info("Only super admins can create provider accounts")
        raise AbortError(403, {"error": "Forbidden"})
    return auth_user


def admins_only(x_user_token: UserToken = "") -> TokenClaims:
    """Allow hospital admins, pharmacy admins and super admins."""
    auth_user = _verify_token(x_user_token)
    if auth_user.role not in ADMIN_ROLES:
        log.info("Only admins can create provider accounts")
        raise AbortError(403, {"error": "Forbidden"})
    return auth_user


async def validate_create_provider_account_request(
    request: Request,
    auth_user: Annotated[TokenClaims, Depends(admins_only)],
) -> NewProviderAccount:
    """Validate a provider account body and hash its password."""
    try:
        req = await bind_json(request, CreateProviderAccountRequest)
    except BindError as exc:
        raise AbortError(400, {"error": "invalid request body"}) from exc

    match auth_user.role:
        case UserRole.HOSPITAL_ADMIN if req.role != UserRole.DOCTOR:
            log.info("Only hospital admins can create doctors accounts")
            raise AbortError(403, {"error": "Forbidden"})
        case UserRole.PHARMACY_ADMIN if req.role != UserRole.PHARMACIST:
            log.info("Only pharmacy admins can create pharmacists accounts")
            raise AbortError(403, {"error": "Forbidden"})

    if not req.email:
        log.info("Email is required")
        raise AbortError(400, {"error": "email is required"})
    if req.user_id == NIL_UUID:
        log.info("User ID is required")
        raise AbortError(400, {"error": "user id is required"})
    if req.role not in PROVIDER_ROLES:
        log.info(
            "Invalid role: %s Only doctors, pharmacists, hospital admins, "
            "and pharmacy admins can be created",
            req.role,
        )
        raise AbortError(400, {"error": "bad request"})
    if not req.password:
        log.info("Password is required")
        raise AbortError(400, {"error": "password is required"})

    password_hash = await _hash_password(req.password)
    return NewProviderAccount(req=req, role_account_id=uuid.uuid4(), password_hash=password_hash)


def validate_confirm_user_request(token: Annotated[str, Query()] = "") -> ConfirmUserRequest:
    """Read the confirmation token from the query string."""
    if not token:
        raise AbortError(401, {"error": "Unauthorized"})
    return ConfirmUserRequest(token=token)


async def validate_create_new_user_account_request(
    request: Request,
    _: Annotated[TokenClaims, Depends(super_admin_only)],
) -> NewUserAccount:
    """Validate a new user body, hash its password and assign a user ID."""
    try:
        req = await bind_json(request, CreateNewUserNoPwdRequest)
    except BindError as exc:
        raise AbortError(400, {"error": "invalid request body"}) from exc

    if not req.password:
        log.info("Password is required")
        raise AbortError(400, {"error": "password is required"})

    password_hash = await _hash_password(req.password)
    return NewUserAccount(req=req, user_id=uuid.uuid4(), password_hash=password_hash)


async def _hash_password(password: str) -> str:
    # bcrypt is CPU-bound; keep it off the event loop.
    try:
        return await run_in_threadpool(generate_from_password, password)
    except PasswordError as exc:
        log.info("Error generating password hash: %s", exc)
        raise AbortError(500, {"message": "internal server error"}) from exc
