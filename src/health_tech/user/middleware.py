"""Auth guards and request validation for the user service."""

import logging
import uuid
from typing import Annotated

from fastapi import Depends, Header, Path, Query, Request
from starlette.concurrency import run_in_threadpool

from health_tech.lib.http import AbortError, BindError, bind_json
from health_tech.lib.ids import NIL_UUID, uuid_from_string_or_nil
from health_tech.lib.password import PasswordError, generate_from_password
from health_tech.lib.tokenmaker import TokenClaims, TokenError, TokenPurpose, validate_token
from health_tech.user import messages
from health_tech.user.dto import (
    DEFAULT_PAGE_SIZE,
    MAX_PAGE_SIZE,
    AddProviderOrganisationRequest,
    ConfirmUserRequest,
    CreateNewUserNoPwdRequest,
    CreateProviderAccountRequest,
    ListUsersRequest,
    NewProviderAccount,
    NewUserAccount,
    ProviderOrganisation,
)
from health_tech.user.model import ORGANISATION_ROLES, UserRole

AUTH_HEADER = "X-USER-TOKEN"
ADMIN_ROLES = frozenset({UserRole.HOSPITAL_ADMIN, UserRole.PHARMACY_ADMIN, UserRole.SUPER_ADMIN})
# Providers are the roles that work for organisations.
PROVIDER_ROLES = ORGANISATION_ROLES

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


def authenticated(x_user_token: UserToken = "") -> TokenClaims:
    """Allow any caller with a valid access token."""
    return _verify_token(x_user_token)


def super_admin_only(x_user_token: UserToken = "") -> TokenClaims:
    """Allow only super admins."""
    auth_user = _verify_token(x_user_token)
    if auth_user.role != UserRole.SUPER_ADMIN:
        log.info("Only super admins are allowed: role %s", auth_user.role)
        raise AbortError(403, {"error": "Forbidden"})
    return auth_user


def admins_only(x_user_token: UserToken = "") -> TokenClaims:
    """Allow hospital admins, pharmacy admins and super admins."""
    auth_user = _verify_token(x_user_token)
    if auth_user.role not in ADMIN_ROLES:
        log.info("Only admins can create provider accounts")
        raise AbortError(403, {"error": "Forbidden"})
    return auth_user


def authorize_user_record_access(
    user_id: Annotated[str, Path(description="ID of the user (person) whose record is read.")],
    auth_user: Annotated[TokenClaims, Depends(authenticated)],
) -> uuid.UUID:
    """Allow super admins to read any user's record and patients to read only their own.

    The caller is identified by the UserID claim (users.id), which sign-in takes from the
    role account in the database. Other roles have no per-patient grant and are refused.
    """
    record_id = uuid_from_string_or_nil(user_id)
    if auth_user.role == UserRole.SUPER_ADMIN:
        if record_id == NIL_UUID:
            raise AbortError(404, {"error": messages.USER_NOT_FOUND})
        return record_id

    caller_id = uuid_from_string_or_nil(auth_user.user_id)
    # Decided from the token alone, before any lookup, so a 403 says nothing about whether
    # another user exists.
    if auth_user.role != UserRole.PATIENT or caller_id == NIL_UUID or record_id != caller_id:
        log.info("Role %s may not read user record %s", auth_user.role, user_id)
        raise AbortError(403, {"error": messages.FORBIDDEN})
    return record_id


def validate_list_users_request(
    _: Annotated[TokenClaims, Depends(super_admin_only)],
    page: Annotated[str, Query(description="Page number, starting at 1.")] = "1",
    page_size: Annotated[
        str,
        Query(
            alias="pageSize",
            description=f"Users per page; larger values get {MAX_PAGE_SIZE}.",
        ),
    ] = str(DEFAULT_PAGE_SIZE),
) -> ListUsersRequest:
    """Allow only super admins and validate the paging parameters."""
    page_number = _positive_int(page)
    if page_number is None:
        raise AbortError(400, {"error": messages.INVALID_PAGE})
    size = _positive_int(page_size)
    if size is None:
        raise AbortError(400, {"error": messages.INVALID_PAGE_SIZE})
    # Asking for more than a page holds gets a full page; the response states the size used.
    return ListUsersRequest(page=page_number, page_size=min(size, MAX_PAGE_SIZE))


def _positive_int(value: str) -> int | None:
    # ASCII digits only: int() also takes signs, spaces, underscores and non-ASCII digits.
    if not (value.isascii() and value.isdigit()):
        return None
    try:
        number = int(value)
    except ValueError:  # more digits than int() converts
        return None
    return number if number >= 1 else None


async def validate_create_provider_account_request(
    request: Request,
    auth_user: Annotated[TokenClaims, Depends(admins_only)],
) -> NewProviderAccount:
    """Validate a provider account body and hash its password."""
    try:
        req = await bind_json(request, CreateProviderAccountRequest)
    except BindError as exc:
        raise AbortError(400, {"error": "invalid request body"}) from exc

    _check_caller_may_manage(auth_user, req.role)

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
    organisation_id = _organisation_for_caller(auth_user, req.organisation_id)

    password_hash = await _hash_password(req.password)
    return NewProviderAccount(
        req=req,
        role_account_id=uuid.uuid4(),
        password_hash=password_hash,
        organisation_id=organisation_id,
    )


async def validate_add_provider_organisation_request(
    request: Request,
    auth_user: Annotated[TokenClaims, Depends(admins_only)],
) -> ProviderOrganisation:
    """Validate a request to let an existing provider login work for another organisation."""
    try:
        req = await bind_json(request, AddProviderOrganisationRequest)
    except BindError as exc:
        raise AbortError(400, {"error": "invalid request body"}) from exc

    _check_caller_may_manage(auth_user, req.role)
    if not req.email:
        log.info("Email is required")
        raise AbortError(400, {"error": messages.EMAIL_REQUIRED})
    if req.role not in ORGANISATION_ROLES:
        log.info("Role %r does not work for organisations", req.role)
        raise AbortError(400, {"error": messages.NOT_ORGANISATION_ROLE})
    organisation_id = _organisation_for_caller(auth_user, req.organisation_id)
    return ProviderOrganisation(email=req.email, role=req.role, organisation_id=organisation_id)


def _check_caller_may_manage(auth_user: TokenClaims, role: str) -> None:
    """Hospital admins manage only doctors, pharmacy admins only pharmacists."""
    match auth_user.role:
        case UserRole.HOSPITAL_ADMIN if role != UserRole.DOCTOR:
            log.info("Hospital admins manage only doctors")
            raise AbortError(403, {"error": messages.FORBIDDEN})
        case UserRole.PHARMACY_ADMIN if role != UserRole.PHARMACIST:
            log.info("Pharmacy admins manage only pharmacists")
            raise AbortError(403, {"error": messages.FORBIDDEN})


def _organisation_for_caller(auth_user: TokenClaims, requested: uuid.UUID) -> uuid.UUID:
    """Return the organisation a provider is added to.

    Super admins name it. Hospital and pharmacy admins act for the organisation they signed
    in to and may not name another.
    """
    if auth_user.role == UserRole.SUPER_ADMIN:
        if requested == NIL_UUID:
            log.info("Organisation id is required")
            raise AbortError(400, {"error": messages.ORGANISATION_ID_REQUIRED})
        return requested

    caller_organisation = uuid_from_string_or_nil(auth_user.organisation_id)
    if caller_organisation == NIL_UUID:
        log.info("Admin token names no organisation")
        raise AbortError(403, {"error": messages.FORBIDDEN})
    if requested not in (NIL_UUID, caller_organisation):
        log.info("Admin of %s may not add to organisation %s", caller_organisation, requested)
        raise AbortError(403, {"error": messages.FORBIDDEN})
    return caller_organisation


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
    return NewUserAccount(
        req=req, user_id=uuid.uuid4(), role_account_id=uuid.uuid4(), password_hash=password_hash
    )


async def _hash_password(password: str) -> str:
    # bcrypt is CPU-bound; keep it off the event loop.
    try:
        return await run_in_threadpool(generate_from_password, password)
    except PasswordError as exc:
        log.info("Error generating password hash: %s", exc)
        raise AbortError(500, {"message": "internal server error"}) from exc
