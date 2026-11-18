"""Request validation for the user service, and the per-request authorization rules.

Which roles may call each endpoint is decided before this, by AccessControlMiddleware and
the table in user/router.py. What is here depends on the request: a patient reads only
their own record, a hospital admin manages only doctors, an admin only their organisation.
"""

import uuid
from typing import Annotated

from fastapi import Depends, Path, Query, Request, Security
from fastapi.security import APIKeyHeader
from starlette.concurrency import run_in_threadpool

from health_tech.lib.access import AUTH_HEADER, caller_claims
from health_tech.lib.http import AbortError, bind_json
from health_tech.lib.ids import NIL_UUID, uuid_from_string_or_nil
from health_tech.lib.password import PasswordError, generate_from_password
from health_tech.lib.tokenmaker import TokenClaims
from health_tech.logger import log
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
from health_tech.user.model import ORGANISATION_ROLES, SELF_REGISTERED_ROLES, UserRole

# Providers are the roles that work for organisations.
PROVIDER_ROLES = ORGANISATION_ROLES
KNOWN_ROLES = frozenset(UserRole)

# Documents the header in OpenAPI; AccessControlMiddleware has already checked it.
user_token = APIKeyHeader(
    name=AUTH_HEADER,
    auto_error=False,
    description="Access token. Callers whose role the endpoint does not allow get 401.",
)


def caller(request: Request, _: Annotated[str | None, Security(user_token)] = None) -> TokenClaims:
    """Return the caller's claims, checked against the endpoint's roles (user/router.py)."""
    return caller_claims(request)


def authorize_user_record_access(
    user_id: Annotated[str, Path(description="ID of the user (person) whose record is read.")],
    auth_user: Annotated[TokenClaims, Depends(caller)],
) -> uuid.UUID:
    """Let super admins read any user's record and patients only their own.

    Only those two roles get here (user/router.py). The caller is identified by the UserID
    claim (users.id), which sign-in takes from the role account in the database.
    """
    record_id = uuid_from_string_or_nil(user_id)
    if auth_user.role == UserRole.SUPER_ADMIN:
        if record_id == NIL_UUID:
            raise AbortError(messages.USER_NOT_FOUND)
        return record_id

    caller_id = uuid_from_string_or_nil(auth_user.user_id)
    # Decided from the token alone, before any lookup, so a 403 says nothing about whether
    # another user exists.
    if auth_user.role != UserRole.PATIENT or caller_id == NIL_UUID or record_id != caller_id:
        log.info("Role %s may not read this user record", auth_user.role)
        raise AbortError(messages.FORBIDDEN)
    return record_id


def validate_list_users_request(
    _: Annotated[TokenClaims, Depends(caller)],
    page: Annotated[str, Query(description="Page number, starting at 1.")] = "1",
    page_size: Annotated[
        str,
        Query(
            alias="pageSize",
            description=f"Users per page; larger values get {MAX_PAGE_SIZE}.",
        ),
    ] = str(DEFAULT_PAGE_SIZE),
) -> ListUsersRequest:
    """Validate the paging parameters."""
    page_number = _positive_int(page)
    if page_number is None:
        raise AbortError(messages.INVALID_PAGE)
    size = _positive_int(page_size)
    if size is None:
        raise AbortError(messages.INVALID_PAGE_SIZE)
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
    auth_user: Annotated[TokenClaims, Depends(caller)],
) -> NewProviderAccount:
    """Validate a provider account body and hash its password."""
    req = await bind_json(request, CreateProviderAccountRequest)

    _check_caller_may_manage(auth_user, req.role)

    if not req.email:
        log.info("Email is required")
        raise AbortError(messages.EMAIL_REQUIRED)
    if req.user_id == NIL_UUID:
        log.info("User ID is required")
        raise AbortError(messages.USER_ID_REQUIRED)
    if req.role not in PROVIDER_ROLES:
        log.info(
            "Role is not a provider role: only doctors, pharmacists, hospital admins "
            "and pharmacy admins can be created"
        )
        raise AbortError(messages.NOT_PROVIDER_ROLE)
    if not req.password:
        log.info("Password is required")
        raise AbortError(messages.PASSWORD_REQUIRED)
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
    auth_user: Annotated[TokenClaims, Depends(caller)],
) -> ProviderOrganisation:
    """Validate a request to let an existing provider login work for another organisation."""
    req = await bind_json(request, AddProviderOrganisationRequest)

    _check_caller_may_manage(auth_user, req.role)
    if not req.email:
        log.info("Email is required")
        raise AbortError(messages.EMAIL_REQUIRED)
    if req.role not in ORGANISATION_ROLES:
        log.info("Role does not work for organisations")
        raise AbortError(messages.NOT_ORGANISATION_ROLE)
    organisation_id = _organisation_for_caller(auth_user, req.organisation_id)
    return ProviderOrganisation(email=req.email, role=req.role, organisation_id=organisation_id)


def _check_caller_may_manage(auth_user: TokenClaims, role: str) -> None:
    """Hospital admins manage only doctors, pharmacy admins only pharmacists."""
    match auth_user.role:
        case UserRole.HOSPITAL_ADMIN if role != UserRole.DOCTOR:
            log.info("Hospital admins manage only doctors")
            raise AbortError(messages.FORBIDDEN)
        case UserRole.PHARMACY_ADMIN if role != UserRole.PHARMACIST:
            log.info("Pharmacy admins manage only pharmacists")
            raise AbortError(messages.FORBIDDEN)


def _organisation_for_caller(auth_user: TokenClaims, requested: uuid.UUID) -> uuid.UUID:
    """Return the organisation a provider is added to.

    Super admins name it. Hospital and pharmacy admins act for the organisation they signed
    in to and may not name another.
    """
    if auth_user.role == UserRole.SUPER_ADMIN:
        if requested == NIL_UUID:
            log.info("Organisation id is required")
            raise AbortError(messages.ORGANISATION_ID_REQUIRED)
        return requested

    caller_organisation = uuid_from_string_or_nil(auth_user.organisation_id)
    if caller_organisation == NIL_UUID:
        log.info("Admin token names no organisation")
        raise AbortError(messages.FORBIDDEN)
    if requested not in (NIL_UUID, caller_organisation):
        log.info("Admin of %s may not add to organisation %s", caller_organisation, requested)
        raise AbortError(messages.FORBIDDEN)
    return caller_organisation


def validate_confirm_user_request(token: Annotated[str, Query()] = "") -> ConfirmUserRequest:
    """Read the confirmation token from the query string."""
    if not token:
        raise AbortError(messages.UNAUTHORIZED)
    return ConfirmUserRequest(token=token)


async def validate_create_new_user_account_request(
    request: Request,
    _: Annotated[TokenClaims, Depends(caller)],
) -> NewUserAccount:
    """Validate a new user body, hash its password and assign a user ID.

    role is patient or super_admin, whose login is created with the user, or empty, for a
    person who gets provider logins later with POST /health-tech/user/healthcare-providers.
    Provider roles are refused here: this endpoint would create no login for them.
    """
    req = await bind_json(request, CreateNewUserNoPwdRequest)

    if not req.email:
        log.info("Email is required")
        raise AbortError(messages.EMAIL_REQUIRED)
    if not req.first_name:
        log.info("First name is required")
        raise AbortError(messages.FIRST_NAME_REQUIRED)
    if not req.last_name:
        log.info("Last name is required")
        raise AbortError(messages.LAST_NAME_REQUIRED)
    if req.role and req.role not in KNOWN_ROLES:
        log.info("Unknown role")
        raise AbortError(messages.INVALID_ROLE)
    if req.role and req.role not in SELF_REGISTERED_ROLES:
        log.info("Role %s is created with the healthcare providers endpoint", req.role)
        raise AbortError(messages.ACCOUNT_ROLE_NOT_ALLOWED)
    if not req.password:
        log.info("Password is required")
        raise AbortError(messages.PASSWORD_REQUIRED)

    password_hash = await _hash_password(req.password)
    return NewUserAccount(
        req=req, user_id=uuid.uuid4(), role_account_id=uuid.uuid4(), password_hash=password_hash
    )


async def _hash_password(password: str) -> str:
    # bcrypt is CPU-bound; keep it off the event loop.
    try:
        return await run_in_threadpool(generate_from_password, password)
    except PasswordError as exc:
        log.error("Error generating password hash: %s", exc)
        raise AbortError(messages.INTERNAL_ERROR) from exc
