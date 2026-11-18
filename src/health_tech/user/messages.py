"""User service response messages.

Errors come from the catalog in lib/errors.py, which fixes each one's status, code and text;
they are re-exported here so the service and its tests name them in one place.
"""

from typing import Final

from health_tech.lib.errors import (
    ACCOUNT_EXISTS,
    ACCOUNT_ROLE_NOT_ALLOWED,
    ALREADY_IN_ORGANISATION,
    BASIC_ACCOUNT_REQUIRED,
    EMAIL_REQUIRED,
    FIRST_NAME_REQUIRED,
    FORBIDDEN,
    INTERNAL_ERROR,
    INVALID_CONFIRMATION_TOKEN,
    INVALID_PAGE,
    INVALID_PAGE_SIZE,
    INVALID_REQUEST_BODY,
    INVALID_ROLE,
    LAST_NAME_REQUIRED,
    NOT_ORGANISATION_ROLE,
    NOT_PROVIDER_ROLE,
    ORGANISATION_ID_REQUIRED,
    PASSWORD_REQUIRED,
    PROVIDER_NOT_FOUND,
    ROLE_ALREADY_HELD,
    ROLE_NOT_ALLOWED,
    UNAUTHORIZED,
    USER_ID_REQUIRED,
    USER_NOT_FOUND,
)

USER_CREATED: Final = "User created successfully"
USER_CONFIRMED: Final = "User confirmed successfully"
PROVIDER_CREATED: Final = "Provider account created successfully"
PROVIDER_ADDED_TO_ORGANISATION: Final = "Provider added to organisation"

__all__ = [
    "ACCOUNT_EXISTS",
    "ACCOUNT_ROLE_NOT_ALLOWED",
    "ALREADY_IN_ORGANISATION",
    "BASIC_ACCOUNT_REQUIRED",
    "EMAIL_REQUIRED",
    "FIRST_NAME_REQUIRED",
    "FORBIDDEN",
    "INTERNAL_ERROR",
    "INVALID_CONFIRMATION_TOKEN",
    "INVALID_PAGE",
    "INVALID_PAGE_SIZE",
    "INVALID_REQUEST_BODY",
    "INVALID_ROLE",
    "LAST_NAME_REQUIRED",
    "NOT_ORGANISATION_ROLE",
    "NOT_PROVIDER_ROLE",
    "ORGANISATION_ID_REQUIRED",
    "PASSWORD_REQUIRED",
    "PROVIDER_ADDED_TO_ORGANISATION",
    "PROVIDER_CREATED",
    "PROVIDER_NOT_FOUND",
    "ROLE_ALREADY_HELD",
    "ROLE_NOT_ALLOWED",
    "UNAUTHORIZED",
    "USER_CONFIRMED",
    "USER_CREATED",
    "USER_ID_REQUIRED",
    "USER_NOT_FOUND",
]
