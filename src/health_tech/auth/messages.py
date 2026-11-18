"""Auth service response messages.

Errors come from the catalog in lib/errors.py, which fixes each one's status, code and text;
they are re-exported here so the service and its tests name them in one place.
"""

from typing import Final

from health_tech.lib.errors import (
    EMAIL_REQUIRED,
    INTERNAL_ERROR,
    INVALID_CREDENTIALS,
    INVALID_ORGANISATION_ID,
    INVALID_REQUEST_BODY,
    INVALID_ROLE,
    ORGANISATION_ID_NOT_ALLOWED,
    ORGANISATION_ID_REQUIRED,
    PASSWORD_REQUIRED,
    ROLE_REQUIRED,
    UNAUTHORIZED,
    USER_NOT_AUTHORIZED,
)

SIGN_IN_SUCCESS: Final = "User signed in successfully"

__all__ = [
    "EMAIL_REQUIRED",
    "INTERNAL_ERROR",
    "INVALID_CREDENTIALS",
    "INVALID_ORGANISATION_ID",
    "INVALID_REQUEST_BODY",
    "INVALID_ROLE",
    "ORGANISATION_ID_NOT_ALLOWED",
    "ORGANISATION_ID_REQUIRED",
    "PASSWORD_REQUIRED",
    "ROLE_REQUIRED",
    "SIGN_IN_SUCCESS",
    "UNAUTHORIZED",
    "USER_NOT_AUTHORIZED",
]
