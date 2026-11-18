"""Auth service response messages."""

from typing import Final

SIGN_IN_SUCCESS: Final = "User signed in successfully"

INVALID_REQUEST_BODY: Final = "invalid request body"
EMAIL_REQUIRED: Final = "email is required"
PASSWORD_REQUIRED: Final = "password is required"
ROLE_REQUIRED: Final = "role is required"
INVALID_ROLE: Final = "unknown role"
ORGANISATION_ID_REQUIRED: Final = "organisation id is required"
INVALID_ORGANISATION_ID: Final = "invalid organisation id"
ORGANISATION_ID_NOT_ALLOWED: Final = "organisation id is not allowed for this role"

INVALID_CREDENTIALS: Final = "invalid credentials"
UNAUTHORIZED: Final = "Unauthorized"
USER_NOT_AUTHORIZED: Final = "user not authorized"

INTERNAL_SERVER_ERROR: Final = "internal server error"
