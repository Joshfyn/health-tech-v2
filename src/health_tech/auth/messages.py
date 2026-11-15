"""Auth service response messages."""

from typing import Final

SIGN_IN_SUCCESS: Final = "User signed in successfully"

INVALID_REQUEST_BODY: Final = "invalid request body"
EMAIL_REQUIRED: Final = "email is required"
PASSWORD_REQUIRED: Final = "password is required"

INVALID_CREDENTIALS: Final = "invalid credentials"
UNAUTHORIZED: Final = "Unauthorized"
USER_NOT_AUTHORIZED: Final = "user not authorized"

INTERNAL_SERVER_ERROR: Final = "internal server error"
