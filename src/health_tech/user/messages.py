"""User service response messages for listing users, reading a user's record, confirmation,
logins whose email and role are taken, and provider organisations."""

from typing import Final

INVALID_PAGE: Final = "page must be a positive integer"
INVALID_PAGE_SIZE: Final = "pageSize must be a positive integer"

FORBIDDEN: Final = "Forbidden"
USER_NOT_FOUND: Final = "user not found"
INVALID_CONFIRMATION_TOKEN: Final = "invalid confirmation token"
ACCOUNT_EXISTS: Final = "an account with this email and role already exists"

EMAIL_REQUIRED: Final = "email is required"
ORGANISATION_ID_REQUIRED: Final = "organisation id is required"
NOT_ORGANISATION_ROLE: Final = "role does not work for organisations"
PROVIDER_NOT_FOUND: Final = "provider account not found"
ALREADY_IN_ORGANISATION: Final = "provider already works for this organisation"
PROVIDER_ADDED_TO_ORGANISATION: Final = "Provider added to organisation"

INTERNAL_SERVER_ERROR: Final = "internal server error"
