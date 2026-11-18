"""Every error the services return: one shape, a fixed snake_case code, our own message.

Error bodies are always {"code": "<snake_case>", "error": "<message>"}. Codes are part of the
API contract: clients branch on them, so never rename one. Messages are written here, never
taken from a library, the database or an exception, so no internal detail reaches a client.

Field rule errors carry "{field}" in their message; for_field() names the request field that
broke the rule (an alias from our own request models, never a client-supplied key).
"""

from dataclasses import dataclass, replace
from enum import StrEnum
from typing import Final

from pydantic import BaseModel

FIELD_PLACEHOLDER: Final = "{field}"


class ErrorCode(StrEnum):
    """Every error code the services can return."""

    # Requests
    INVALID_REQUEST = "invalid_request"
    INVALID_REQUEST_BODY = "invalid_request_body"
    UNSAFE_INPUT = "unsafe_input"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    NOT_FOUND = "not_found"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    INTERNAL_ERROR = "internal_error"

    # Field rules
    VALUE_TOO_LONG = "value_too_long"
    INVALID_EMAIL = "invalid_email"
    INVALID_NAME = "invalid_name"
    INVALID_DATE_OF_BIRTH = "invalid_date_of_birth"
    INVALID_PHONE = "invalid_phone"
    INVALID_NATIONAL_ID = "invalid_national_id"
    INVALID_POSTAL_CODE = "invalid_postal_code"
    PASSWORD_TOO_SHORT = "password_too_short"
    PASSWORD_TOO_LONG = "password_too_long"

    # Required values
    EMAIL_REQUIRED = "email_required"
    PASSWORD_REQUIRED = "password_required"
    ROLE_REQUIRED = "role_required"
    FIRST_NAME_REQUIRED = "first_name_required"
    LAST_NAME_REQUIRED = "last_name_required"
    USER_ID_REQUIRED = "user_id_required"
    ORGANISATION_ID_REQUIRED = "organisation_id_required"

    # Roles and organisations
    INVALID_ROLE = "invalid_role"
    ACCOUNT_ROLE_NOT_ALLOWED = "account_role_not_allowed"
    NOT_PROVIDER_ROLE = "not_provider_role"
    NOT_ORGANISATION_ROLE = "not_organisation_role"
    INVALID_ORGANISATION_ID = "invalid_organisation_id"
    ORGANISATION_ID_NOT_ALLOWED = "organisation_id_not_allowed"

    # Authentication and authorization
    UNAUTHORIZED = "unauthorized"
    ROLE_NOT_ALLOWED = "role_not_allowed"
    USER_NOT_AUTHORIZED = "user_not_authorized"
    INVALID_CREDENTIALS = "invalid_credentials"
    FORBIDDEN = "forbidden"
    INVALID_CONFIRMATION_TOKEN = "invalid_confirmation_token"

    # Paging
    INVALID_PAGE = "invalid_page"
    INVALID_PAGE_SIZE = "invalid_page_size"

    # Users and accounts
    USER_NOT_FOUND = "user_not_found"
    BASIC_ACCOUNT_REQUIRED = "basic_account_required"
    ROLE_ALREADY_HELD = "role_already_held"
    ACCOUNT_EXISTS = "account_exists"
    PROVIDER_NOT_FOUND = "provider_not_found"
    ALREADY_IN_ORGANISATION = "already_in_organisation"


class AbortError(Exception):
    """Stops the request and responds with error."""

    def __init__(self, error: ApiError) -> None:
        super().__init__(error.status, error.code)
        self.error = error


class ErrorResponse(BaseModel):
    """The body of every error response."""

    code: str
    error: str


@dataclass(frozen=True, slots=True)
class ApiError:
    """An error response: HTTP status, fixed code and client-safe message."""

    status: int
    code: ErrorCode
    message: str

    def for_field(self, field: str) -> ApiError:
        """Return this error with {field} in its message replaced by field."""
        return replace(self, message=self.message.replace(FIELD_PLACEHOLDER, field))

    def body(self) -> dict[str, str]:
        """Return the JSON body of this error."""
        return ErrorResponse(code=self.code.value, error=self.message).model_dump()


# --- Requests ---
INVALID_REQUEST = ApiError(400, ErrorCode.INVALID_REQUEST, "invalid request")
INVALID_REQUEST_BODY = ApiError(400, ErrorCode.INVALID_REQUEST_BODY, "invalid request body")
PAYLOAD_TOO_LARGE = ApiError(413, ErrorCode.PAYLOAD_TOO_LARGE, "request body is too large")
NOT_FOUND = ApiError(404, ErrorCode.NOT_FOUND, "not found")
METHOD_NOT_ALLOWED = ApiError(405, ErrorCode.METHOD_NOT_ALLOWED, "method not allowed")
INTERNAL_ERROR = ApiError(500, ErrorCode.INTERNAL_ERROR, "internal server error")

# --- Field rules (message names the field) ---
UNSAFE_INPUT = ApiError(
    400,
    ErrorCode.UNSAFE_INPUT,
    "{field} contains characters or content that are not allowed",
)
VALUE_TOO_LONG = ApiError(400, ErrorCode.VALUE_TOO_LONG, "{field} is too long")
INVALID_EMAIL = ApiError(400, ErrorCode.INVALID_EMAIL, "{field} must be a valid email address")
INVALID_NAME = ApiError(
    400,
    ErrorCode.INVALID_NAME,
    "{field} may contain only letters, spaces, apostrophes, hyphens and full stops",
)
INVALID_DATE_OF_BIRTH = ApiError(
    400, ErrorCode.INVALID_DATE_OF_BIRTH, "{field} must be a date in the past"
)
INVALID_PHONE = ApiError(
    400, ErrorCode.INVALID_PHONE, "{field} may contain only digits, spaces and + ( ) - ."
)
INVALID_NATIONAL_ID = ApiError(
    400,
    ErrorCode.INVALID_NATIONAL_ID,
    "{field} may contain only letters, digits, spaces and - . /",
)
INVALID_POSTAL_CODE = ApiError(
    400,
    ErrorCode.INVALID_POSTAL_CODE,
    "{field} may contain only letters, digits, spaces and hyphens",
)
PASSWORD_TOO_SHORT = ApiError(
    400, ErrorCode.PASSWORD_TOO_SHORT, "{field} must be at least 8 characters"
)
PASSWORD_TOO_LONG = ApiError(400, ErrorCode.PASSWORD_TOO_LONG, "{field} must be at most 72 bytes")

# --- Required values ---
EMAIL_REQUIRED = ApiError(400, ErrorCode.EMAIL_REQUIRED, "email is required")
PASSWORD_REQUIRED = ApiError(400, ErrorCode.PASSWORD_REQUIRED, "password is required")
ROLE_REQUIRED = ApiError(400, ErrorCode.ROLE_REQUIRED, "role is required")
FIRST_NAME_REQUIRED = ApiError(400, ErrorCode.FIRST_NAME_REQUIRED, "first name is required")
LAST_NAME_REQUIRED = ApiError(400, ErrorCode.LAST_NAME_REQUIRED, "last name is required")
USER_ID_REQUIRED = ApiError(400, ErrorCode.USER_ID_REQUIRED, "user id is required")
ORGANISATION_ID_REQUIRED = ApiError(
    400, ErrorCode.ORGANISATION_ID_REQUIRED, "organisation id is required"
)

# --- Roles and organisations ---
# Deliberately does not list the roles.
INVALID_ROLE = ApiError(400, ErrorCode.INVALID_ROLE, "unknown role")
# POST /health-tech/user creates patient and super admin logins only.
ACCOUNT_ROLE_NOT_ALLOWED = ApiError(
    400,
    ErrorCode.ACCOUNT_ROLE_NOT_ALLOWED,
    "doctors, pharmacists and hospital or pharmacy admins are created with "
    "POST /health-tech/user/healthcare-providers",
)
NOT_PROVIDER_ROLE = ApiError(
    400, ErrorCode.NOT_PROVIDER_ROLE, "role is not a healthcare provider role"
)
NOT_ORGANISATION_ROLE = ApiError(
    400, ErrorCode.NOT_ORGANISATION_ROLE, "role does not work for organisations"
)
INVALID_ORGANISATION_ID = ApiError(
    400, ErrorCode.INVALID_ORGANISATION_ID, "invalid organisation id"
)
ORGANISATION_ID_NOT_ALLOWED = ApiError(
    400, ErrorCode.ORGANISATION_ID_NOT_ALLOWED, "organisation id is not allowed for this role"
)

# --- Authentication and authorization ---
UNAUTHORIZED = ApiError(401, ErrorCode.UNAUTHORIZED, "Unauthorized")
# The caller's token is valid, but their role may not use the endpoint at all. Not retryable:
# signing in again gives the same role.
ROLE_NOT_ALLOWED = ApiError(
    401, ErrorCode.ROLE_NOT_ALLOWED, "this role is not allowed to use this endpoint"
)
USER_NOT_AUTHORIZED = ApiError(401, ErrorCode.USER_NOT_AUTHORIZED, "user not authorized")
# One answer for every sign-in failure, so it does not reveal which emails have accounts.
INVALID_CREDENTIALS = ApiError(401, ErrorCode.INVALID_CREDENTIALS, "invalid credentials")
FORBIDDEN = ApiError(403, ErrorCode.FORBIDDEN, "Forbidden")
INVALID_CONFIRMATION_TOKEN = ApiError(
    400, ErrorCode.INVALID_CONFIRMATION_TOKEN, "invalid confirmation token"
)

# --- Paging ---
INVALID_PAGE = ApiError(400, ErrorCode.INVALID_PAGE, "page must be a positive integer")
INVALID_PAGE_SIZE = ApiError(
    400, ErrorCode.INVALID_PAGE_SIZE, "pageSize must be a positive integer"
)

# --- Users and accounts ---
USER_NOT_FOUND = ApiError(404, ErrorCode.USER_NOT_FOUND, "user not found")
BASIC_ACCOUNT_REQUIRED = ApiError(
    400, ErrorCode.BASIC_ACCOUNT_REQUIRED, "user must have a basic account first"
)
ROLE_ALREADY_HELD = ApiError(400, ErrorCode.ROLE_ALREADY_HELD, "user already has this role")
ACCOUNT_EXISTS = ApiError(
    409, ErrorCode.ACCOUNT_EXISTS, "an account with this email and role already exists"
)
PROVIDER_NOT_FOUND = ApiError(404, ErrorCode.PROVIDER_NOT_FOUND, "provider account not found")
ALREADY_IN_ORGANISATION = ApiError(
    409, ErrorCode.ALREADY_IN_ORGANISATION, "provider already works for this organisation"
)


# Every error, by code. A code belongs to exactly one error.
CATALOG: Final[dict[ErrorCode, ApiError]] = {
    error.code: error for error in globals().copy().values() if isinstance(error, ApiError)
}

# Errors a request model's field validators raise, looked up by pydantic error type.
FIELD_RULES: Final[dict[str, ApiError]] = {
    error.code.value: error for error in CATALOG.values() if FIELD_PLACEHOLDER in error.message
}
