"""Base request and response models and the field types requests are validated with.

Request models drop fields they do not declare. Each field type below raises an error whose
type is an ErrorCode (see lib/errors.py); bind_json answers with that code and our message,
never with the library's.

Empty strings pass the field types: whether a value is required depends on the endpoint, and
is checked there, in order, so each missing value gets its own *_required code.
"""

import re
import unicodedata
from datetime import UTC, datetime
from typing import Annotated, Any, Final

from pydantic import AfterValidator, BaseModel, BeforeValidator, ConfigDict
from pydantic_core import PydanticCustomError

from health_tech.lib import errors
from health_tech.lib.errors import ApiError
from health_tech.lib.normalize import lower_email, lower_name
from health_tech.lib.safe_text import unsafe_reason

EMAIL_MAX_LENGTH: Final = 254
EMAIL_LOCAL_MAX_LENGTH: Final = 64
NAME_MAX_LENGTH: Final = 100
PASSWORD_MIN_LENGTH: Final = 8
# bcrypt refuses longer passwords.
PASSWORD_MAX_BYTES: Final = 72
PHONE_MAX_LENGTH: Final = 32
NATIONAL_ID_MAX_LENGTH: Final = 32
POSTAL_CODE_MAX_LENGTH: Final = 16
STREET_MAX_LENGTH: Final = 200
ADDRESS_PART_MAX_LENGTH: Final = 100
EARLIEST_DATE_OF_BIRTH: Final = datetime(1900, 1, 1, tzinfo=UTC)

# A deliberately plain address: letters, digits and . _ + ' - before the @, dot-separated
# labels after it, ending in an alphabetic top-level domain. Checked after lower-casing.
_EMAIL_LOCAL = r"[a-z0-9_+'-]+(?:\.[a-z0-9_+'-]+)*"
_DOMAIN_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
EMAIL_PATTERN: Final = re.compile(rf"{_EMAIL_LOCAL}@(?:{_DOMAIN_LABEL}\.)+[a-z]{{2,63}}")
PHONE_PATTERN: Final = re.compile(r"\+?[0-9][0-9 ().\-]*")
NATIONAL_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 .\-/]*")
POSTAL_CODE_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9 \-]*")
NAME_PUNCTUATION: Final = frozenset(" '’-.")


def rule_error(error: ApiError) -> PydanticCustomError:
    """Return the validation error that bind_json answers with error."""
    return PydanticCustomError(error.code.value, error.message)


def _max_length(limit: int):
    def check(value: str) -> str:
        if len(value) > limit:
            raise rule_error(errors.VALUE_TOO_LONG)
        return value

    return AfterValidator(check)


def _safe(value: str) -> str:
    if unsafe_reason(value) is not None:
        raise rule_error(errors.UNSAFE_INPUT)
    return value


def _pattern(pattern: re.Pattern[str], error: ApiError):
    def check(value: str) -> str:
        if value and not pattern.fullmatch(value):
            raise rule_error(error)
        return value

    return AfterValidator(check)


def _email(value: str) -> str:
    # Emails compare without regard to case, so they are lower-cased before anything else.
    value = lower_email(value)
    if not value:
        return value
    if (
        len(value) > EMAIL_MAX_LENGTH
        or not EMAIL_PATTERN.fullmatch(value)
        or len(value.partition("@")[0]) > EMAIL_LOCAL_MAX_LENGTH
    ):
        raise rule_error(errors.INVALID_EMAIL)
    return value


def _is_name_character(char: str) -> bool:
    return char in NAME_PUNCTUATION or unicodedata.category(char).startswith(("L", "M"))


def _lower_name(value: str) -> str:
    # Before the other checks, so they apply to the value that is stored.
    return lower_name(value)


def _person_name(value: str) -> str:
    # Not trimmed: leading or trailing spaces are refused, not silently removed.
    if not value:
        return value
    if (
        not unicodedata.category(value[0]).startswith("L")
        or value[-1].isspace()
        or not all(_is_name_character(c) for c in value)
    ):
        raise rule_error(errors.INVALID_NAME)
    return value


def _password(value: str) -> str:
    if len(value.encode()) > PASSWORD_MAX_BYTES:
        raise rule_error(errors.PASSWORD_TOO_LONG)
    return value


def _new_password(value: str) -> str:
    if value and len(value) < PASSWORD_MIN_LENGTH:
        raise rule_error(errors.PASSWORD_TOO_SHORT)
    return _password(value)


def _date_of_birth_string(value: Any) -> Any:
    # Only ISO 8601 text: pydantic would otherwise read a number as seconds since 1970.
    if value is not None and not isinstance(value, str):
        raise rule_error(errors.INVALID_DATE_OF_BIRTH)
    return value


def _date_of_birth(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:  # a date, or a time without an offset: read as UTC
        value = value.replace(tzinfo=UTC)
    if not EARLIEST_DATE_OF_BIRTH <= value < datetime.now(UTC):
        raise rule_error(errors.INVALID_DATE_OF_BIRTH)
    return value


# Lower-cased, then a valid address of at most 254 characters; "" passes.
Email = Annotated[str, AfterValidator(_email)]
# Lower-cased, then letters, combining marks, spaces, apostrophes, hyphens and full stops;
# starts with a letter; at most 100 characters.
PersonName = Annotated[
    str,
    AfterValidator(_lower_name),
    _max_length(NAME_MAX_LENGTH),
    AfterValidator(_person_name),
]
# Any characters, at most 72 bytes (checked at sign in, where no minimum applies).
Password = Annotated[str, AfterValidator(_password)]
# A password being set: 8 characters to 72 bytes.
NewPassword = Annotated[str, AfterValidator(_new_password)]
# In the past and not before 1900; a value without an offset is UTC.
DateOfBirth = Annotated[
    datetime | None, BeforeValidator(_date_of_birth_string), AfterValidator(_date_of_birth)
]
Phone = Annotated[str, _max_length(PHONE_MAX_LENGTH), _pattern(PHONE_PATTERN, errors.INVALID_PHONE)]
NationalId = Annotated[
    str,
    _max_length(NATIONAL_ID_MAX_LENGTH),
    _pattern(NATIONAL_ID_PATTERN, errors.INVALID_NATIONAL_ID),
]
PostalCode = Annotated[
    str,
    _max_length(POSTAL_CODE_MAX_LENGTH),
    _pattern(POSTAL_CODE_PATTERN, errors.INVALID_POSTAL_CODE),
]
Street = Annotated[str, _max_length(STREET_MAX_LENGTH), AfterValidator(_safe)]
AddressPart = Annotated[str, _max_length(ADDRESS_PART_MAX_LENGTH), AfterValidator(_safe)]


class RequestModel(BaseModel):
    """Base of every request body. Fields it does not declare are dropped."""

    model_config = ConfigDict(extra="ignore", populate_by_name=True)


class ResponseModel(BaseModel):
    """Base of every response body. Serialised with the API's field names."""

    model_config = ConfigDict(populate_by_name=True, serialize_by_alias=True)
