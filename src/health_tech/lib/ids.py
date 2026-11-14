"""UUID helpers."""

import uuid

NIL_UUID = uuid.UUID(int=0)


def uuid_from_string_or_nil(value: str) -> uuid.UUID:
    """Parse a UUID, returning NIL_UUID when value is not a valid UUID."""
    try:
        return uuid.UUID(value)
    except ValueError:
        return NIL_UUID
