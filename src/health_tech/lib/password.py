"""bcrypt password hashing."""

import bcrypt

DEFAULT_COST = 10


class PasswordError(ValueError):
    """A password could not be hashed or does not match its hash."""


def generate_from_password(password: str, cost: int = DEFAULT_COST) -> str:
    """Return the bcrypt hash of password."""
    try:
        return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost)).decode()
    except ValueError as exc:
        raise PasswordError(str(exc)) from exc


def compare_hash_and_password(hashed: str, password: str) -> None:
    """Raise PasswordError unless password matches the bcrypt hash."""
    try:
        matches = bcrypt.checkpw(password.encode(), hashed.encode())
    except ValueError as exc:
        raise PasswordError(str(exc)) from exc
    if not matches:
        raise PasswordError("hashedPassword is not the hash of the given password")
