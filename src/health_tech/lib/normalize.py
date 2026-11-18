"""Case handlers: the one place that decides how values are lower-cased.

Emails and first and last names are stored in lower case, so they compare without regard to
case: Sam@Example.com and sam@example.com are one email. Every path that writes or looks up
one of these values goes through a handler here:

- request models, before validation (lib/validation.py: Email, PersonName);
- the database models, on every write however it is made, e.g. the seed script
  (user/model.py: User, RoleAccount);
- lookups by email (RoleAccount queries, confirmation links);
- migrate-db, whose SQLite lower() is lower_case (migrate/migrations.py).

Passwords, roles, national IDs and contact details are never lower-cased: passwords and
roles must match exactly, and IDs and addresses keep the case they were given.

Lower-casing is full Unicode (ÉLODIE -> élodie, ØRSTED -> ørsted), not ASCII only.
"""


def lower_case(value: str | None) -> str | None:
    """Lower-case every letter of value, in any script; None stays None."""
    return value.lower() if value is not None else None


def lower_email(value: str | None) -> str | None:
    """Handler for emails: stored and compared in lower case."""
    return lower_case(value)


def lower_name(value: str | None) -> str | None:
    """Handler for first and last names: stored in lower case."""
    return lower_case(value)
