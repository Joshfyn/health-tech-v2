"""Seed the database with sample users."""

import uuid
from datetime import UTC, datetime

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from health_tech.lib.db import connect_to_db
from health_tech.user.model import Address, Contact, User


def sample_users(now: datetime) -> list[User]:
    """Return three sample users with placeholder details."""
    samples = [
        ("user1@example.com", "Sample", "Patient", "123439371", datetime(1990, 5, 15, tzinfo=UTC)),
        ("user2@example.com", "Sample", "Doctor", "123439372", None),
        ("user3@example.com", "Sample", "Pharmacist", "123439373", None),
    ]
    return [
        User(
            id=uuid.uuid4(),
            email=email,
            first_name=first_name,
            last_name=last_name,
            date_of_birth=date_of_birth,
            contact=Contact(
                phone=phone,
                address=Address(
                    street="1 Example Street",
                    city="Example City",
                    state="EX",
                    zip_code="00000",
                    country="US",
                ),
            ).model_dump(by_alias=True),
            created_at=now,
            updated_at=now,
        )
        for email, first_name, last_name, phone, date_of_birth in samples
    ]


def create_sample_users(session: Session) -> None:
    """Insert the sample users."""
    print("Creating 3 sample users...")
    session.add_all(sample_users(datetime.now(UTC)))
    print("Created 3 users successfully!")


def main() -> None:
    """Create the tables and insert the sample data."""
    print("Health-Tech Database Initialization")
    try:
        db = connect_to_db()
        with db.begin() as session:
            create_sample_users(session)
    except SQLAlchemyError as exc:
        raise SystemExit(f"Initialization failed: {exc}") from exc
    print("Database initialization completed successfully!")


if __name__ == "__main__":
    main()
