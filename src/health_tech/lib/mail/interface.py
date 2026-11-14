"""Mailer contract the services depend on."""

from typing import Protocol


class Mailer(Protocol):
    """Sends transactional emails."""

    def send_confirmation_email(self, recipient_email: str, jwt_token: str) -> None:
        """Send the email-confirmation link carrying jwt_token."""
        ...
