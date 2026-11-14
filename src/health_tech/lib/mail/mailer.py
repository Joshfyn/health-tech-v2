"""SMTP and console implementations of Mailer."""

import logging
import smtplib
import sys
from email.message import EmailMessage

from health_tech.lib.config import Settings
from health_tech.lib.env import get_service_host_with_port
from health_tech.lib.mail.interface import Mailer

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_TIMEOUT_SECONDS = 10
SENDER = "no-reply@example.com"
SUBJECT = "Action Required: Confirm Your Email Address"
SCHEME = "http"
CONFIRMATION_PATH = "/health-tech/user/confirm"
BACKEND_SMTP = "smtp"
BACKEND_CONSOLE = "console"

HTML_TEMPLATE = """
<html>
<body>
    <p>Welcome! Your HealthTech registration is almost complete.</p>
    <p>Please click the button below to **verify your email address** and activate your account:</p>

    <div style="margin-top: 20px;">
        <a href="{url}"
           style="padding: 10px 20px; background-color: #007bff; color: white;
                  text-decoration: none; border-radius: 5px; font-weight: bold;">
            Verify My Account
        </a>
    </div>

    <p style="margin-top: 20px; font-size: 10px; color: #888;">
        If the button doesn't work, copy and paste this link into your browser:<br>
        <a href="{url}">{url}</a>
    </p>
    <p>The link will expire in 2 hours.</p>
</body>
</html>
"""

log = logging.getLogger(__name__)


class MailError(Exception):
    """An email could not be sent."""


def confirmation_url(jwt_token: str) -> str:
    """Return the user service link that confirms an account."""
    host, port = get_service_host_with_port("user")
    return f"{SCHEME}://{host}:{port}{CONFIRMATION_PATH}?token={jwt_token}"


def build_confirmation_email(recipient_email: str, jwt_token: str) -> EmailMessage:
    """Build the confirmation email for recipient_email."""
    msg = EmailMessage()
    msg["From"] = SENDER
    msg["To"] = recipient_email
    msg["Subject"] = SUBJECT
    msg.set_content(HTML_TEMPLATE.format(url=confirmation_url(jwt_token)), subtype="html")
    return msg


class SmtpMailer:
    """Sends emails through an SMTP server with STARTTLS."""

    def __init__(
        self,
        user: str,
        password: str,
        host: str = SMTP_HOST,
        port: int = SMTP_PORT,
    ) -> None:
        self._user = user
        self._password = password
        self._host = host
        self._port = port

    def send_confirmation_email(self, recipient_email: str, jwt_token: str) -> None:
        """Send the confirmation email over SMTP."""
        msg = build_confirmation_email(recipient_email, jwt_token)
        if not self._user or not self._password:
            raise MailError("SMTP_PASS or SMTP_USER is not set")
        try:
            with smtplib.SMTP(self._host, self._port, timeout=SMTP_TIMEOUT_SECONDS) as smtp:
                smtp.starttls()
                smtp.login(self._user, self._password)
                smtp.send_message(msg)
        except (smtplib.SMTPException, OSError) as exc:
            raise MailError(f"failed to send confirmation email: {exc}") from exc
        log.info("Verification email successfully dispatched to %s.", recipient_email)


class ConsoleMailer:
    """Prints emails to stdout instead of sending them, for local development."""

    def send_confirmation_email(self, recipient_email: str, jwt_token: str) -> None:
        """Print the confirmation link."""
        sys.stdout.write(
            f"\n--- email to {recipient_email}: {SUBJECT}\n"
            f"Confirm link: {confirmation_url(jwt_token)}\n---\n\n"
        )
        sys.stdout.flush()


def new_mailer(settings: Settings) -> Mailer:
    """Return the mailer selected by MAIL_BACKEND."""
    match settings.mail_backend:
        case "" | "smtp":
            return SmtpMailer(settings.smtp_user, settings.smtp_pass)
        case "console":
            return ConsoleMailer()
        case other:
            raise ValueError(f"unknown MAIL_BACKEND: {other}")
