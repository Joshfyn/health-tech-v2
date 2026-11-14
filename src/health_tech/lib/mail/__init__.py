"""Transactional email clients."""

from health_tech.lib.mail.interface import Mailer
from health_tech.lib.mail.mailer import ConsoleMailer, MailError, SmtpMailer, new_mailer

__all__ = ["ConsoleMailer", "MailError", "Mailer", "SmtpMailer", "new_mailer"]
