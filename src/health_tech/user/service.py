"""User service handlers."""

from dataclasses import dataclass
from typing import Annotated, Any

from fastapi import Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from health_tech.lib.db import NotFoundError
from health_tech.lib.http import AbortError
from health_tech.lib.ids import uuid_from_string_or_nil
from health_tech.lib.mail import Mailer, MailError
from health_tech.lib.tokenmaker import (
    TokenError,
    TokenPurpose,
    TokenRequirements,
    generate_token,
    validate_token,
)
from health_tech.logger import Clog
from health_tech.user.dto import (
    ConfirmUserRequest,
    ConfirmUserResponse,
    CreateNewUserNoPwdResponse,
    CreateProviderAccountResponse,
    NewProviderAccount,
    NewUserAccount,
)
from health_tech.user.middleware import (
    validate_confirm_user_request,
    validate_create_new_user_account_request,
    validate_create_provider_account_request,
)
from health_tech.user.model import (
    MissingLookupKeyError,
    RoleAccount,
    RoleExistsError,
    User,
    UserRole,
)

SERVICE_NAME = "user"
SELF_REGISTERED_ROLES = frozenset({UserRole.PATIENT, UserRole.SUPER_ADMIN})


@dataclass(slots=True)
class UserService:
    """User service dependencies and HTTP handlers."""

    db: sessionmaker[Session]
    logger: Clog
    mailer: Mailer

    def create_new_user_account(
        self,
        request: Request,
        account: Annotated[NewUserAccount, Depends(validate_create_new_user_account_request)],
    ) -> CreateNewUserNoPwdResponse:
        """Create a user, plus a role account for patients and super admins."""
        req = account.req
        try:
            verification_token = generate_token(
                TokenRequirements(email=req.email, user_id=str(account.user_id), role=req.role),
                TokenPurpose.EMAIL_CONFIRMATION,
            )
        except TokenError as exc:
            self.logger.errorf(request, "Error generating verification token: %s", exc)
            raise AbortError(500, {"message": "internal server error"}) from exc

        user = User(
            id=account.user_id,
            email=req.email,
            first_name=req.first_name,
            last_name=req.last_name,
            date_of_birth=req.date_of_birth,
            contact=req.contact.model_dump(by_alias=True),
            national_id=req.national_id,
        )
        try:
            with self.db.begin() as session:
                self._register_user(request, session, user, account, verification_token)
        except (SQLAlchemyError, RoleExistsError, MailError) as exc:
            self.logger.errorf(request, "Error registering user in transaction: %s", exc)
            raise AbortError(500, {"error": "internal server error"}) from exc

        return CreateNewUserNoPwdResponse(message="User created successfully")

    def _register_user(
        self,
        request: Request,
        session: Session,
        user: User,
        account: NewUserAccount,
        verification_token: str,
    ) -> None:
        req = account.req
        try:
            user.create_new_user(session)
        except SQLAlchemyError as exc:
            self.logger.errorf(request, "Error creating new user: %s", exc)
            raise

        if req.role not in SELF_REGISTERED_ROLES:
            return

        role_account = RoleAccount(
            email=user.email,
            role=req.role,
            user_id=user.id,
            password_hash=account.password_hash,
            is_confirmed=False,
            is_active=True,
        )
        try:
            user_roles = RoleAccount.get_all_user_roles(session, user.id)
        except SQLAlchemyError as exc:
            self.logger.errorf(request, "Error getting user roles: %s", exc)
            raise
        if req.role in user_roles:
            self.logger.errorf(request, "User already has this role: %s", req.role)
            raise RoleExistsError("user already has this role")

        try:
            role_account.create_new_user_account(session)
        except SQLAlchemyError as exc:
            self.logger.errorf(request, "Error creating patient account: %s", exc)
            raise

        try:
            self.mailer.send_confirmation_email(user.email, verification_token)
        except MailError as exc:
            self.logger.errorf(request, "Error sending confirmation email: %s", exc)
            raise

    def get_users(self) -> list[dict[str, Any]]:
        """Return every user."""
        try:
            with self.db() as session:
                return [user.to_json() for user in User.get_users(session)]
        except SQLAlchemyError as exc:
            raise AbortError(500, {"error": str(exc)}) from exc

    def create_provider_account(
        self,
        request: Request,
        account: Annotated[NewProviderAccount, Depends(validate_create_provider_account_request)],
    ) -> CreateProviderAccountResponse:
        """Create a provider role account for an existing user."""
        req = account.req
        try:
            with self.db() as session:
                User.get_single_user(session, user_id=req.user_id)
        except (NotFoundError, SQLAlchemyError) as exc:
            self.logger.errorf(
                request, "Error getting user: %s, user must have a basic account first", exc
            )
            raise AbortError(400, {"error": "user must have a basic account first"}) from exc

        role_account = RoleAccount(
            role_account_id=account.role_account_id,
            user_id=req.user_id,
            email=req.email,
            role=req.role,
            password_hash=account.password_hash,
            is_confirmed=False,
            is_active=True,
        )
        try:
            with self.db() as session:
                user_roles = RoleAccount.get_all_user_roles(session, req.user_id)
        except SQLAlchemyError as exc:
            self.logger.errorf(request, "Error getting user roles: %s", exc)
            raise AbortError(500, {"message": "internal server error"}) from exc
        if req.role in user_roles:
            self.logger.errorf(request, "User already has this role: %s", req.role)
            raise AbortError(400, {"error": "user already has this role"})

        try:
            verification_token = generate_token(
                TokenRequirements(
                    email=req.email, user_id=str(account.role_account_id), role=req.role
                ),
                TokenPurpose.EMAIL_CONFIRMATION,
            )
        except TokenError as exc:
            self.logger.errorf(request, "Error generating verification token: %s", exc)
            raise AbortError(500, {"message": "internal server error"}) from exc
        role_account.confirmation_token = verification_token

        try:
            with self.db.begin() as session:
                self._register_provider(request, session, role_account, verification_token)
        except (SQLAlchemyError, MailError) as exc:
            self.logger.errorf(request, "Error creating provider account in transaction: %s", exc)
            raise AbortError(500, {"error": "internal server error"}) from exc

        return CreateProviderAccountResponse(message="Provider account created successfully")

    def _register_provider(
        self,
        request: Request,
        session: Session,
        role_account: RoleAccount,
        verification_token: str,
    ) -> None:
        try:
            role_account.create_new_user_account(session)
        except SQLAlchemyError as exc:
            self.logger.errorf(request, "Error creating patient account: %s", exc)
            raise

        try:
            self.mailer.send_confirmation_email(role_account.email, verification_token)
        except MailError as exc:
            self.logger.errorf(request, "Error sending confirmation email: %s", exc)
            raise

    def confirm_user(
        self,
        request: Request,
        req: Annotated[ConfirmUserRequest, Depends(validate_confirm_user_request)],
    ) -> ConfirmUserResponse:
        """Confirm the role account named in the confirmation token."""
        try:
            claims = validate_token(req.token, TokenPurpose.EMAIL_CONFIRMATION)
        except TokenError as exc:
            raise AbortError(400, {"error": str(exc)}) from exc

        user_id = uuid_from_string_or_nil(claims.user_id)
        try:
            with self.db() as session:
                User.get_single_user(session, email=claims.email, user_id=user_id)
        except NotFoundError as exc:
            self.logger.errorf(request, "User not found: %s", exc)
            raise AbortError(404, {"error": "user not found"}) from exc
        except (MissingLookupKeyError, SQLAlchemyError) as exc:
            self.logger.errorf(request, "Error getting user: %s", exc)
            raise AbortError(500, {"error": "internal server error"}) from exc

        try:
            with self.db.begin() as session:
                RoleAccount.confirm_user(
                    session, email=claims.email, user_id=user_id, role=claims.role
                )
        except SQLAlchemyError as exc:
            self.logger.errorf(request, "Error confirming user: %s", exc)
            raise AbortError(500, {"error": str(exc)}) from exc

        return ConfirmUserResponse(message="User confirmed successfully")
