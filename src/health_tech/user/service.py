"""User service handlers."""

import math
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated

from fastapi import Depends
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from health_tech.lib.db import NotFoundError
from health_tech.lib.http import AbortError
from health_tech.lib.ids import NIL_UUID, uuid_from_string_or_nil
from health_tech.lib.mail import Mailer, MailError
from health_tech.lib.normalize import lower_email
from health_tech.lib.tokenmaker import (
    TokenError,
    TokenPurpose,
    TokenRequirements,
    generate_token,
    validate_token,
)
from health_tech.logger import log
from health_tech.user import messages
from health_tech.user.dto import (
    AddProviderOrganisationResponse,
    ConfirmUserRequest,
    ConfirmUserResponse,
    CreateNewUserNoPwdResponse,
    CreateProviderAccountResponse,
    ListUsersRequest,
    ListUsersResponse,
    NewProviderAccount,
    NewUserAccount,
    ProviderOrganisation,
    UserResponse,
    UserSummaryResponse,
)
from health_tech.user.middleware import (
    authorize_user_record_access,
    validate_add_provider_organisation_request,
    validate_confirm_user_request,
    validate_create_new_user_account_request,
    validate_create_provider_account_request,
    validate_list_users_request,
)
from health_tech.user.model import (
    SELF_REGISTERED_ROLES,
    AccountExistsError,
    OrganisationMembership,
    RoleAccount,
    RoleExistsError,
    User,
)

SERVICE_NAME = "user"


@dataclass(slots=True)
class UserService:
    """User service dependencies and HTTP handlers."""

    db: sessionmaker[Session]
    mailer: Mailer

    def create_new_user_account(
        self,
        account: Annotated[NewUserAccount, Depends(validate_create_new_user_account_request)],
    ) -> CreateNewUserNoPwdResponse:
        """Create a user, plus a role account for patients and super admins."""
        req = account.req
        try:
            verification_token = generate_token(
                TokenRequirements(
                    email=req.email,
                    user_id=str(account.user_id),
                    role_account_id=str(account.role_account_id),
                    role=req.role,
                ),
                TokenPurpose.EMAIL_CONFIRMATION,
            )
        except TokenError as exc:
            log.error("Error generating verification token: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

        now = datetime.now(UTC)
        user = User(
            id=account.user_id,
            email=req.email,
            first_name=req.first_name,
            last_name=req.last_name,
            date_of_birth=req.date_of_birth,
            contact=req.contact.model_dump(by_alias=True),
            national_id=req.national_id,
            created_at=now,
            updated_at=now,
        )
        try:
            with self.db.begin() as session:
                self._register_user(session, user, account, verification_token)
        except AccountExistsError as exc:
            raise self._account_exists(req.role) from exc
        except IntegrityError as exc:
            if req.role in SELF_REGISTERED_ROLES and self._email_role_taken(req.email, req.role):
                raise self._account_exists(req.role) from exc
            log.error("Error registering user in transaction: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        except (SQLAlchemyError, RoleExistsError, MailError) as exc:
            log.error("Error registering user in transaction: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

        return CreateNewUserNoPwdResponse(message=messages.USER_CREATED)

    def _register_user(
        self,
        session: Session,
        user: User,
        account: NewUserAccount,
        verification_token: str,
    ) -> None:
        req = account.req
        try:
            user.create_new_user(session)
        except SQLAlchemyError as exc:
            log.error("Error creating new user: %s", exc)
            raise

        if req.role not in SELF_REGISTERED_ROLES:
            return

        role_account = RoleAccount(
            role_account_id=account.role_account_id,
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
            log.error("Error getting user roles: %s", exc)
            raise
        if req.role in user_roles:
            log.error("User already has this role: %s", req.role)
            raise RoleExistsError("user already has this role")

        self._check_email_role_free(session, role_account)
        try:
            role_account.create_new_user_account(session)
        except SQLAlchemyError as exc:
            log.error("Error creating patient account: %s", exc)
            raise

        try:
            self.mailer.send_confirmation_email(user.email, verification_token)
        except MailError as exc:
            log.error("Error sending confirmation email: %s", exc)
            raise

    def get_users(
        self,
        req: Annotated[ListUsersRequest, Depends(validate_list_users_request)],
    ) -> ListUsersResponse:
        """Return one page of users. Super admins only."""
        try:
            with self.db() as session:
                users, total = User.get_users_page(session, offset=req.offset, limit=req.page_size)
                page = [UserSummaryResponse.from_user(user) for user in users]
        except SQLAlchemyError as exc:
            log.error("Error listing users: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        return ListUsersResponse(
            users=page,
            page=req.page,
            page_size=req.page_size,
            total=total,
            total_pages=math.ceil(total / req.page_size),
        )

    def get_user(
        self,
        user_id: Annotated[uuid.UUID, Depends(authorize_user_record_access)],
    ) -> UserResponse:
        """Return one user's record: any user for super admins, only their own for patients."""
        try:
            with self.db() as session:
                return UserResponse.from_user(User.get_user(session, user_id))
        except NotFoundError as exc:
            raise AbortError(messages.USER_NOT_FOUND) from exc
        except SQLAlchemyError as exc:
            log.error("Error getting user: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

    def create_provider_account(
        self,
        account: Annotated[NewProviderAccount, Depends(validate_create_provider_account_request)],
    ) -> CreateProviderAccountResponse:
        """Create a provider role account for an existing user."""
        req = account.req
        try:
            with self.db() as session:
                User.get_single_user(session, user_id=req.user_id)
        except NotFoundError as exc:
            log.error("User must have a basic account first: %s", exc)
            raise AbortError(messages.BASIC_ACCOUNT_REQUIRED) from exc
        except SQLAlchemyError as exc:
            log.error("Error getting user: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

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
            log.error("Error getting user roles: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        if req.role in user_roles:
            log.error("User already has this role: %s", req.role)
            raise AbortError(messages.ROLE_ALREADY_HELD)

        try:
            verification_token = generate_token(
                TokenRequirements(
                    email=req.email,
                    user_id=str(req.user_id),
                    role_account_id=str(account.role_account_id),
                    role=req.role,
                ),
                TokenPurpose.EMAIL_CONFIRMATION,
            )
        except TokenError as exc:
            log.error("Error generating verification token: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        role_account.confirmation_token = verification_token

        try:
            with self.db.begin() as session:
                self._register_provider(
                    session, role_account, account.organisation_id, verification_token
                )
        except AccountExistsError as exc:
            raise self._account_exists(req.role) from exc
        except IntegrityError as exc:
            if self._email_role_taken(req.email, req.role):
                raise self._account_exists(req.role) from exc
            log.error("Error creating provider account in transaction: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        except (SQLAlchemyError, MailError) as exc:
            log.error("Error creating provider account in transaction: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

        return CreateProviderAccountResponse(message=messages.PROVIDER_CREATED)

    def _register_provider(
        self,
        session: Session,
        role_account: RoleAccount,
        organisation_id: uuid.UUID,
        verification_token: str,
    ) -> None:
        self._check_email_role_free(session, role_account)
        try:
            role_account.create_new_user_account(session)
            OrganisationMembership(
                role_account_id=role_account.role_account_id,
                organisation_id=organisation_id,
                created_at=datetime.now(UTC),
            ).add(session)
        except SQLAlchemyError as exc:
            log.error("Error creating provider account: %s", exc)
            raise

        try:
            self.mailer.send_confirmation_email(role_account.email, verification_token)
        except MailError as exc:
            log.error("Error sending confirmation email: %s", exc)
            raise

    def add_provider_organisation(
        self,
        req: Annotated[ProviderOrganisation, Depends(validate_add_provider_organisation_request)],
    ) -> AddProviderOrganisationResponse:
        """Let an existing provider login work for another organisation too."""
        try:
            with self.db.begin() as session:
                account = RoleAccount.get_by_email_and_role(session, email=req.email, role=req.role)
                if OrganisationMembership.is_member(
                    session,
                    role_account_id=account.role_account_id,
                    organisation_id=req.organisation_id,
                ):
                    raise AbortError(messages.ALREADY_IN_ORGANISATION)
                OrganisationMembership(
                    role_account_id=account.role_account_id,
                    organisation_id=req.organisation_id,
                    created_at=datetime.now(UTC),
                ).add(session)
        except NotFoundError as exc:
            raise AbortError(messages.PROVIDER_NOT_FOUND) from exc
        except IntegrityError as exc:
            # Another request added the same membership between the check and the insert.
            if self._is_member_after_failed_insert(req):
                raise AbortError(messages.ALREADY_IN_ORGANISATION) from exc
            log.error("Error adding provider to organisation: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        except SQLAlchemyError as exc:
            log.error("Error adding provider to organisation: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        return AddProviderOrganisationResponse(message=messages.PROVIDER_ADDED_TO_ORGANISATION)

    def _is_member_after_failed_insert(self, req: ProviderOrganisation) -> bool:
        try:
            with self.db() as session:
                account = RoleAccount.get_by_email_and_role(session, email=req.email, role=req.role)
                return OrganisationMembership.is_member(
                    session,
                    role_account_id=account.role_account_id,
                    organisation_id=req.organisation_id,
                )
        except NotFoundError, SQLAlchemyError:
            return False

    def _check_email_role_free(self, session: Session, role_account: RoleAccount) -> None:
        """Raise AccountExistsError if a login already has role_account's email and role."""
        try:
            taken = RoleAccount.email_role_taken(
                session, email=role_account.email, role=role_account.role
            )
        except SQLAlchemyError as exc:
            log.error("Error checking email and role: %s", exc)
            raise
        if taken:
            raise AccountExistsError("an account with this email and role already exists")

    def _email_role_taken(self, email: str, role: str) -> bool:
        """Check in a new session, after a failed insert has rolled its transaction back.

        The unique index refuses a login whose email and role another request took between
        the check and the insert; this tells that apart from other integrity errors.
        """
        try:
            with self.db() as session:
                return RoleAccount.email_role_taken(session, email=email, role=role)
        except SQLAlchemyError:
            return False

    def _account_exists(self, role: str) -> AbortError:
        log.error("An account with this email and role %s already exists", role)
        return AbortError(messages.ACCOUNT_EXISTS)

    def confirm_user(
        self,
        req: Annotated[ConfirmUserRequest, Depends(validate_confirm_user_request)],
    ) -> ConfirmUserResponse:
        """Confirm the role account named in the confirmation token."""
        try:
            claims = validate_token(req.token, TokenPurpose.EMAIL_CONFIRMATION)
        except TokenError as exc:
            # The reason (expired, bad signature, ...) is for the log, not the client.
            log.info("Invalid confirmation token: %s", exc)
            raise AbortError(messages.INVALID_CONFIRMATION_TOKEN) from exc

        # UserID is the person; RoleAccountID, when present, is the exact login to confirm.
        user_id = uuid_from_string_or_nil(claims.user_id)
        role_account_id = None
        if claims.role_account_id:
            role_account_id = uuid_from_string_or_nil(claims.role_account_id)
        if user_id == NIL_UUID or role_account_id == NIL_UUID:
            log.error("Confirmation token has an invalid user or account id")
            raise AbortError(messages.INVALID_CONFIRMATION_TOKEN)

        try:
            with self.db.begin() as session:
                User.get_user(session, user_id)
                confirmed = RoleAccount.confirm_user(
                    session,
                    # Links emailed before emails were stored in lower case carry the old case.
                    email=lower_email(claims.email),
                    user_id=user_id,
                    role=claims.role,
                    role_account_id=role_account_id,
                )
        except NotFoundError as exc:
            log.error("User not found: %s", exc)
            raise AbortError(messages.USER_NOT_FOUND) from exc
        except SQLAlchemyError as exc:
            log.error("Error confirming user: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc
        if not confirmed:
            log.error("No role account matches the confirmation token")
            raise AbortError(messages.USER_NOT_FOUND)

        return ConfirmUserResponse(message=messages.USER_CONFIRMED)
