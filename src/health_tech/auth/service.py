"""Auth service handlers."""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from health_tech.auth import messages
from health_tech.auth.dto import (
    RefreshTokenRequest,
    RefreshTokenResponse,
    SignInAttempt,
    SignInUserResponse,
    ValidateTokenRequest,
    ValidateTokenResponse,
)
from health_tech.auth.middleware import (
    validate_refresh_token_request,
    validate_sign_in_user_request,
    validate_token_request,
)
from health_tech.auth.model import (
    AmbiguousAccountError,
    Auth,
    MissingAccountIdError,
    UserNotFoundError,
)
from health_tech.lib.http import AbortError
from health_tech.lib.password import PasswordError, compare_hash_and_password
from health_tech.lib.tokenmaker import (
    TokenError,
    TokenPurpose,
    TokenRequirements,
    generate_token,
)
from health_tech.lib.tokenmaker import validate_token as validate_jwt
from health_tech.logger import log

SERVICE_NAME = "auth"


@dataclass(slots=True)
class AuthService:
    """Auth service dependencies and HTTP handlers."""

    db: sessionmaker[Session]

    def sign_in_user(
        self,
        req: Annotated[SignInAttempt, Depends(validate_sign_in_user_request)],
    ) -> SignInUserResponse:
        """Check credentials and return access and refresh tokens."""
        auth = Auth(email=req.email, role=req.role, organisation_id=req.organisation_id)
        try:
            with self.db() as session:
                auth.get_user_by_email_and_role(session)
        except UserNotFoundError as exc:
            # Same as a wrong password, so emails and the roles they hold can't be probed.
            log.with_field("role", req.role).error(
                "No confirmed account for email and role: %s", exc
            )
            raise AbortError(messages.INVALID_CREDENTIALS) from exc
        except (AmbiguousAccountError, MissingAccountIdError, SQLAlchemyError) as exc:
            log.with_field("role", req.role).error("Error getting user by email and role: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

        try:
            compare_hash_and_password(auth.password_hash, req.password)
        except PasswordError as exc:
            log.with_field("role", req.role).error("Error comparing password hash: %s", exc)
            raise AbortError(messages.INVALID_CREDENTIALS) from exc

        identity = TokenRequirements(
            email=auth.email,
            user_id=auth.user_id,
            role_account_id=auth.role_account_id,
            role=auth.role,
            organisation_id=str(auth.organisation_id) if auth.organisation_id else "",
        )
        try:
            access_token = generate_token(identity, TokenPurpose.ACCESS)
            refresh_token = generate_token(identity, TokenPurpose.REFRESH)
        except TokenError as exc:
            log.error("Error generating token: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

        return SignInUserResponse(
            message=messages.SIGN_IN_SUCCESS, token=access_token, refresh_token=refresh_token
        )

    def validate_token(
        self,
        req: Annotated[ValidateTokenRequest, Depends(validate_token_request)],
    ) -> ValidateTokenResponse:
        """Return the claims of a valid access token."""
        try:
            claims = validate_jwt(req.token, TokenPurpose.ACCESS)
        except TokenError as exc:
            log.info("Error validating access token: %s", exc)
            raise AbortError(messages.USER_NOT_AUTHORIZED) from exc
        return ValidateTokenResponse(
            email=claims.email,
            role=claims.role,
            user_id=claims.user_id,
            role_account_id=claims.role_account_id,
            organisation_id=claims.organisation_id,
        )

    def refresh_token(
        self,
        req: Annotated[RefreshTokenRequest, Depends(validate_refresh_token_request)],
    ) -> RefreshTokenResponse:
        """Exchange a refresh token for a new access token."""
        try:
            claims = validate_jwt(req.token, TokenPurpose.REFRESH)
        except TokenError as exc:
            log.info("Error validating refresh token: %s", exc)
            raise AbortError(messages.UNAUTHORIZED) from exc

        try:
            token = generate_token(
                TokenRequirements(
                    email=claims.email,
                    user_id=claims.user_id,
                    role_account_id=claims.role_account_id,
                    role=claims.role,
                    organisation_id=claims.organisation_id,
                ),
                TokenPurpose.ACCESS,
            )
        except TokenError as exc:
            log.error("Error generating token: %s", exc)
            raise AbortError(messages.INTERNAL_ERROR) from exc

        return RefreshTokenResponse(token=token)
