"""Auth service handlers."""

from dataclasses import dataclass
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from health_tech.auth.dto import (
    RefreshTokenResponse,
    SignInUserRequest,
    SignInUserResponse,
    ValidateTokenRequest,
    ValidateTokenResponse,
)
from health_tech.auth.middleware import validate_sign_in_user_request, validate_token_request
from health_tech.auth.model import Auth, UserNotFoundError
from health_tech.lib.http import AbortError
from health_tech.lib.password import PasswordError, compare_hash_and_password
from health_tech.lib.tokenmaker import (
    TokenError,
    TokenRequirements,
    generate_token,
    validate_verification_token,
)
from health_tech.logger import Clog

SERVICE_NAME = "auth"


@dataclass(slots=True)
class AuthService:
    """Auth service dependencies and HTTP handlers."""

    db: sessionmaker[Session]
    logger: Clog

    def sign_in_user(
        self,
        request: Request,
        req: Annotated[SignInUserRequest, Depends(validate_sign_in_user_request)],
    ) -> SignInUserResponse:
        """Check email and password and return a session token."""
        auth = Auth(email=req.email)
        try:
            with self.db() as session:
                auth.get_user_by_email(session)
        except (UserNotFoundError, SQLAlchemyError) as exc:
            self.logger.with_field("email", req.email).errorf(
                request, "Error getting user by email: %s", exc
            )
            raise AbortError(500, {"error": "internal server error"}) from exc

        try:
            compare_hash_and_password(auth.password_hash, req.password)
        except PasswordError as exc:
            self.logger.with_field("email", req.email).errorf(
                request, "Error comparing password hash: %s", exc
            )
            raise AbortError(401, {"error": "invalid credentials"}) from exc

        try:
            token = generate_token(
                TokenRequirements(email=req.email, user_id=auth.role_account_id, role=auth.role)
            )
        except TokenError as exc:
            self.logger.with_field("email", req.email).with_field(
                "user_id", auth.role_account_id
            ).errorf(request, "Error generating token: %s", exc)
            raise AbortError(500, {"error": "internal server error"}) from exc

        return SignInUserResponse(token=token)

    def validate_token(
        self,
        request: Request,
        req: Annotated[ValidateTokenRequest, Depends(validate_token_request)],
    ) -> ValidateTokenResponse:
        """Return the claims of a valid token."""
        try:
            claims = validate_verification_token(req.token)
        except TokenError as exc:
            self.logger.with_field("token", req.token).errorf(
                request, "Error validating token: %s", exc
            )
            raise AbortError(401, {"error": "user not authorized"}) from exc
        return ValidateTokenResponse(email=claims.email, role=claims.role, user_id=claims.user_id)

    def refresh_token(
        self,
        request: Request,
        req: Annotated[ValidateTokenRequest, Depends(validate_token_request)],
    ) -> RefreshTokenResponse:
        """Exchange a valid token for a new one."""
        try:
            claims = validate_verification_token(req.token)
        except TokenError as exc:
            self.logger.with_field("token", req.token).errorf(
                request, "Error validating token: %s", exc
            )
            raise AbortError(401, {"error": "Unauthorized"}) from exc

        try:
            token = generate_token(
                TokenRequirements(email=claims.email, user_id=claims.user_id, role=claims.role)
            )
        except TokenError as exc:
            self.logger.with_field("email", claims.email).with_field(
                "user_id", claims.user_id
            ).errorf(request, "Error generating token: %s", exc)
            raise AbortError(500, {"error": "internal server error"}) from exc

        return RefreshTokenResponse(token=token)
