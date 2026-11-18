"""Auth service routes."""

from fastapi import FastAPI, status

from health_tech.auth.service import SERVICE_NAME, AuthService
from health_tech.lib.http import new_app


def new_auth_router(svc: AuthService) -> FastAPI:
    """Build the auth service app."""
    app = new_app("health-tech auth service", SERVICE_NAME)
    app.add_api_route(
        "/health-tech/auth/signin",
        svc.sign_in_user,
        methods=["POST"],
        status_code=status.HTTP_200_OK,
    )
    app.add_api_route("/health-tech/auth/validate", svc.validate_token, methods=["GET"])
    app.add_api_route("/health-tech/auth/refresh", svc.refresh_token, methods=["POST"])
    return app
