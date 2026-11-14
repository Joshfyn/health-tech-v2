"""Auth service routes."""

from fastapi import FastAPI

from health_tech.auth.service import AuthService
from health_tech.lib.http import new_app


def new_auth_router(svc: AuthService) -> FastAPI:
    """Build the auth service app."""
    app = new_app("health-tech auth service")
    app.add_api_route("/health-tech/auth/signin", svc.sign_in_user, methods=["POST"])
    app.add_api_route("/health-tech/auth/validate", svc.validate_token, methods=["GET"])
    app.add_api_route("/health-tech/auth/refresh", svc.refresh_token, methods=["POST"])
    return app
