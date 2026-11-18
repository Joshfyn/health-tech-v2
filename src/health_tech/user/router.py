"""User service routes."""

from fastapi import FastAPI

from health_tech.lib.http import new_app
from health_tech.user.service import UserService


def new_user_router(svc: UserService) -> FastAPI:
    """Build the user service app."""
    app = new_app("health-tech user service")
    app.add_api_route("/health-tech/user", svc.create_new_user_account, methods=["POST"])
    app.add_api_route("/health-tech/user", svc.get_users, methods=["GET"])
    app.add_api_route("/health-tech/user/confirm", svc.confirm_user, methods=["GET"])
    app.add_api_route(
        "/health-tech/user/healthcare-providers", svc.create_provider_account, methods=["POST"]
    )
    app.add_api_route(
        "/health-tech/user/healthcare-providers/organisations",
        svc.add_provider_organisation,
        methods=["POST"],
    )
    # Last, so the fixed paths above are never read as a user ID.
    app.add_api_route("/health-tech/user/{user_id}", svc.get_user, methods=["GET"])
    return app
