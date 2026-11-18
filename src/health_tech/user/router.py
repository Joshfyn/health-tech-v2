"""User service routes and the caller roles each one allows."""

from typing import Final

from fastapi import FastAPI

from health_tech.lib.access import PUBLIC, AccessPolicy, roles
from health_tech.lib.http import new_app
from health_tech.user.model import UserRole
from health_tech.user.service import SERVICE_NAME, UserService

USERS: Final = "/health-tech/user"
CONFIRM: Final = f"{USERS}/confirm"
PROVIDERS: Final = f"{USERS}/healthcare-providers"
PROVIDER_ORGANISATIONS: Final = f"{PROVIDERS}/organisations"
USER_RECORD: Final = f"{USERS}/{{user_id}}"

SUPER_ADMIN_ONLY: Final = roles(UserRole.SUPER_ADMIN)
ADMINS: Final = roles(UserRole.SUPER_ADMIN, UserRole.HOSPITAL_ADMIN, UserRole.PHARMACY_ADMIN)

# Who may call each endpoint. Any other caller gets 401 before the request body is read:
# doctors, pharmacists and hospital and pharmacy admins may not create, list or read users.
ACCESS: Final[AccessPolicy] = {
    ("POST", USERS): SUPER_ADMIN_ONLY,
    ("GET", USERS): SUPER_ADMIN_ONLY,
    # The link in the confirmation email: its token is the credential.
    ("GET", CONFIRM): PUBLIC,
    ("POST", PROVIDERS): ADMINS,
    ("POST", PROVIDER_ORGANISATIONS): ADMINS,
    # Patients, their own record only (checked by the endpoint, 403 otherwise).
    ("GET", USER_RECORD): roles(UserRole.SUPER_ADMIN, UserRole.PATIENT),
}


def new_user_router(svc: UserService) -> FastAPI:
    """Build the user service app."""
    app = new_app("health-tech user service", SERVICE_NAME, access=ACCESS)
    app.add_api_route(USERS, svc.create_new_user_account, methods=["POST"])
    app.add_api_route(USERS, svc.get_users, methods=["GET"])
    app.add_api_route(CONFIRM, svc.confirm_user, methods=["GET"])
    app.add_api_route(PROVIDERS, svc.create_provider_account, methods=["POST"])
    app.add_api_route(PROVIDER_ORGANISATIONS, svc.add_provider_organisation, methods=["POST"])
    # Last, so the fixed paths above are never read as a user ID.
    app.add_api_route(USER_RECORD, svc.get_user, methods=["GET"])
    return app
