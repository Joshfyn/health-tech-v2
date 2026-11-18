"""Auth service entrypoint."""

import uvicorn

from health_tech import logger as clog
from health_tech.auth.router import new_auth_router
from health_tech.auth.service import SERVICE_NAME, AuthService
from health_tech.lib.db import connect_to_db
from health_tech.lib.env import get_service_host_with_port


def main() -> None:
    """Start the auth service."""
    clog.configure_logging(SERVICE_NAME)
    svc = AuthService(db=connect_to_db())
    host, port = get_service_host_with_port(SERVICE_NAME)
    # Logging is configured above; uvicorn's access log would write tokens and addresses.
    uvicorn.run(new_auth_router(svc), host=host, port=port, log_config=None, access_log=False)


if __name__ == "__main__":
    main()
