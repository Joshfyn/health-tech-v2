"""Auth service entrypoint."""

import logging

import uvicorn

from health_tech import logger as clog
from health_tech.auth.router import new_auth_router
from health_tech.auth.service import SERVICE_NAME, AuthService
from health_tech.lib.db import connect_to_db
from health_tech.lib.env import get_service_host_with_port


def main() -> None:
    """Start the auth service."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    svc = AuthService(db=connect_to_db(), logger=clog.must_new(SERVICE_NAME))
    host, port = get_service_host_with_port(SERVICE_NAME)
    uvicorn.run(new_auth_router(svc), host=host, port=port)


if __name__ == "__main__":
    main()
