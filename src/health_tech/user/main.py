"""User service entrypoint."""

import logging

import uvicorn

from health_tech import logger as clog
from health_tech.lib.config import get_settings
from health_tech.lib.db import connect_to_db
from health_tech.lib.env import get_service_host_with_port
from health_tech.lib.mail import new_mailer
from health_tech.user.router import new_user_router
from health_tech.user.service import SERVICE_NAME, UserService


def main() -> None:
    """Start the user service."""
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    svc = UserService(
        db=connect_to_db(),
        logger=clog.must_new(SERVICE_NAME),
        mailer=new_mailer(get_settings()),
    )
    host, port = get_service_host_with_port(SERVICE_NAME)
    uvicorn.run(new_user_router(svc), host=host, port=port)


if __name__ == "__main__":
    main()
