"""User service entrypoint."""

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
    clog.configure_logging(SERVICE_NAME)
    svc = UserService(db=connect_to_db(), mailer=new_mailer(get_settings()))
    host, port = get_service_host_with_port(SERVICE_NAME)
    # Logging is configured above; uvicorn's access log would write tokens and addresses.
    uvicorn.run(new_user_router(svc), host=host, port=port, log_config=None, access_log=False)


if __name__ == "__main__":
    main()
