"""Environment helpers shared by the services."""

from health_tech.lib.config import get_settings

BIND_HOST = "0.0.0.0"
PRODUCTION_PORT = 80


def is_production() -> bool:
    """Report whether the service runs in production."""
    return get_settings().is_production


def get_service_host_with_port(svc_name: str) -> tuple[str, int]:
    """Return the bind host and port for a service, from <SVC>_SERVICE_PORT outside production."""
    if not is_production():
        return BIND_HOST, getattr(get_settings(), f"{svc_name}_service_port")
    return BIND_HOST, PRODUCTION_PORT
