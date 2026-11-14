"""clog: structured service logger with optional Sentry reporting."""

import logging
import sys
from datetime import UTC, datetime
from typing import Any, Self

from starlette.requests import Request

SERVER_NAME_KEY = "server_name"
RESOURCE_KEY = "resource"


class _TextFormatter(logging.Formatter):
    """Renders records as key=value text."""

    def format(self, record: logging.LogRecord) -> str:
        parts = [
            f"time={datetime.fromtimestamp(record.created, UTC).isoformat()}",
            f"level={record.levelname.lower()}",
            f"msg={record.getMessage()}",
        ]
        fields: dict[str, Any] = getattr(record, "fields", {})
        parts.extend(f"{key}={value}" for key, value in fields.items())
        return " ".join(parts)


class Clog:
    """Logger that carries structured fields on every line."""

    def __init__(self, logger: logging.Logger, fields: dict[str, Any] | None = None) -> None:
        self._logger = logger
        self._fields = dict(fields or {})

    def with_field(self, key: str, value: Any) -> Self:
        """Add a field to this logger and return it."""
        self._fields[key] = value
        return self

    def with_fields(self, fields: dict[str, Any]) -> Self:
        """Add several fields to this logger and return it."""
        self._fields.update(fields)
        return self

    def errorf(self, req: Request | None, fmt: str, *args: Any) -> None:
        """Log an error with the request as the resource field."""
        fields = {**self._fields, RESOURCE_KEY: _describe_request(req)}
        self._logger.error(fmt, *args, extra={"fields": fields})


def _describe_request(req: Request | None) -> str:
    if req is None:
        return "<nil>"
    return f"{req.method} {req.url.path}"


def must_new(service_name: str, dsn: str = "") -> Clog:
    """Create a service logger; raise if Sentry cannot be set up."""
    logger = logging.getLogger(f"health_tech.{service_name or 'app'}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(_TextFormatter())
        logger.addHandler(handler)

    if dsn:
        import sentry_sdk  # optional: pip install "health-tech[sentry]"

        sentry_sdk.init(dsn=dsn)

    fields = {SERVER_NAME_KEY: service_name} if service_name else {}
    return Clog(logger, fields)
