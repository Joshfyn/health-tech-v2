"""ASGI middleware, outermost of each app: gives every request an ID and logs it once.

For the whole request it sets, for the logger (see logger.py):
- request_id: the caller's X-Request-ID if it is a UUID, so one ID can follow a request
  across services, else a new one. Only a UUID is taken: anything else could carry personal
  data into every log line. It is sent back in the X-Request-ID response header;
- server_name: the service;
- resource: the method and route template (GET /health-tech/user/{user_id}), never the
  URL itself, which may hold a user ID or, in its query string, a token.

It ends each request with one line, "Request completed: status=... duration_ms=...", in
place of uvicorn's access log, and answers unexpected exceptions itself. Starlette's own
handler for them runs outside every middleware, where the request ID is no longer known.
"""

import time
import uuid
from typing import Final

from starlette.datastructures import Headers, MutableHeaders
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Match
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from health_tech.lib import errors
from health_tech.logger import log, request_id_var, resource_var, sanitize, server_name_var

REQUEST_ID_HEADER: Final = "X-Request-ID"
UNMATCHED_PATH: Final = "<unmatched path>"
MAX_METHOD_LENGTH: Final = 16


def request_id_from(header: str | None) -> str:
    """Return the caller's request ID if it is a UUID, else a new one."""
    if header:
        try:
            return str(uuid.UUID(header))
        except ValueError:
            pass
    return str(uuid.uuid4())


def route_resource(scope: Scope, routes: list[BaseRoute]) -> str:
    """Return the method and route template the request is for, without any values."""
    method = sanitize(scope.get("method", ""))[:MAX_METHOD_LENGTH]
    for route in routes:
        match, _ = route.matches(scope)
        if match is not Match.NONE:
            return f"{method} {getattr(route, 'path', UNMATCHED_PATH)}"
    return f"{method} {UNMATCHED_PATH}"


class RequestContextMiddleware:
    """Set the request ID and resource for the logger, and log each request once."""

    def __init__(self, app: ASGIApp, service_name: str, routes: list[BaseRoute]) -> None:
        self.app = app
        self.service_name = service_name
        # The app's route list, filled in after the app is built; read on each request.
        self.routes = routes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = request_id_from(Headers(scope=scope).get(REQUEST_ID_HEADER))
        # Not reset afterwards: each request runs in its own task, whose context ends with it.
        request_id_var.set(request_id)
        server_name_var.set(self.service_name)
        resource_var.set(route_resource(scope, self.routes))

        started = time.perf_counter()
        status = 0

        async def send_with_request_id(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
                MutableHeaders(scope=message)[REQUEST_ID_HEADER] = request_id
            await send(message)

        try:
            await self.app(scope, receive, send_with_request_id)
        except Exception as exc:
            log.error("Unhandled %s", exc, exc_info=exc)  # type and redacted message
            if status:  # the response has begun; nothing can be sent now
                raise
            error = errors.INTERNAL_ERROR
            response = JSONResponse(status_code=error.status, content=error.body())
            await response(scope, receive, send_with_request_id)
        finally:
            duration_ms = round((time.perf_counter() - started) * 1000)
            log.info("Request completed: status=%d duration_ms=%d", status, duration_ms)
