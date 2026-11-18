"""HTTP helpers shared by the routers: the app factory, error responses and body binding.

Every error response, whatever raised it, has the body {"code": ..., "error": ...} built from
the catalog in lib/errors.py and is logged once, here, with its status and code. Unexpected
exceptions are answered by lib/request_context.py, which knows the request ID.
"""

from typing import Any, Final

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException

from health_tech.lib import errors
from health_tech.lib.access import AccessControlMiddleware, AccessPolicy
from health_tech.lib.errors import AbortError, ApiError, ErrorResponse
from health_tech.lib.payload_guard import PayloadGuardMiddleware
from health_tech.lib.request_context import RequestContextMiddleware
from health_tech.logger import log

__all__ = ["AbortError", "bind_json", "error_response", "new_app"]

# Documented on every route; FastAPI's own 422 never reaches a client.
ERROR_RESPONSES: Final[dict[int | str, dict[str, Any]]] = {
    status: {"model": ErrorResponse} for status in (400, 401, 403, 404, 409, 413, 500)
}

# Errors Starlette raises itself (unknown path, wrong method, ...), by status.
_HTTP_ERRORS: Final = {
    404: errors.NOT_FOUND,
    405: errors.METHOD_NOT_ALLOWED,
    413: errors.PAYLOAD_TOO_LARGE,
}


async def bind_json[T: BaseModel](request: Request, model: type[T]) -> T:
    """Parse and validate the JSON request body into model.

    Raise AbortError with the field rule the body broke first, or invalid_request_body for a
    body that is not JSON or has a value of the wrong type.
    """
    try:
        payload = await request.json()
    except ValueError as exc:
        raise AbortError(errors.INVALID_REQUEST_BODY) from exc
    try:
        return model.model_validate(payload)
    except ValidationError as exc:
        raise AbortError(_first_rule_broken(exc)) from exc


def _first_rule_broken(exc: ValidationError) -> ApiError:
    first = exc.errors()[0]
    rule = errors.FIELD_RULES.get(first["type"])
    if rule is None:  # the library's own checks: wrong type, not a UUID, not a date
        return errors.INVALID_REQUEST_BODY
    # loc holds the aliases of our own model's fields, never a client-chosen key.
    return rule.for_field(".".join(str(part) for part in first["loc"]))


def error_response(error: ApiError, headers: dict[str, str] | None = None) -> JSONResponse:
    """Return the JSON response for error."""
    return JSONResponse(status_code=error.status, content=error.body(), headers=headers)


def new_app(title: str, service_name: str, access: AccessPolicy | None = None) -> FastAPI:
    """Create a FastAPI app whose every error response has the standard shape.

    Middleware, outermost first: request context (request ID, one log line per request,
    unexpected exceptions); access control, if access is given (callers the endpoint does
    not allow get 401 before their body is read); then the payload guard.
    """
    app = FastAPI(title=title, responses=ERROR_RESPONSES)
    app.add_middleware(PayloadGuardMiddleware)
    if access is not None:
        app.add_middleware(AccessControlMiddleware, routes=app.router.routes, policy=access)
    app.add_middleware(
        RequestContextMiddleware, service_name=service_name, routes=app.router.routes
    )

    def respond(error: ApiError, headers: dict[str, str] | None = None) -> JSONResponse:
        log.info("Request failed: status=%d code=%s", error.status, error.code)
        return error_response(error, headers)

    @app.exception_handler(AbortError)
    async def abort_handler(_: Request, exc: AbortError) -> JSONResponse:
        return respond(exc.error)

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(_: Request, __: RequestValidationError) -> JSONResponse:
        # FastAPI's own answer (422) would echo the library's messages and the input.
        return respond(errors.INVALID_REQUEST)

    @app.exception_handler(StarletteHTTPException)
    async def http_error_handler(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        error = _HTTP_ERRORS.get(exc.status_code)
        if error is None:
            error = errors.INTERNAL_ERROR if exc.status_code >= 500 else errors.INVALID_REQUEST
        return respond(error, getattr(exc, "headers", None))

    return app
