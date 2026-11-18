"""Which caller roles may use each endpoint, enforced before anything else reads the request.

Each app that needs it declares one table, (method, route path) -> Access, and
AccessControlMiddleware enforces it ahead of the payload guard, body parsing and every
handler: a caller with no valid access token, or whose role the endpoint does not allow,
gets 401 at once and the request body is never read.

- no token, or not a valid access token: 401 unauthorized;
- a valid token whose role the endpoint does not allow: 401 role_not_allowed.

Finer rules that depend on the request itself (a patient reads only their own record, a
hospital admin manages only doctors) stay with the endpoint and answer 403 forbidden.

Every route must be in the table: the app refuses to start otherwise, so a new endpoint
cannot be left open by accident.
"""

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Final

from fastapi import Request
from fastapi.routing import APIRoute
from starlette.datastructures import Headers
from starlette.responses import JSONResponse
from starlette.routing import BaseRoute, Match
from starlette.types import ASGIApp, Receive, Scope, Send

from health_tech.lib import errors
from health_tech.lib.errors import AbortError, ApiError
from health_tech.lib.tokenmaker import TokenClaims, TokenError, TokenPurpose, validate_token
from health_tech.logger import log

AUTH_HEADER: Final = "X-USER-TOKEN"
# Where the middleware leaves the caller's claims for the endpoint (request.state).
CLAIMS_STATE_KEY: Final = "caller_claims"


@dataclass(frozen=True, slots=True)
class Access:
    """Who may call an endpoint: anyone (roles is None), or holders of these roles."""

    roles: frozenset[str] | None

    @property
    def is_public(self) -> bool:
        """Report whether the endpoint needs no access token."""
        return self.roles is None


# The endpoint checks whatever credential it takes itself (a sign-in body, a refresh token,
# a confirmation link).
PUBLIC: Final = Access(roles=None)


def roles(*allowed: str) -> Access:
    """Return the access of an endpoint that only these roles may call."""
    if not allowed:
        raise ValueError("an endpoint needs at least one role; use PUBLIC for none")
    return Access(roles=frozenset(allowed))


type AccessPolicy = Mapping[tuple[str, str], Access]


class AccessPolicyError(RuntimeError):
    """The access table does not match the app's routes."""


def check_policy(routes: Iterable[BaseRoute], policy: AccessPolicy) -> None:
    """Raise AccessPolicyError unless every API route has exactly the entries it needs."""
    needed = {
        (method, route.path)
        for route in routes
        if isinstance(route, APIRoute)
        for method in route.methods
    }
    if missing := needed - policy.keys():
        raise AccessPolicyError(f"routes without an access rule: {sorted(missing)}")
    if unknown := policy.keys() - needed:
        raise AccessPolicyError(f"access rules for no route: {sorted(unknown)}")


def caller_claims(request: Request) -> TokenClaims:
    """Return the claims AccessControlMiddleware verified for this request.

    Fails closed: an endpoint that asks for them without the middleware having run (a
    route wrongly marked PUBLIC, say) answers 401 rather than running unauthenticated.
    """
    claims = getattr(request.state, CLAIMS_STATE_KEY, None)
    if not isinstance(claims, TokenClaims):
        log.error("Endpoint needs a caller but none was verified; check its access rule")
        raise AbortError(errors.UNAUTHORIZED)
    return claims


class AccessControlMiddleware:
    """Refuse callers the endpoint's access rule does not allow, before the body is read."""

    def __init__(self, app: ASGIApp, routes: list[BaseRoute], policy: AccessPolicy) -> None:
        # Starlette builds middleware when the app starts, after every route is added.
        check_policy(routes, policy)
        self.app = app
        self.routes = routes
        self.policy = policy

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        access = self._access_for(scope)
        if access is None or access.is_public:  # no such endpoint (404, 405), or public
            await self.app(scope, receive, send)
            return

        token = Headers(scope=scope).get(AUTH_HEADER, "")
        if not token:
            await _refuse(scope, receive, send, errors.UNAUTHORIZED, "no access token")
            return
        try:
            claims = validate_token(token, TokenPurpose.ACCESS)
        except TokenError as exc:
            await _refuse(scope, receive, send, errors.UNAUTHORIZED, str(exc))
            return
        if claims.role not in (access.roles or ()):
            reason = f"role {claims.role} may not use this endpoint"
            await _refuse(scope, receive, send, errors.ROLE_NOT_ALLOWED, reason)
            return

        scope.setdefault("state", {})[CLAIMS_STATE_KEY] = claims
        await self.app(scope, receive, send)

    def _access_for(self, scope: Scope) -> Access | None:
        """Return the access rule of the route the router will pick, or None if none.

        As the router does, a route matching path and method wins over an earlier one that
        matches only the path: GET /health-tech/user must not stop at POST /health-tech/user.
        """
        for route in self.routes:
            match, _ = route.matches(scope)
            if match is Match.FULL:
                if not isinstance(route, APIRoute):
                    return PUBLIC  # FastAPI's own pages: /docs, /openapi.json
                return self.policy[(scope["method"], route.path)]
        return None  # no such path (404), or not with this method (405): the router answers


async def _refuse(scope: Scope, receive: Receive, send: Send, error: ApiError, reason: str) -> None:
    # The reason is ours (the token library's message, or the role): never the token itself.
    log.info("Request refused: status=%d code=%s reason=%s", error.status, error.code, reason)
    response = JSONResponse(status_code=error.status, content=error.body())
    await response(scope, receive, send)
