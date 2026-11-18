"""ASGI middleware that refuses unsafe request bodies before any route, auth check or model.

Every key and every string value in a JSON body, at any depth and including fields no route
knows (request models drop those later), must pass the safe text rule. The first that fails
ends the request with 400 unsafe_input. Bodies that are too large, not UTF-8 JSON or too
deeply nested are refused the same way, each with its own code.

Only the body is checked here. Query and path parameters and headers are each parsed by a
strict parser in their route (positive integers, UUIDs, signed JWTs), and a JWT may contain
"--", which the SQL rule would refuse.
"""

import json
import math
import re
from collections.abc import Iterator
from typing import Any, Final

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from health_tech.lib import errors
from health_tech.lib.errors import ApiError
from health_tech.lib.safe_text import unsafe_reason
from health_tech.lib.validation import RequestModel
from health_tech.logger import log

MAX_BODY_BYTES: Final = 64 * 1024
MAX_DEPTH: Final = 8
# Keys are field names: an identifier, never free text.
KEY_PATTERN: Final = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")
# Passwords are hashed and never shown, stored or put in a query. Restricting their characters
# would only make them weaker, so they are checked for length by the request models instead.
EXEMPT_KEYS: Final = frozenset({"password"})
# Logged locations are cut to this length.
MAX_LOGGED_LOCATION: Final = 80
# Stands in, in a logged location, for a key no request model declares: a client may send
# anything as a key, a person's name included.
UNNAMED_KEY: Final = "?"


class UnsafePayloadError(Exception):
    """The body holds a key or value that is not safe text."""

    def __init__(self, location: str, reason: str) -> None:
        super().__init__(location, reason)
        self.location = location
        self.reason = reason


class MalformedPayloadError(Exception):
    """The body is JSON, but nested too deeply or holding a number that is not finite."""


class _PayloadTooLargeError(Exception):
    pass


def _reject_constant(_: str) -> None:
    raise ValueError("NaN and Infinity are not JSON")


class _JsonObject(list[tuple[str, Any]]):
    """A JSON object as its (key, value) pairs, so a key sent twice is checked both times."""


def parse_json(body: bytes) -> Any:
    """Parse a UTF-8 JSON body; raise ValueError if it is anything else."""
    return json.loads(
        body.decode("utf-8"),
        object_pairs_hook=_JsonObject,
        parse_constant=_reject_constant,
    )


def declared_field_names() -> frozenset[str]:
    """Return the name and alias of every field of every request model."""
    names: set[str] = set()
    pending = list(RequestModel.__subclasses__())
    while pending:
        model = pending.pop()
        pending.extend(model.__subclasses__())
        for name, field in model.model_fields.items():
            names.add(name)
            if field.alias:
                names.add(field.alias)
    return frozenset(names)


def _walk(node: Any, location: str, depth: int) -> Iterator[tuple[str, str, bool]]:
    """Yield (location, text, is_key) for every key and string under node."""
    if depth > MAX_DEPTH:
        raise MalformedPayloadError(f"nested too deeply at {location}")
    if isinstance(node, _JsonObject):
        for key, value in node:
            child = f"{location}.{key}"
            yield child, key, True
            if key in EXEMPT_KEYS and isinstance(value, str):
                continue
            yield from _walk(value, child, depth + 1)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            yield from _walk(value, f"{location}[{index}]", depth + 1)
    elif isinstance(node, str):
        yield location, node, False
    elif isinstance(node, float) and not math.isfinite(node):  # 1e999 parses as inf
        raise MalformedPayloadError(f"number is not finite at {location}")


def check_payload(payload: Any) -> None:
    """Raise UnsafePayloadError at the first key or string that is not safe text, or
    MalformedPayloadError if the payload is nested too deeply or holds a non-finite number."""
    for location, text, is_key in _walk(payload, "$", 0):
        if is_key:
            if not KEY_PATTERN.fullmatch(text):
                raise UnsafePayloadError(location, "key is not a field name")
        elif (reason := unsafe_reason(text)) is not None:
            raise UnsafePayloadError(location, reason)


class PayloadGuardMiddleware:
    """Refuse unsafe request bodies before the app sees them; replay safe ones unchanged."""

    def __init__(self, app: ASGIApp, max_body_bytes: int = MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        try:
            body, messages = await self._read_body(receive)
        except _PayloadTooLargeError:
            await self._refuse(scope, send, errors.PAYLOAD_TOO_LARGE, "body is too large")
            return

        if body:
            try:
                payload = parse_json(body)
            except ValueError, RecursionError:
                await self._refuse(scope, send, errors.INVALID_REQUEST_BODY, "body is not JSON")
                return
            try:
                check_payload(payload)
            except MalformedPayloadError as exc:
                reason = str(exc)[:MAX_LOGGED_LOCATION]
                await self._refuse(scope, send, errors.INVALID_REQUEST_BODY, reason)
                return
            except UnsafePayloadError as exc:
                location = _loggable(exc.location)[:MAX_LOGGED_LOCATION]
                await self._refuse(
                    scope,
                    send,
                    errors.UNSAFE_INPUT.for_field("request"),
                    f"{exc.reason} at {location}",
                )
                return

        await self.app(scope, _replay(messages, receive), send)

    async def _read_body(self, receive: Receive) -> tuple[bytes, list[Message]]:
        messages: list[Message] = []
        size = 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] != "http.request":
                break  # the client went away; let the app see it
            size += len(message.get("body", b""))
            if size > self.max_body_bytes:
                raise _PayloadTooLargeError
            if not message.get("more_body", False):
                break
        body = b"".join(m.get("body", b"") for m in messages if m["type"] == "http.request")
        return body, messages

    async def _refuse(self, scope: Scope, send: Send, error: ApiError, reason: str) -> None:
        log.info("Request refused: status=%d code=%s reason=%s", error.status, error.code, reason)
        response = JSONResponse(status_code=error.status, content=error.body())
        await response(scope, _no_more_body, send)


def _loggable(location: str) -> str:
    """Return location with every key no request model declares replaced by UNNAMED_KEY.

    Values never go into a location; keys do, and a client may send any text as a key.
    """
    declared = declared_field_names()
    parts = re.split(r"(\.[^.\[]*|\[\d+\])", location)
    return "".join(
        f".{UNNAMED_KEY}" if part.startswith(".") and part[1:] not in declared else part
        for part in parts
    )


def _replay(messages: list[Message], receive: Receive) -> Receive:
    """Return a receive that gives back the buffered messages, then reads on."""
    pending = list(messages)

    async def replay() -> Message:
        if pending:
            return pending.pop(0)
        return await receive()

    return replay


async def _no_more_body() -> Message:
    return {"type": "http.disconnect"}
