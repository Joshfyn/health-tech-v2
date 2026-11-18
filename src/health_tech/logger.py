"""clog: the one logger of every service.

Every module logs through `log`; libraries (uvicorn, SQLAlchemy, ...) log through the same
handler and format once configure_logging has run. Every line carries the request ID:

    time=... level=info request_id=3f2c... msg=Request completed: status=200 duration_ms=4
        server_name=user resource=GET /health-tech/user/{user_id}

request_id, server_name and resource come from the request being served (set by
lib/request_context.py); outside a request, request_id and resource are "-".

No personal data or tokens:
- never pass emails, names, user IDs, passwords, tokens or request values to the logger;
- sensitive fields are redacted by name, never by what a value looks like: the record's
  structured fields (log.with_field("email", ...) logs email=[REDACTED]), and fields written
  in messages and exception messages (password=..., "token": ..., a database's
  "Key (email, role)=(..., patient)", a connection URL's password). See SENSITIVE_FIELDS;
  numbers, dates, IDs and free text are left as they are, so personal data goes into a log
  line only as a named field;
- tracebacks show where an error happened (files, lines, code) and each exception's
  redacted message;
- resources are route templates (/health-tech/user/{user_id}), never the ID in the URL, and
  never the query string (which may hold a confirmation token).
"""

import logging
import re
import sys
import traceback
from collections.abc import Mapping
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import Any, Final

LOGGER_NAME: Final = "health_tech"
REQUEST_ID_KEY: Final = "request_id"
SERVER_NAME_KEY: Final = "server_name"
RESOURCE_KEY: Final = "resource"
NO_REQUEST: Final = "-"
TRACEBACK_PREFIX: Final = "  | "
# Longer exception messages are cut, so one error cannot flood the log.
MAX_EXCEPTION_MESSAGE: Final = 2000

request_id_var: ContextVar[str] = ContextVar("request_id", default=NO_REQUEST)
resource_var: ContextVar[str] = ContextVar("resource", default=NO_REQUEST)
server_name_var: ContextVar[str] = ContextVar("server_name", default="")

# The service this process runs, for lines outside any request (startup, shutdown).
_process_server_name = ""

# Every control character, including newlines, so logged text cannot start a forged line.
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f-\x9f\u2028\u2029]")


def sanitize(value: object) -> str:
    """Return value as one line of text, control characters escaped."""
    return _CONTROL_CHARACTERS.sub(
        lambda m: m.group().encode("unicode_escape").decode(), str(value)
    )


REDACTED: Final = "[REDACTED]"

# Fields whose values are personal data or secrets. Names are compared normalised: lower case,
# letters and digits only, so firstName, first_name and First-Name are one field.
SENSITIVE_FIELDS: Final = frozenset(
    {
        # people
        "email", "emailaddress", "recipient", "recipients", "sender",
        "name", "firstname", "lastname", "fullname", "username",
        "phone", "phonenumber", "mobile", "telephone", "tel",
        "nationalid", "ssn", "nin", "passport",
        "dateofbirth", "dob", "birthdate",
        "contact", "address", "street", "city", "zipcode", "postcode", "postalcode",
        "userid", "roleaccountid", "personid", "patientid",
        "ip", "clientip", "remoteaddr",
        # secrets
        "password", "passwd", "pwd", "passwordhash", "hashedpassword",
        "secret", "clientsecret", "jwtsecret", "smtppass",
        "token", "accesstoken", "refreshtoken", "idtoken", "xusertoken", "xrefreshtoken",
        "authorization", "proxyauthorization", "cookie", "setcookie", "apikey", "credentials",
    }
)  # fmt: skip
# Also sensitive: any field whose name ends with one of these (patient_email, csrf_token).
SENSITIVE_SUFFIXES: Final = (
    "email", "phone", "password", "passwd", "token", "secret", "apikey",
    "nationalid", "dateofbirth", "address",
)  # fmt: skip


def _normalise(field: str) -> str:
    return re.sub(r"[^a-z0-9]", "", field.lower())


def is_sensitive_field(field: str) -> bool:
    """Report whether field's values are personal data or secrets, by its name alone."""
    name = _normalise(field)
    return name in SENSITIVE_FIELDS or name.endswith(SENSITIVE_SUFFIXES)


def redact_fields(value: Any, field: str = "") -> Any:
    """Return value with the value of every sensitive field, at any depth, redacted.

    A mapping's keys name its fields; a list or tuple inherits the field it is the value of.
    """
    if field and is_sensitive_field(field):
        return REDACTED
    if isinstance(value, Mapping):
        return {key: redact_fields(item, str(key)) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return type(value)(redact_fields(item, field) for item in value)
    return value


# Fields written inside text. The value that follows is found by _value_end.
_TEXT_FIELD = re.compile(
    r"""(?P<quote>["'])(?P<quoted>[A-Za-z_][\w.-]*)(?P=quote)\s*:\s*  # "field": / 'field':
      | \b(?P<bare>[A-Za-z_][\w.-]*)\s*=\s*                            # field=
    """,
    re.VERBOSE,
)
# Header syntax, "Name: value" to the end of the line, for these fields only: an unquoted
# "field:" is otherwise prose ("error sending confirmation email: timeout").
_HEADER_FIELD = re.compile(
    r"\b(?P<name>authorization|proxy-authorization|cookie|set-cookie|x-user-token"
    r"|x-refresh-token)(?P<sep>\s*:\s*)[^\r\n]*",
    re.IGNORECASE,
)
# PostgreSQL names the columns of a key: Key (email, role)=(sam@example.com, patient)
_KEY_DETAIL = re.compile(
    r"Key \((?P<columns>[^)]*)\)=\((?P<values>.*?)\)(?= already exists| is not present|\s*$|\.)"
)
# Values whose fields are not named: PostgreSQL's whole row, SQLAlchemy's bound parameters.
_UNNAMED_VALUES = (
    (re.compile(r"(Failing row contains )\(.*?\)(?=\.?\s*$|\.?\n)"), rf"\1({REDACTED})"),
    (re.compile(r"\[parameters: .*?\](?=\s*(?:\(Background|$))"), f"[parameters: {REDACTED}]"),
)
# The password field of a URL: scheme://user:password@host
_URL_PASSWORD = re.compile(r"(?<=://)(?P<user>[^\s/@:]+):[^\s/@]+@")
_BARE_VALUE = re.compile(r"[^\s,;&)\]}]*")
_CLOSING = {"{": "}", "[": "]", "(": ")"}


def _value_end(text: str, start: int) -> int:
    """Return where the value starting at start ends: a quoted string, a bracketed group, or
    text up to the next space or separator."""
    if start >= len(text):
        return start
    opening = text[start]
    if opening in "\"'":
        index = start + 1
        while index < len(text) and text[index] != opening:
            index += 2 if text[index] == "\\" else 1
        return min(index + 1, len(text))
    if opening in _CLOSING:
        depth, index = 0, start
        while index < len(text):
            if text[index] == opening:
                depth += 1
            elif text[index] == _CLOSING[opening]:
                depth -= 1
                if depth == 0:
                    return index + 1
            index += 1
        return len(text)
    match = _BARE_VALUE.match(text, start)
    return match.end() if match else start


def _redact_text_fields(text: str) -> str:
    parts: list[str] = []
    position = 0
    for match in _TEXT_FIELD.finditer(text):
        if match.start() < position:  # inside a value already redacted
            continue
        if not is_sensitive_field(match.group("quoted") or match.group("bare")):
            continue
        end = _value_end(text, match.end())
        if end == match.end():
            continue
        quote = text[match.end()] if text[match.end()] in "\"'" else ""
        parts += [text[position : match.end()], f"{quote}{REDACTED}{quote}"]
        position = end
    return "".join(parts) + text[position:]


def _redact_key_detail(match: re.Match[str]) -> str:
    columns = [c.strip() for c in match.group("columns").split(",")]
    values = [v.strip() for v in match.group("values").split(",")]
    if len(values) != len(columns):  # a value holds a comma: cannot pair them, hide all
        return f"Key ({match.group('columns')})=({REDACTED})"
    shown = [REDACTED if is_sensitive_field(c) else v for c, v in zip(columns, values, strict=True)]
    return f"Key ({match.group('columns')})=({', '.join(shown)})"


def redact(text: str) -> str:
    """Return text with the values of sensitive fields written in it redacted.

    Only values whose field is named are redacted: field=value, "field": value, 'field': value,
    Authorization: value, PostgreSQL's Key (field, ...)=(value, ...), a URL's password; and
    the values PostgreSQL and SQLAlchemy list without names. Nothing is redacted for how it
    looks: numbers, dates, IDs and free text stay as they are, so never write personal data
    into a message except as a named field.
    """
    text = _URL_PASSWORD.sub(rf"\g<user>:{REDACTED}@", text)
    text = _HEADER_FIELD.sub(rf"\g<name>\g<sep>{REDACTED}", text)
    text = _KEY_DETAIL.sub(_redact_key_detail, text)
    for pattern, replacement in _UNNAMED_VALUES:
        text = pattern.sub(replacement, text)
    return _redact_text_fields(text)


def describe(exc: BaseException) -> str:
    """Return exc's type and redacted message, as logged."""
    name = type(exc).__name__
    message = redact(str(exc))
    if len(message) > MAX_EXCEPTION_MESSAGE:
        message = message[:MAX_EXCEPTION_MESSAGE] + "...(cut)"
    return f"{name}: {message}" if message else name


def _exception_chain(exc: BaseException) -> list[BaseException]:
    """Return exc and the exceptions that led to it, oldest first, as Python prints them."""
    chain: list[BaseException] = []
    current: BaseException | None = exc
    while current is not None and not any(current is seen for seen in chain):
        chain.append(current)
        if current.__cause__ is not None:  # raise ... from cause
            current = current.__cause__
        elif not current.__suppress_context__:  # raised while handling another
            current = current.__context__
        else:  # raise ... from None
            current = None
    return chain[::-1]


def format_traceback(exc: BaseException) -> str:
    """Return exc's traceback, oldest cause first, each exception's message redacted."""
    lines: list[str] = []
    for index, link in enumerate(_exception_chain(exc)):
        if index:
            lines.append("which led to:")
        lines.append("Traceback (most recent call last):")
        for frame in traceback.format_list(traceback.extract_tb(link.__traceback__)):
            lines.extend(frame.rstrip("\n").split("\n"))
        lines.append(describe(link))
    return "".join(f"\n{TRACEBACK_PREFIX}{sanitize(line)}" for line in lines)


class _TextFormatter(logging.Formatter):
    """Renders any record as one key=value line, plus an indented traceback.

    Sensitive fields are redacted by name: the record's structured fields (log.with_field)
    and the fields written in its message and exception messages.
    """

    def format(self, record: logging.LogRecord) -> str:
        args = record.args
        if isinstance(args, tuple):  # exceptions logged as arguments: type and redacted message
            record.args = tuple(describe(a) if isinstance(a, BaseException) else a for a in args)
        try:
            message = record.getMessage()
        finally:
            record.args = args
        parts = [
            f"time={datetime.fromtimestamp(record.created, UTC).isoformat()}",
            f"level={record.levelname.lower()}",
            f"{REQUEST_ID_KEY}={request_id_var.get()}",
            f"msg={sanitize(redact(message))}",
        ]
        fields: dict[str, Any] = redact_fields(getattr(record, "fields", {}))
        parts.extend(f"{sanitize(key)}={sanitize(value)}" for key, value in fields.items())
        if record.name != LOGGER_NAME:
            parts.append(f"logger={record.name}")
        parts.append(f"{SERVER_NAME_KEY}={server_name_var.get() or _process_server_name or '-'}")
        parts.append(f"{RESOURCE_KEY}={resource_var.get()}")
        line = " ".join(parts)
        if record.exc_info and record.exc_info[1] is not None:
            line += format_traceback(record.exc_info[1])
        return line


class Clog:
    """Logger that carries structured fields on every line.

    with_field and with_fields return a new logger; the shared one is never changed.
    """

    def __init__(self, logger: logging.Logger, fields: dict[str, Any] | None = None) -> None:
        self._logger = logger
        self._fields = dict(fields or {})

    def with_field(self, key: str, value: Any) -> Clog:
        """Return a logger that also carries key=value."""
        return Clog(self._logger, {**self._fields, key: value})

    def with_fields(self, fields: dict[str, Any]) -> Clog:
        """Return a logger that also carries fields."""
        return Clog(self._logger, {**self._fields, **fields})

    def info(self, fmt: str, *args: Any) -> None:
        """Log information."""
        self._log(logging.INFO, fmt, args)

    def error(self, fmt: str, *args: Any, exc_info: BaseException | None = None) -> None:
        """Log an error, with exc_info's traceback if given."""
        self._log(logging.ERROR, fmt, args, exc_info=exc_info)

    def _log(
        self,
        level: int,
        fmt: str,
        args: tuple[Any, ...],
        *,
        exc_info: BaseException | None = None,
    ) -> None:
        self._logger.log(level, fmt, *args, extra={"fields": self._fields}, exc_info=exc_info)


_logger = logging.getLogger(LOGGER_NAME)
_logger.setLevel(logging.INFO)

# The logger every module uses.
log = Clog(_logger)


def configure_logging(service_name: str, dsn: str = "", level: int = logging.INFO) -> None:
    """Send every log record in the process, ours and libraries', to stdout in one format.

    uvicorn's access log is turned off: it writes client addresses and full URLs, query
    strings (confirmation tokens) included. lib/request_context.py logs each request instead.
    """
    global _process_server_name
    _process_server_name = service_name

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(_TextFormatter())
    logging.basicConfig(level=level, handlers=[handler], force=True)
    for name in ("uvicorn", "uvicorn.error"):
        library_logger = logging.getLogger(name)
        library_logger.handlers.clear()
        library_logger.propagate = True
    logging.getLogger("uvicorn.access").disabled = True

    if dsn:
        import sentry_sdk  # optional: pip install "health-tech[sentry]"

        # Nothing personal to Sentry either: no request bodies, cookies, headers, IPs or
        # local variables (which hold passwords and tokens).
        sentry_sdk.init(
            dsn=dsn,
            send_default_pii=False,
            include_local_variables=False,
            max_request_body_size="never",
        )
