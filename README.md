# health-tech

Backend for a patient health portal: an **auth** service (sign in, validate and refresh JWTs) and a **user** service (users, role accounts, email confirmation, provider onboarding). Built with FastAPI and SQLAlchemy.

Runs locally with no external services: data goes to a SQLite file and confirmation emails are printed to the terminal.

## Requirements

- Python 3.14
- [uv](https://docs.astral.sh/uv/) (recommended) or pip 25.1+

Install Python 3.14 if you don't have it:

```bash
# macOS
brew install python@3.14
# Linux (or macOS) with uv
uv python install 3.14
```

## Setup

```bash
cp .env.example .env
python3 -c "import secrets; print(secrets.token_urlsafe(48))"   # paste the output as JWT_SECRET in .env
```

Install dependencies with **uv**:

```bash
uv sync
```

or with **pip**:

```bash
python3.14 -m venv .venv
source .venv/bin/activate
pip install -e . && pip install --group dev
```

## Run

Run each service in its own terminal. With pip, drop the `uv run` prefix (the venv must be active).

```bash
uv run user-service    # http://localhost:8080
uv run auth-service    # http://localhost:8081
uv run seed-db         # optional: insert sample users
```

### Migrations

New databases get their tables and constraints on service start. To upgrade an existing database, run:

```bash
uv run migrate-db
```

It applies the SQL scripts in `src/health_tech/migrate/sql/<sqlite|postgresql>/` in filename order, each in one transaction. Scripts are written to be safe to run again.

Name scripts `<YYYYMMDDHHMMSS>_<name>.sql` using the UTC time they were written, so filename order is creation order; the runner rejects other names. Add each migration for both SQLite and PostgreSQL under the same name.

`20261114170306_role_account_id_not_nil.sql` gives each role account that was created without an ID (the nil UUID, which patient and super admin accounts used to get) its own ID, then adds a database rule that rejects a nil or NULL `role_account_id` on insert and update: a CHECK constraint on PostgreSQL, triggers on SQLite. Until it runs, those accounts cannot sign in.

`20261117201625_role_accounts_email_role_unique.sql` adds the unique index `uq_role_accounts_email_role` on `role_accounts (email, role)`, so no two logins share an email and role; one email can still hold several logins in different roles. New databases get the index on service start. If duplicates already exist, the script fails and changes nothing; it does not pick which login to keep. Find them with:

```sql
SELECT email, role, COUNT(*) FROM role_accounts GROUP BY email, role HAVING COUNT(*) > 1;
```

Resolve each (remove or re-address the logins that should not exist), then run `migrate-db` again. Until the index is in place, sign in refuses with `500` an email and role held by more than one confirmed login rather than guess.

`20261117204659_lowercase_emails_and_names.sql` converts stored emails (`users` and `role_accounts`) and first and last names to lower case; the services store them that way on every write (see [Lower case](#lower-case)), so `Sam@example.com` and `sam@example.com` are one email. National IDs, contact details and passwords keep their case. If lower-casing would give two logins the same email and role, the script fails and changes nothing; find them with:

```sql
SELECT lower(email), role, COUNT(*) FROM role_accounts GROUP BY lower(email), role HAVING COUNT(*) > 1;
```

`migrate-db` runs SQLite scripts with a `lower()` that is the services' own handler, `lower_case` in `lib/normalize.py`; SQLite's own changes only ASCII (`ÉLODIE` would become `Élodie`). PostgreSQL's `lower()` follows the database's `LC_CTYPE`, so use a UTF-8 locale (the usual default); with the `C` locale it too changes only ASCII.

The `organisation_memberships` table is new, so service start and `migrate-db` create it; it needs no script.

Interactive API docs: http://localhost:8080/docs and http://localhost:8081/docs.

## Try it

Creating users needs a super admin access token. Mint one locally:

```bash
TOKEN=$(uv run python -c "from health_tech.lib.tokenmaker import *; print(generate_token(TokenRequirements(role='super_admin'), TokenPurpose.ACCESS))")
```

Create a patient:

```bash
curl -X POST http://localhost:8080/health-tech/user \
  -H "X-USER-TOKEN: $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"user1@example.com","role":"patient","firstName":"Sample","lastName":"Patient",
       "dateOfBirth":"1990-05-15T00:00:00Z","nationalID":"000000-0000","password":"choose-a-password",
       "contact":{"phone":"123439373","address":{"street":"1 Example Street","city":"Example City",
       "state":"EX","zipCode":"00000","country":"US"}}}'
```

The user service terminal prints the confirmation link. Open it (or `curl` it), then sign in:

```bash
curl -X POST http://localhost:8081/health-tech/auth/signin \
  -H "Content-Type: application/json" \
  -d '{"email":"user1@example.com","password":"choose-a-password","role":"patient"}'
# 200 {"message":"User signed in successfully","token":"<access token>","refresh_token":"<refresh token>"}
```

`role` says which login to sign in to, since one email can hold several (a patient who is also a doctor, say), each with its own password. It is required and must exactly match one of the `UserRole` values in `user/model.py`. A missing role gets `400 {"code":"role_required","error":"role is required"}` and any other value, such as `"p"` or `"Patient"`, gets `400 {"code":"invalid_role","error":"unknown role"}`, both before any account lookup. Each email and role pair belongs to at most one login (see Migrations), so the pair always names one account.

Emails are not case sensitive: they are stored in lower case, and sign in lower-cases the one given. Names are stored and returned in lower case too. Passwords are case sensitive.

Doctors, pharmacists, hospital admins and pharmacy admins work for organisations, possibly several, and sign in to one at a time, named by the mandatory `organisationId` query parameter (these roles are `ORGANISATION_ROLES` in `user/model.py`):

```bash
curl -X POST "http://localhost:8081/health-tech/auth/signin?organisationId=<organisation id>" \
  -H "Content-Type: application/json" \
  -d '{"email":"doctor@example.com","password":"choose-a-password","role":"doctor"}'
```

Without it they get `400 {"code":"organisation_id_required",...}`; a value that is not a UUID gets `400 {"code":"invalid_organisation_id",...}`. Other roles must not send it: `400 {"code":"organisation_id_not_allowed",...}`. All three are checked before any account lookup. The token's `OrganisationID` claim names the organisation signed in to.

A wrong password, an unknown email, a role the email does not hold, an organisation the login does not work for and an unconfirmed account all get the same `401 {"code":"invalid_credentials","error":"invalid credentials"}`, so the response does not reveal which emails have accounts, which roles they hold or where they work.

Send the access token as `X-USER-TOKEN`. A patient can read their own record, and only their own; the ID is the `user_id` from `/auth/validate`:

```bash
curl http://localhost:8080/health-tech/user/<user_id> -H "X-USER-TOKEN: <access token>"
# 200 with the record; 403 {"code":"forbidden","error":"Forbidden"} for anyone else's ID
```

A super admin lists users one page at a time:

```bash
curl "http://localhost:8080/health-tech/user?page=2&pageSize=50" -H "X-USER-TOKEN: $TOKEN"
# {"users":[...],"page":2,"pageSize":50,"total":120,"totalPages":3}
```

When the access token expires, exchange the refresh token for a new one:

```bash
curl -X POST http://localhost:8081/health-tech/auth/refresh -H "X-REFRESH-TOKEN: <refresh token>"
# {"token":"<new access token>"}
```

## Tokens

Every token is minted for one purpose and is rejected everywhere else:

| Purpose | Issued by | Accepted only by | Lifetime |
|---|---|---|---|
| `access` | sign in, refresh | `X-USER-TOKEN` on API calls and `/auth/validate` | 15 minutes |
| `refresh` | sign in | `X-REFRESH-TOKEN` on `/auth/refresh` | 8 hours |
| `email_confirmation` | user and provider creation (emailed) | `/user/confirm?token=...` | 2 hours |

### Identity claims

| Claim | Holds |
|---|---|
| `UserID` | the person: `users.id`. Authorization that is scoped to one patient compares this with the record's ID |
| `RoleAccountID` | the login the token was issued to: `role_accounts.role_account_id` |
| `Role`, `Email` | the role and email of that login |
| `OrganisationID` | the organisation the login signed in to; empty for patients and super admins |

Sign in takes every claim from the stored role account, never from the request. Refresh copies the claims of the refresh token. `/auth/validate` returns them as `user_id`, `role_account_id`, `role`, `email` and `organisation_id`.

Access and refresh tokens must carry all five claims; tokens issued before `OrganisationID` existed are rejected and their holders sign in again. Before this change `UserID` held the role account ID; tokens from then lack `RoleAccountID`, are rejected, and their holders must sign in again, so an old `UserID` is never taken for a person's ID. Confirmation links emailed before the change keep working until they expire: they name the person and role, and confirm the account matching email, person and role. New links also carry `RoleAccountID` and confirm exactly that account.

Purposes are separated twice: each has its own HMAC key derived from `JWT_SECRET`, and each token carries a `Purpose` claim that is checked on every validation. Refresh returns only an access token and does not renew the refresh token, so a session lasts at most 8 hours before the user has to sign in again. Lifetimes are set in `TOKEN_LIFETIME_SECONDS` in `lib/tokenmaker.py`.

## Endpoints

| Method | Path | Callers allowed |
|---|---|---|
| POST | `/health-tech/auth/signin` | anyone |
| GET | `/health-tech/auth/validate` | `X-USER-TOKEN` (access token) |
| POST | `/health-tech/auth/refresh` | `X-REFRESH-TOKEN` (refresh token) |
| POST | `/health-tech/user` | super admin |
| GET | `/health-tech/user?page=&pageSize=` | super admin |
| GET | `/health-tech/user/{user_id}` | super admin (any user), patient (own record only) |
| GET | `/health-tech/user/confirm?token=...` | anyone with the confirmation token |
| POST | `/health-tech/user/healthcare-providers` | hospital, pharmacy or super admin |
| POST | `/health-tech/user/healthcare-providers/organisations` | hospital, pharmacy or super admin |

### Access control

The user service checks the caller before anything else reads the request: `AccessControlMiddleware` (`lib/access.py`) enforces the table `ACCESS` in `user/router.py`, the one place that says which roles may call each endpoint. A refused caller gets `401` at once. Their body is never read, so they get `401` even for a body that is unsafe, malformed or too large, and no endpoint code runs:

- no `X-USER-TOKEN`, or not a valid access token (a refresh or confirmation token, an expired or forged one): `401 {"code":"unauthorized","error":"Unauthorized"}`;
- a valid token whose role the endpoint does not allow: `401 {"code":"role_not_allowed","error":"this role is not allowed to use this endpoint"}`. Doctors, pharmacists and hospital and pharmacy admins may not create, list or read users; patients may only read a record. Signing in again does not help, since the role stays the same, so clients should not retry on this code.

Rules that depend on the request itself stay with the endpoint and answer `403 forbidden`: a patient reading another person's record, a hospital admin managing a pharmacist, an admin naming another organisation. Every route must be in `ACCESS`; the service refuses to start otherwise, so a new endpoint cannot be left open by accident.

`POST /health-tech/user` creates patient and super admin logins with the user, or, with an empty `role`, only the person. Doctors, pharmacists and hospital and pharmacy admins get `400 account_role_not_allowed`: create the person with `role` empty, then their login with `POST /health-tech/user/healthcare-providers`.

`POST /health-tech/user/healthcare-providers` creates a provider login working for one organisation: `organisationId` in the body, required from super admins. Hospital and pharmacy admins add providers to the organisation they signed in to; naming another gets `403`. Hospital admins manage only doctors, pharmacy admins only pharmacists.

`POST /health-tech/user/healthcare-providers/organisations` lets an existing provider login work for another organisation too, with the same rules:

```bash
curl -X POST http://localhost:8080/health-tech/user/healthcare-providers/organisations \
  -H "X-USER-TOKEN: $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"doctor@example.com","role":"doctor","organisationId":"<organisation id>"}'
# 200 {"message":"Provider added to organisation"}
```

It answers `404 provider_not_found` when no login has that email and role, `409 already_in_organisation` when it already does, and `400 not_organisation_role` for patients and super admins. Organisations are identified by ID only; there is no organisation record yet.

Creating a login (`POST /health-tech/user` for patients and super admins, `POST /health-tech/user/healthcare-providers`) whose email and role another login already has gets `409 account_exists`, and nothing is created.

`GET /health-tech/user` returns one page of users, oldest first: `page` starts at 1 (default 1) and `pageSize` defaults to 20. A `pageSize` above 100 gets 100, and the response's `pageSize` says so; zero, negatives and non-numbers get `400`. A page past the end has an empty `users` list. The response carries `total` and `totalPages`. Listed users have no `nationalID`; it is shown only by `GET /health-tech/user/{user_id}`.

`GET /health-tech/user/{user_id}` answers `403` to a patient asking for any ID but their own token's `UserID`, whether or not that user exists. Doctors, pharmacists and hospital or pharmacy admins have no per-patient access yet and get `401 role_not_allowed`.

## Requests, responses and errors

### Every request body is checked before anything else

`lib/payload_guard.py` is ASGI middleware on both services. Before routing or any model sees a request, and right after access control lets the caller in, it reads the body (at most 64 KiB, else `413 payload_too_large`), which must be UTF-8 JSON (else `400 invalid_request_body`), and checks **every key and every string at any depth**, including fields no endpoint knows. The first that fails ends the request:

```bash
curl -X POST http://localhost:8080/health-tech/user -H "X-USER-TOKEN: $TOKEN" \
  -H "Content-Type: application/json" -d '{"user":"<html>example_name</>"}'
# 400 {"code":"unsafe_input","error":"request contains characters or content that are not allowed"}
```

The rule (`lib/safe_text.py`): strings may hold letters and digits in any script, combining accents, spaces and `' ’ - . , @ _ + ( ) : / #`, which is enough for names like `O'Brien` or `Élodie`, addresses like `12/3 Main St., Apt #4`, phone numbers, emails and timestamps. Anything else is refused: HTML (`< > &`), quotes, `; = % * \ | $`, control characters, emoji and invisible characters. So is text that reads as SQL (`--`, `UNION SELECT`, `DROP TABLE`, `' OR '1`, `pg_sleep(`, ...) or as a link (`https://`, any `scheme://`, `javascript:`, `data:`, `www.`). Keys must be field names (`[A-Za-z_][A-Za-z0-9_]*`, at most 64 characters). This is defence in depth: queries are parameterised and responses are JSON either way.

`password` values are exempt, because passwords are hashed, never shown and never put in a query, and limiting their characters would only weaken them. They are length-checked instead. Query and path parameters are not scanned by the guard: each is parsed strictly by its endpoint (positive integers, UUIDs, signed JWTs, which may legitimately contain `--`).

The log line for a refusal says where and why (`reason=character U+003C is not allowed at $.user`), never the value.

### Request rules

Request models (`lib/validation.py`, `*/dto.py`) drop fields they do not declare, so a client cannot set `id`, `createdAt`, a password hash or anything else not listed here.

| Field | Rule | Code |
|---|---|---|
| `email` | lower-cased, then a plain address (`local@domain.tld`), at most 254 characters | `invalid_email` |
| `firstName`, `lastName` | lower-cased, then letters, accents, spaces, `' ’ - .`; starts with a letter; at most 100 | `invalid_name`, `value_too_long` |
| `role` | exactly a `UserRole` value (may be empty on `POST /user` for a person who only gets provider logins later) | `invalid_role` |
| `password` (new) | 8 characters to 72 bytes (bcrypt's limit); any characters | `password_too_short`, `password_too_long` |
| `password` (sign in) | at most 72 bytes; no minimum, so a short wrong password is just wrong | `password_too_long` |
| `dateOfBirth` | optional; ISO 8601 text, in the past, not before 1900; without an offset it is UTC | `invalid_date_of_birth` |
| `nationalID` | letters, digits, spaces, `- . /`; at most 32 | `invalid_national_id`, `value_too_long` |
| `contact.phone` | digits, spaces, `+ ( ) - .`; at most 32 | `invalid_phone`, `value_too_long` |
| `contact.address.zipCode` | letters, digits, spaces, hyphens; at most 16 | `invalid_postal_code`, `value_too_long` |
| other address fields | safe text; street at most 200, others 100 | `unsafe_input`, `value_too_long` |

`POST /health-tech/user` requires `email`, `firstName`, `lastName` and `password` (`email_required`, `first_name_required`, ...). A value of the wrong type, or an ID that is not a UUID, gets `invalid_request_body`. A field rule's message names the field: `{"code":"value_too_long","error":"contact.address.street is too long"}`.

### Lower case

Emails and first and last names are stored in lower case. One module decides how: `lib/normalize.py`, whose handlers `lower_email` and `lower_name` (both full-Unicode `lower_case`: `ÉLODIE` → `élodie`) are the only lower-casing in the code. They are called:

- by the request models, before the field rules, so the rules check the value that is stored;
- by the `User` and `RoleAccount` models on every write, whatever makes it (the API, the seed script);
- by lookups by email (sign in, provider lookup, confirmation links);
- by `migrate-db`, as SQLite's `lower()`.

Passwords, roles, national IDs and contact details are never lower-cased. To lower-case another field, add a handler to `lib/normalize.py` and call it from the request field type and the model's `@validates`.

### Responses

Every endpoint answers with a response model (`ResponseModel` in `lib/validation.py`), never a database model: `UserResponse` and `UserSummaryResponse` copy the fields they show from `User`, and a stored `contact` is re-read through `ContactResponse`, so nothing else stored in it is shown. `dateOfBirth` is always present, `null` when unknown.

### Errors

Every error, whatever raised it (the services, the guard, FastAPI's own validation, an unknown path, an unexpected exception), has the same body:

```json
{"code": "invalid_credentials", "error": "invalid credentials"}
```

`code` is fixed snake_case and is the part to branch on; `error` is for people. All codes, with their statuses and messages, are in `lib/errors.py` (`ErrorCode`, `CATALOG`); there are no others. Messages are written there and never come from a library, the database or an exception: an unexpected failure is `500 {"code":"internal_error","error":"internal server error"}`, and its detail goes only to the log.

### Logging

There is one logger, `log` in `src/health_tech/logger.py`, and every module uses it. Once a service starts, uvicorn's and other libraries' records go through the same handler and format. Every line carries the request ID:

```
time=... level=info request_id=0b9a8c7d-... msg=Request completed: status=200 duration_ms=4 server_name=user resource=GET /health-tech/user/{user_id}
```

- **Request ID.** Each request gets one. A caller's `X-Request-ID` is kept if it is a UUID, so one ID can follow a request across services; anything else is replaced, since it could carry personal data into every line. The ID is returned in the `X-Request-ID` response header, on errors too, so a support request can quote it. Lines outside a request (startup, shutdown) have `request_id=-`.
- **One line per request.** `Request completed` records status and duration. Each error adds `Request failed: status=... code=...`, and a body refused by the payload guard adds `Request refused` with the rule and where it was broken (`at $.contact.address.street`; keys no request model declares show as `?`). uvicorn's access log is off: it writes client addresses and full URLs, including query strings that hold confirmation tokens.
- **Exception messages.** Errors are logged with the exception's type and message, for debugging: `Error sending confirmation email: MailError: failed to send confirmation email: ConnectionRefusedError: [Errno 111] Connection refused`. Unexpected exceptions also get their traceback, each line indented under `  | `, ending in the same message. Messages longer than 2000 characters are cut.
- **Redaction by field name.** A value is redacted because of the field it belongs to, never because of how it looks, so numbers, dates, IDs and codes stay readable. The sensitive fields are listed in `SENSITIVE_FIELDS` in `logger.py`: email, names, phone, national ID, date of birth, contact and address parts, user and login IDs, passwords and hashes, tokens, secrets, API keys, `Authorization` and cookies. Names are compared ignoring case and punctuation (`firstName` = `first_name`), and any name ending in `email`, `phone`, `password`, `token`, `secret`, ... counts too (`patient_email`, `csrf_token`). Values are redacted wherever their field is named:

  | Where | Logged as |
  |---|---|
  | structured fields: `log.with_fields({"email": ..., "page": 2})` | `email=[REDACTED] page=2`, at any depth (`contact`, lists) |
  | `field=value` in text, query strings included | `password=[REDACTED] host=db`, `?token=[REDACTED]&lang=en` |
  | JSON and Python dicts in text | `{"email": "[REDACTED]", "role": "patient"}` |
  | headers | `Authorization: [REDACTED]` |
  | PostgreSQL `Key (email, role)=(...)` | `Key (email, role)=([REDACTED], patient)` |
  | a URL's password | `postgresql://health:[REDACTED]@db` |
  | values listed without field names: PostgreSQL's `Failing row contains (...)`, SQLAlchemy's `[parameters: ...]` | `([REDACTED])`, `[parameters: [REDACTED]]` |

  A value with no field name is not redacted: `lookup failed for sam@example.com` is logged as written. So personal data goes into a log line, or an exception message, only as a named field (`log.with_field("email", email)`), never in free text. The mailer follows this rule for SMTP errors, which list refused recipients keyed by their addresses: it logs only the SMTP reply codes.
- **No personal data or tokens otherwise.** Log calls never pass emails, names, user IDs, passwords, tokens or request values. `resource` is the route template (`/health-tech/user/{user_id}`), never the URL. Control characters are escaped, so logged text cannot forge a line. With a Sentry DSN, Sentry is set up to send no request bodies, client data or local variables.
- `MAIL_BACKEND=console` prints confirmation links (tokens) and addresses to stdout, so it is refused when `ENV=prod`.

## Tests and lint

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

Tests use a throwaway SQLite database per test; nothing else is needed. To also run the migration tests against PostgreSQL, point `TEST_POSTGRES_URL` at a server where the user can create databases:

```bash
TEST_POSTGRES_URL=postgresql+psycopg://<user>@localhost:5432/postgres uv run pytest tests/test_migrate.py
```

## Configuration

All settings come from environment variables or `.env` (see `.env.example`).

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./health_tech.db` | Database for local development |
| `USER_SERVICE_PORT` / `AUTH_SERVICE_PORT` | `8080` / `8081` | Service ports |
| `JWT_SECRET` | empty | Master secret the per-purpose HS256 keys are derived from; required, token operations fail while it is empty. Changing it invalidates every outstanding token |
| `MAIL_BACKEND` | `smtp` | `console` prints emails (refused in production), `smtp` sends them via `SMTP_USER` / `SMTP_PASS` |
| `ENV` | empty | `prod` builds a PostgreSQL URL from `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME` and binds to port 80 |

### PostgreSQL (optional)

PostgreSQL 15 (or any version below 16) works instead of SQLite:

```bash
uv sync --extra postgres            # pip: pip install -e ".[postgres]"
createdb health_tech
# in .env:
DATABASE_URL=postgresql+psycopg://<user>:<password>@localhost:5432/health_tech
```

Tables are created on service start.

## Layout

```
src/health_tech/
  auth/       sign in and token endpoints; messages.py names the errors it answers with
  user/       users, role accounts, confirmation, providers; messages.py likewise
  lib/        errors.py        every error: status, fixed code, message
              safe_text.py     the rule for what text a client may send
              payload_guard.py middleware that applies it to every request body
              request_context.py middleware that gives each request its ID and log line
              access.py        middleware that admits only the roles each endpoint allows
              validation.py    request/response base models and validated field types
              normalize.py     the lower-case handlers for emails and names
              http.py          app factory, error handlers, body binding
              config, db, tokenmaker (purpose-bound JWTs), mail, password hashing
  logger.py   log, the one logger; request ID on every line, no personal data
  migrate/    seed script, migrate-db runner and its SQL scripts
tests/
```

Each service has `dto.py` (request/response models), `middleware.py` (request validation and per-request authorization as FastAPI dependencies), `model.py` (tables and queries), `service.py` (handlers), `router.py` and `main.py`.
