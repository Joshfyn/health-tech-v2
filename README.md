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

`20261117204659_lowercase_emails_and_names.sql` converts stored emails (`users` and `role_accounts`) and first and last names to lower case; the services store them that way on every write, so `Sam@example.com` and `sam@example.com` are one email. National IDs, contact details and passwords keep their case. If lower-casing would give two logins the same email and role, the script fails and changes nothing; find them with:

```sql
SELECT lower(email), role, COUNT(*) FROM role_accounts GROUP BY lower(email), role HAVING COUNT(*) > 1;
```

`migrate-db` runs SQLite scripts with a `lower()` that lower-cases all letters, as the services do; SQLite's own changes only ASCII (`ÉLODIE` would become `Élodie`). PostgreSQL's `lower()` follows the database's `LC_CTYPE`, so use a UTF-8 locale (the usual default); with the `C` locale it too changes only ASCII.

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

`role` says which login to sign in to, since one email can hold several (a patient who is also a doctor, say), each with its own password. It is required and must exactly match one of the `UserRole` values in `user/model.py`. A missing role gets `400 {"error":"role is required"}` and any other value, such as `"p"` or `"Patient"`, gets `400 {"error":"unknown role"}`, both before any account lookup. Each email and role pair belongs to at most one login (see Migrations), so the pair always names one account.

Emails are not case sensitive: they are stored in lower case, and sign in lower-cases the one given. Passwords are case sensitive.

Doctors, pharmacists, hospital admins and pharmacy admins work for organisations, possibly several, and sign in to one at a time, named by the mandatory `organisationId` query parameter (these roles are `ORGANISATION_ROLES` in `user/model.py`):

```bash
curl -X POST "http://localhost:8081/health-tech/auth/signin?organisationId=<organisation id>" \
  -H "Content-Type: application/json" \
  -d '{"email":"doctor@example.com","password":"choose-a-password","role":"doctor"}'
```

Without it they get `400 {"error":"organisation id is required"}`; a value that is not a UUID gets `400 {"error":"invalid organisation id"}`. Other roles must not send it: `400 {"error":"organisation id is not allowed for this role"}`. All three are checked before any account lookup. The token's `OrganisationID` claim names the organisation signed in to.

A wrong password, an unknown email, a role the email does not hold, an organisation the login does not work for and an unconfirmed account all get the same `401 {"error":"invalid credentials"}`, so the response does not reveal which emails have accounts, which roles they hold or where they work. The auth service's response messages are defined in `src/health_tech/auth/messages.py`.

Send the access token as `X-USER-TOKEN`. A patient can read their own record, and only their own; the ID is the `user_id` from `/auth/validate`:

```bash
curl http://localhost:8080/health-tech/user/<user_id> -H "X-USER-TOKEN: <access token>"
# 200 with the record; 403 {"error":"Forbidden"} for anyone else's ID
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

| Method | Path | Auth |
|---|---|---|
| POST | `/health-tech/auth/signin` | none |
| GET | `/health-tech/auth/validate` | `X-USER-TOKEN` (access token) |
| POST | `/health-tech/auth/refresh` | `X-REFRESH-TOKEN` (refresh token) |
| POST | `/health-tech/user` | super admin |
| GET | `/health-tech/user?page=&pageSize=` | super admin |
| GET | `/health-tech/user/{user_id}` | super admin (any user), patient (own record only) |
| GET | `/health-tech/user/confirm?token=...` | confirmation token |
| POST | `/health-tech/user/healthcare-providers` | hospital, pharmacy or super admin |
| POST | `/health-tech/user/healthcare-providers/organisations` | hospital, pharmacy or super admin |

`POST /health-tech/user/healthcare-providers` creates a provider login working for one organisation: `organisationId` in the body, required from super admins. Hospital and pharmacy admins add providers to the organisation they signed in to; naming another gets `403`. Hospital admins manage only doctors, pharmacy admins only pharmacists.

`POST /health-tech/user/healthcare-providers/organisations` lets an existing provider login work for another organisation too, with the same rules:

```bash
curl -X POST http://localhost:8080/health-tech/user/healthcare-providers/organisations \
  -H "X-USER-TOKEN: $TOKEN" -H "Content-Type: application/json" \
  -d '{"email":"doctor@example.com","role":"doctor","organisationId":"<organisation id>"}'
# 200 {"message":"Provider added to organisation"}
```

It answers `404 {"error":"provider account not found"}` when no login has that email and role, `409 {"error":"provider already works for this organisation"}` when it already does, and `400 {"error":"role does not work for organisations"}` for patients and super admins. Organisations are identified by ID only; there is no organisation record yet.

Creating a login (`POST /health-tech/user` for patients and super admins, `POST /health-tech/user/healthcare-providers`) whose email and role another login already has gets `409 {"error":"an account with this email and role already exists"}`, and nothing is created.

`GET /health-tech/user` returns one page of users, oldest first: `page` starts at 1 (default 1) and `pageSize` defaults to 20. A `pageSize` above 100 gets 100, and the response's `pageSize` says so; zero, negatives and non-numbers get `400`. A page past the end has an empty `users` list. The response carries `total` and `totalPages`. Listed users have no `nationalID`; it is shown only by `GET /health-tech/user/{user_id}`.

`GET /health-tech/user/{user_id}` answers `403` to a patient asking for any ID but their own token's `UserID`, whether or not that user exists, and to doctors, pharmacists and hospital or pharmacy admins, which have no per-patient access yet.

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
| `MAIL_BACKEND` | `smtp` | `console` prints emails, `smtp` sends them via `SMTP_USER` / `SMTP_PASS` |
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
  auth/       sign in and token endpoints; messages.py holds its response messages
  user/       users, role accounts, confirmation, providers; messages.py holds the response
              messages of user listing, record reads and confirmation
  lib/        config, db, tokenmaker (purpose-bound JWTs), mail, password hashing, HTTP helpers
  logger.py   clog, the structured service logger
  migrate/    seed script, migrate-db runner and its SQL scripts
tests/
```

Each service has `dto.py` (request/response models), `middleware.py` (auth guards and body validation as FastAPI dependencies), `model.py` (tables and queries), `service.py` (handlers), `router.py` and `main.py`.
