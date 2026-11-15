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
  -d '{"email":"user1@example.com","password":"choose-a-password"}'
# 200 {"message":"User signed in successfully","token":"<access token>","refresh_token":"<refresh token>"}
```

A wrong password, an unknown email and an unconfirmed account all get the same `401 {"error":"invalid credentials"}`, so the response does not reveal which emails have accounts. The auth service's response messages are defined in `src/health_tech/auth/messages.py`.

Send the access token as `X-USER-TOKEN`. When it expires, exchange the refresh token for a new one:

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

Purposes are separated twice: each has its own HMAC key derived from `JWT_SECRET`, and each token carries a `Purpose` claim that is checked on every validation. Refresh returns only an access token and does not renew the refresh token, so a session lasts at most 8 hours before the user has to sign in again. Lifetimes are set in `TOKEN_LIFETIME_SECONDS` in `lib/tokenmaker.py`.

## Endpoints

| Method | Path | Auth |
|---|---|---|
| POST | `/health-tech/auth/signin` | none |
| GET | `/health-tech/auth/validate` | `X-USER-TOKEN` (access token) |
| POST | `/health-tech/auth/refresh` | `X-REFRESH-TOKEN` (refresh token) |
| POST | `/health-tech/user` | super admin |
| GET | `/health-tech/user` | none |
| GET | `/health-tech/user/confirm?token=...` | confirmation token |
| POST | `/health-tech/user/healthcare-providers` | hospital, pharmacy or super admin |

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
  user/       users, role accounts, confirmation, providers
  lib/        config, db, tokenmaker (purpose-bound JWTs), mail, password hashing, HTTP helpers
  logger.py   clog, the structured service logger
  migrate/    seed script, migrate-db runner and its SQL scripts
tests/
```

Each service has `dto.py` (request/response models), `middleware.py` (auth guards and body validation as FastAPI dependencies), `model.py` (tables and queries), `service.py` (handlers), `router.py` and `main.py`.
