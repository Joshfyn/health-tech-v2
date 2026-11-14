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

Interactive API docs: http://localhost:8080/docs and http://localhost:8081/docs.

## Try it

Creating users needs a super admin token. Mint one locally:

```bash
TOKEN=$(uv run python -c "from health_tech.lib.tokenmaker import *; print(generate_token(TokenRequirements(role='super_admin')))")
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
```

## Endpoints

| Method | Path | Auth |
|---|---|---|
| POST | `/health-tech/auth/signin` | none |
| GET | `/health-tech/auth/validate` | `X-USER-TOKEN` |
| POST | `/health-tech/auth/refresh` | `X-USER-TOKEN` |
| POST | `/health-tech/user` | super admin |
| GET | `/health-tech/user` | none |
| GET | `/health-tech/user/confirm?token=...` | confirmation token |
| POST | `/health-tech/user/healthcare-providers` | hospital, pharmacy or super admin |

## Tests and lint

```bash
uv run pytest
uv run ruff check . && uv run ruff format --check .
```

Tests use a throwaway SQLite database per test; nothing else is needed.

## Configuration

All settings come from environment variables or `.env` (see `.env.example`).

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_URL` | `sqlite:///./health_tech.db` | Database for local development |
| `USER_SERVICE_PORT` / `AUTH_SERVICE_PORT` | `8080` / `8081` | Service ports |
| `JWT_SECRET` | empty | HS256 signing key; set it |
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
  auth/       sign in and token endpoints
  user/       users, role accounts, confirmation, providers
  lib/        config, db, tokenmaker, mail, password hashing, HTTP helpers
  logger.py   clog, the structured service logger
  migrate/    seed script
tests/
```

Each service has `dto.py` (request/response models), `middleware.py` (auth guards and body validation as FastAPI dependencies), `model.py` (tables and queries), `service.py` (handlers), `router.py` and `main.py`.
