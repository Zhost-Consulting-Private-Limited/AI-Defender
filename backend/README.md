# Backend API + Dashboard

## Run

```bash
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Open `http://127.0.0.1:8000` for dashboard.

## Database configuration

### Environment profiles

The backend now uses `APP_ENV` to enforce database posture:

- `development` (default): local sqlite is allowed.
- `test`: sqlite is allowed and recommended for local/CI tests.
- `staging` / `production`: `DATABASE_URL` must be explicitly set and cannot be sqlite.

```bash
export APP_ENV=development
export DATABASE_URL=sqlite:///./security_platform.db
```

For PostgreSQL deployments, configure transport and pool behavior:

```bash
export DATABASE_URL=postgresql+psycopg://user:pass@db-host:5432/ai_defender
export DB_SSL_MODE=require
export DB_POOL_RECYCLE=1800
```

> Emergency override only: set `ALLOW_SQLITE_IN_NON_DEV=true` to bypass sqlite enforcement in staging/production-like environments.

## Migrations (Alembic)

```bash
alembic upgrade head
alembic downgrade -1
```

Create a new migration:

```bash
alembic revision -m "describe_change"
```

## API key roles

Set env var `API_KEYS` (default below):

- `admin-key:admin`
- `analyst-key:analyst`
- `agent-key:agent`
