# Backend API + Dashboard

## Run

```bash
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Open `http://127.0.0.1:8000` for dashboard.

## Database configuration

Set `DATABASE_URL` to point to your runtime database (defaults to local sqlite):

```bash
export DATABASE_URL=sqlite:///./security_platform.db
```

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
