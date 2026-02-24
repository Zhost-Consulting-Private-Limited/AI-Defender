# Backend API + Dashboard

## Run

```bash
pip install -r backend/requirements.txt
uvicorn backend.app.main:app --reload
```

Open `http://127.0.0.1:8000` for dashboard.

## API key roles

Set env var `API_KEYS` (default below):

- `admin-key:admin`
- `analyst-key:analyst`
- `agent-key:agent`
