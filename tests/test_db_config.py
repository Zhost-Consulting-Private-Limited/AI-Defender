import importlib
import sys
from pathlib import Path

import pytest

sys.path.append(str(Path(__file__).resolve().parents[1]))


MODULE = "backend.app.db"


def _reload_db_module(monkeypatch, **env):
    monkeypatch.setenv("APP_ENV", env.get("APP_ENV", "development"))

    optional_vars = ["DATABASE_URL", "ALLOW_SQLITE_IN_NON_DEV", "DB_SSL_MODE", "DB_POOL_RECYCLE"]
    for var in optional_vars:
        if var in env:
            monkeypatch.setenv(var, env[var])
        else:
            monkeypatch.delenv(var, raising=False)

    if MODULE in sys.modules:
        del sys.modules[MODULE]
    module = importlib.import_module(MODULE)
    module.load_db_config.cache_clear()
    module.get_engine.cache_clear()
    return module


def test_staging_requires_explicit_database_url(monkeypatch):
    db = _reload_db_module(monkeypatch, APP_ENV="staging")
    with pytest.raises(RuntimeError, match="DATABASE_URL must be explicitly set"):
        db.load_db_config()


def test_staging_blocks_sqlite(monkeypatch):
    db = _reload_db_module(monkeypatch, APP_ENV="staging", DATABASE_URL="sqlite:///./security_platform.db")
    with pytest.raises(RuntimeError, match="sqlite is not supported"):
        db.load_db_config()


def test_staging_allows_sqlite_only_with_break_glass(monkeypatch):
    db = _reload_db_module(
        monkeypatch,
        APP_ENV="staging",
        DATABASE_URL="sqlite:///./security_platform.db",
        ALLOW_SQLITE_IN_NON_DEV="true",
    )
    assert db.load_db_config()["database_url"].startswith("sqlite")


def test_postgres_defaults_to_require_ssl_in_production(monkeypatch):
    db = _reload_db_module(
        monkeypatch,
        APP_ENV="production",
        DATABASE_URL="postgresql+psycopg://user:pass@localhost:5432/ai_defender",
    )
    assert db.load_db_config()["engine_kwargs"]["connect_args"]["sslmode"] == "require"
