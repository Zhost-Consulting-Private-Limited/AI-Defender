import os
from functools import lru_cache

from sqlmodel import SQLModel, Session, create_engine

from . import models  # noqa: F401


@lru_cache(maxsize=1)
def load_db_config() -> dict:
    app_env = os.getenv("APP_ENV", "development").strip().lower()
    database_url = os.getenv("DATABASE_URL", "sqlite:///./security_platform.db")
    enforce_non_sqlite = os.getenv("ALLOW_SQLITE_IN_NON_DEV", "false").strip().lower() != "true"

    if app_env in {"staging", "production"} and enforce_non_sqlite:
        if not os.getenv("DATABASE_URL"):
            raise RuntimeError("DATABASE_URL must be explicitly set when APP_ENV is staging/production")
        if database_url.startswith("sqlite"):
            raise RuntimeError("sqlite is not supported when APP_ENV is staging/production")

    engine_kwargs = {"echo": False}
    if database_url.startswith("sqlite"):
        engine_kwargs["connect_args"] = {"check_same_thread": False}
    else:
        engine_kwargs["pool_pre_ping"] = True
        engine_kwargs["pool_recycle"] = int(os.getenv("DB_POOL_RECYCLE", "1800"))

        if database_url.startswith("postgresql"):
            ssl_mode = os.getenv("DB_SSL_MODE", "require" if app_env in {"staging", "production"} else "prefer")
            engine_kwargs["connect_args"] = {"sslmode": ssl_mode}

    return {
        "app_env": app_env,
        "database_url": database_url,
        "engine_kwargs": engine_kwargs,
    }


@lru_cache(maxsize=1)
def get_engine():
    config = load_db_config()
    return create_engine(config["database_url"], **config["engine_kwargs"])


def init_db() -> None:
    SQLModel.metadata.create_all(get_engine())


def get_session():
    with Session(get_engine()) as session:
        yield session
