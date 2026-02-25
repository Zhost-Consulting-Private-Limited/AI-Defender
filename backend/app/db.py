import os

from sqlmodel import SQLModel, Session, create_engine

from . import models  # noqa: F401

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./security_platform.db")
connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, echo=False, connect_args=connect_args)


def init_db() -> None:
    SQLModel.metadata.create_all(engine)


def get_session():
    with Session(engine) as session:
        yield session
