"""Database configuration and session management for WorkHub.

Exports:
- Base: declarative base for models
- engine: SQLAlchemy engine
- SessionLocal: session factory
- get_db: FastAPI dependency that yields a DB session
- init_db(): helper to create tables (calls Base.metadata.create_all)

Behavior:
- Reads DATABASE_URL from env, falls back to a local SQLite file `workhub.db` in the project root.
- Uses connect_args for SQLite to allow multi-threaded access in dev.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Generator, Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, declarative_base, sessionmaker

logger = logging.getLogger(__name__)

# Project root (two levels up from this file)
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _default_sqlite_url() -> str:
    db_path = PROJECT_ROOT / "workhub.db"
    # ensure parent dir exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{db_path.as_posix()}"


DATABASE_URL: str = os.getenv("DATABASE_URL", _default_sqlite_url())

# Engine options: SQLite requires `check_same_thread=False` when using threads (uvicorn)
engine_kwargs = {"future": True}
if DATABASE_URL.startswith("sqlite"):
    engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, **engine_kwargs)
else:
    engine = create_engine(DATABASE_URL, **engine_kwargs)

# Session factory
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False, class_=Session)

# Declarative base for models
Base = declarative_base()


def get_db() -> Generator[Session, None, None]:
    """Yield a SQLAlchemy DB session for FastAPI dependencies.

    Usage:
        def endpoint(db: Session = Depends(get_db)):
            ...
    """
    db: Optional[Session] = None
    try:
        db = SessionLocal()
        yield db
    finally:
        if db is not None:
            db.close()


def init_db() -> None:
    """Create all tables for the registered models.

    This will import `app.models` to ensure model classes are registered
    with `Base` before calling `Base.metadata.create_all()`.
    """
    try:
        # Import models to ensure they are registered on Base.metadata
        # (import here to avoid circular imports at module import time)
        import app.models  # noqa: F401

        logger.info("Creating database tables (if not exists)")
        Base.metadata.create_all(bind=engine)
        logger.info("Database initialized")
    except Exception as exc:
        logger.exception("Failed to initialize database: %s", exc)
        raise


__all__ = ["Base", "engine", "SessionLocal", "get_db", "init_db"]
