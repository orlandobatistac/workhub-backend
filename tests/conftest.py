"""Pytest fixtures for WorkHub tests.

Uses an in-memory SQLite database and FastAPI TestClient. Overrides the
`get_db` dependency so tests are isolated from any real DB file.
"""

import os
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.database as database
from app.main import app
from app.auth import get_password_hash
from app.models import Base, UserModel


TEST_DATABASE_URL = os.getenv("TEST_DATABASE_URL", "sqlite:///./test_workhub.db")

# Create test engine and session factory
engine = create_engine(TEST_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, expire_on_commit=False)


@pytest.fixture(autouse=True)
def setup_database():
    """Create tables before each test and drop them after to ensure isolation."""
    Base.metadata.create_all(bind=engine)
    try:
        yield
    finally:
        # Drop all tables to start clean for next test
        Base.metadata.drop_all(bind=engine)


@pytest.fixture()
def db_session():
    """Provide a SQLAlchemy session for direct DB access in tests."""
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()


# Override get_db dependency in the app
def _override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[database.get_db] = _override_get_db

# Tests run in an isolated environment; disable the global rate limiter to avoid
# flaky failures due to many auth calls across tests. We intentionally do this
# only for the test environment to keep rate limiting active in production.
try:
    app.state.limiter.enabled = False  # type: ignore[attr-defined]
except Exception:
    # If limiter API changes, don't break tests; just continue without disabling.
    pass


@pytest.fixture()
def client():
    """FastAPI test client using the app with overridden dependencies."""
    with TestClient(app) as c:
        yield c


# Helper: create a user directly in DB for tests
@pytest.fixture()
def create_user(db_session):
    def _create_user(user_type: str = "admin", username: str | None = None, email: str | None = None, password: str = "secret123", **kwargs):
        username = username or (f"{user_type}_" + uuid.uuid4().hex[:8])
        email = email or (f"{username}@example.com")
        hashed = get_password_hash(password)
        user = UserModel(
            username=username,
            email=email,
            full_name=(kwargs.get("full_name") or username),
            hashed_password=hashed,
            user_type=user_type,
            phone=kwargs.get("phone"),
            is_active=kwargs.get("is_active", True),
            workgroup_id=kwargs.get("workgroup_id"),
            primary_branch_id=kwargs.get("primary_branch_id"),
            external_id=kwargs.get("external_id"),
            created_at=datetime.now(timezone.utc),
        )
        db_session.add(user)
        db_session.commit()
        db_session.refresh(user)
        return user

    return _create_user


@pytest.fixture()
def auth_headers(client, create_user):
    """Return a helper to get auth headers for a user created via fixture."""
    def _auth_headers(user_type: str = "admin", username: str | None = None, email: str | None = None, password: str = "secret123", **kwargs):
        user = create_user(user_type=user_type, username=username, email=email, password=password, **kwargs)
        resp = client.post("/api/auth/login", json={"username_or_email": user.username or user.email, "password": password})
        assert resp.status_code == 200
        token = resp.json()["access_token"]
        return {"Authorization": f"Bearer {token}"}, user

    return _auth_headers
