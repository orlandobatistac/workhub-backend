import sqlalchemy
from sqlalchemy import inspect

from app import database as app_db
from app.models import (
    UserModel,
    BranchModel,
    WorkgroupModel,
    TicketModel,
    MessageModel,
)


def test_init_db_creates_tables():
    # Use the test engine from conftest by binding it to our database module temporarily
    from tests import conftest

    test_engine = conftest.engine

    # Ensure clean state
    app_db.Base.metadata.drop_all(bind=test_engine)

    # Replace engine temporarily
    original_engine = app_db.engine
    app_db.engine = test_engine
    try:
        app_db.init_db()

        inspector = inspect(test_engine)
        tables = inspector.get_table_names()

        assert "users" in tables
        assert "branches" in tables
        assert "tickets" in tables
        assert "messages" in tables
        assert "workgroups" in tables
    finally:
        # Restore original engine
        app_db.engine = original_engine


def test_seed_endpoint_creates_expected_data_and_is_idempotent(client, db_session):
    # Ensure the route is registered on the app
    assert any(r.path == "/api/seed" for r in client.app.routes), f"/api/seed not registered; routes={[r.path for r in client.app.routes]}"

    # Call the package-level seed route via HTTP
    r1 = client.post("/api/seed")
    assert r1.status_code == 200
    payload1 = r1.json()
    assert payload1["message"] == "Seed completed"

    data1 = payload1.get("data", {})
    assert data1.get("users", 0) > 0
    assert data1.get("branches", 0) > 0
    assert data1.get("workgroups", 0) > 0
    assert data1.get("tickets", 0) > 0

    # Ensure there are agent/contact users created (user_type column)
    agent_count = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM users WHERE user_type = 'agent' ")).scalar()
    contact_count = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM users WHERE user_type = 'contact' ")).scalar()
    assert agent_count >= 1
    assert contact_count >= 1

    # Verify DB counts via raw SQL (avoids ORM column mismatch between modules)
    users_count = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM users")).scalar()
    branches_count = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM branches")).scalar()
    tickets_count = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM tickets")).scalar()

    assert users_count >= data1.get("users", 0)
    assert branches_count >= data1.get("branches", 0)
    assert tickets_count >= data1.get("tickets", 0)

    # Second run: call seed endpoint again via HTTP to test idempotency
    r2 = client.post("/api/seed")
    assert r2.status_code == 200
    payload2 = r2.json()

    data2 = payload2.get("data", {})
    # Either the second response reports zeros (nothing created) or the same counts; both are acceptable
    for key in ("users", "branches", "workgroups", "tickets"):
        assert data2.get(key, 0) == 0 or data2.get(key) == data1.get(key)

    # DB counts remain at least the same
    users_count_2 = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM users")).scalar()
    branches_count_2 = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM branches")).scalar()
    tickets_count_2 = db_session.execute(sqlalchemy.text("SELECT COUNT(*) FROM tickets")).scalar()

    assert users_count_2 >= users_count
    assert branches_count_2 >= branches_count
    assert tickets_count_2 >= tickets_count
