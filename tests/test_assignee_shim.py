import os
from fastapi.testclient import TestClient

# Set test DB before importing app so engine uses in-memory SQLite
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'

import main
from main import Base, engine, SessionLocal, UserModel, get_password_hash, create_access_token


def setup_module(module):
    # Create tables in the in-memory test DB
    Base.metadata.create_all(bind=engine)


def create_user(session, username: str, agent_external_id: str = None) -> UserModel:
    user = UserModel(
        username=username,
        email=f"{username}@example.test",
        full_name=username,
        hashed_password=get_password_hash("testpass"),
        role="agent" if agent_external_id else "user",
        agent_external_id=agent_external_id,
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def test_create_ticket_with_assignee_agent_mapping():
    session = SessionLocal()
    # Create a user that represents an agent with agent_external_id 'AG-001'
    user = create_user(session, "agent_user", agent_external_id="AG-001")

    client = TestClient(main.app)
    token = create_access_token({"sub": user.username})
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "subject": "Ticket with legacy assignee",
        "description": "Testing mapping from assignee_agent_id",
        "assignee_agent_id": "AG-001",
    }

    r = client.post("/api/tickets", json=payload, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("assignee_user_id") == user.id


def test_update_ticket_assign_by_agent_value():
    session = SessionLocal()
    # Create mapping user
    user = create_user(session, "agent_user2", agent_external_id="AG-002")

    # Create a ticket first (authenticated as same user)
    client = TestClient(main.app)
    token = create_access_token({"sub": user.username})
    headers = {"Authorization": f"Bearer {token}"}

    create_payload = {
        "subject": "Ticket to update",
        "description": "Initial",
    }

    r = client.post("/api/tickets", json=create_payload, headers=headers)
    assert r.status_code == 200
    ticket = r.json()

    # Update with legacy assignee id
    update_payload = {"assignee_agent_id": "AG-002"}
    r2 = client.put(f"/api/tickets/{ticket['id']}", json=update_payload, headers=headers)
    assert r2.status_code == 200, r2.text
    updated = r2.json()
    assert updated.get("assignee_user_id") == user.id
