import os
from fastapi.testclient import TestClient

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
import main
from main import Base, engine, SessionLocal, get_password_hash, create_access_token, UserModel


def setup_module(module):
    Base.metadata.create_all(bind=engine)


def create_user(session, username: str, role: str = 'user', workgroup_id: str | None = None) -> UserModel:
    user = UserModel(
        username=username,
        email=f"{username}@example.test",
        full_name=username,
        hashed_password=get_password_hash("testpass"),
        role=role,
        agent_external_id=None,
        workgroup_id=workgroup_id,
        is_active=True,
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user


def test_contact_can_be_created_with_user_link():
    session = SessionLocal()
    user = create_user(session, 'contact_user')

    client = TestClient(main.app)
    token = create_access_token({"sub": user.username})
    headers = {"Authorization": f"Bearer {token}"}

    payload = {
        "contact_id": "C-001",
        "name": "Contact One",
        "email": "contact1@example.test",
        "primary_branch_id": "b1",
        "user_id": user.id,
    }

    r = client.post("/api/contacts", json=payload, headers=headers)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get('user_id') == user.id


def test_create_agent_creates_user_with_workgroup():
    client = TestClient(main.app)
    # Use an admin user to create agent
    session = SessionLocal()
    admin = create_user(session, 'admin1', role='admin')
    token = create_access_token({"sub": admin.username})
    headers = {"Authorization": f"Bearer {token}"}

    agent_payload = {
        "agent_id": "AG-999",
        "name": "Agent 999",
        "workgroup_id": "wg-1",
    }

    r = client.post('/api/agents', json=agent_payload, headers=headers)
    assert r.status_code == 200, r.text

    # Confirm corresponding user was created
    u = session.query(UserModel).filter(UserModel.agent_external_id == 'AG-999').first()
    assert u is not None
    assert u.workgroup_id == 'wg-1'
