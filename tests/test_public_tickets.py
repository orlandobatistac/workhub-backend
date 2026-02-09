import os
from fastapi.testclient import TestClient

os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
import main
from main import Base, engine, SessionLocal


def setup_module(module):
    Base.metadata.create_all(bind=engine)


def test_public_ticket_creates_contact_and_returns_token():
    client = TestClient(main.app)

    payload = {
        "name": "Public User",
        "email": "public@example.test",
        "subject": "Help needed",
        "description": "I need help",
        "primary_branch_id": "b-public"
    }

    r = client.post('/api/public/tickets', json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert 'id' in body and 'secret_token' in body

    # Verify contact created
    session = SessionLocal()
    from main import ContactModel
    cnt = session.query(ContactModel).filter(ContactModel.email == payload['email']).count()
    assert cnt == 1


def test_public_ticket_reuses_existing_contact():
    session = SessionLocal()
    # Create a contact manually
    # Create using ORM to avoid SQL text coercion issues
    from main import ContactModel
    c = ContactModel(id="c1", contact_id="C-000001", name="Existing", email="exist@example.test", primary_branch_id="b1")
    session.add(c)
    session.commit()

    client = TestClient(main.app)
    payload = {"name": "Existing", "email": "exist@example.test", "subject": "Hi", "description": "Hello"}
    r = client.post('/api/public/tickets', json=payload)
    assert r.status_code == 200
    body = r.json()
    assert 'id' in body and 'secret_token' in body