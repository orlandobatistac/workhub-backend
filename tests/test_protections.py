from fastapi.testclient import TestClient
from main import app

client = TestClient(app)


def test_get_branches_public():
    resp = client.get("/api/branches")
    assert resp.status_code == 200


def test_create_branch_requires_authentication():
    payload = {"branch_code": "BR-999", "name": "Test Branch", "address": "Nowhere"}
    resp = client.post("/api/branches", json=payload)
    assert resp.status_code == 401


def test_create_branch_forbidden_for_contact():
    # register a contact
    reg = client.post("/api/register", json={"username": "ctest", "email": "ctest@example.com", "full_name": "C Test", "password": "testpass123"})
    assert reg.status_code in (200, 201)

    # login
    login = client.post("/api/token", json={"username": "ctest", "password": "testpass123"})
    assert login.status_code == 200
    token = login.json().get("access_token")
    assert token

    headers = {"Authorization": f"Bearer {token}"}

    payload = {"branch_code": "BR-998", "name": "Forbidden Branch", "address": "Nowhere"}
    resp = client.post("/api/branches", json=payload, headers=headers)
    assert resp.status_code in (403, 401)  # contact shouldn't be allowed to create branches
