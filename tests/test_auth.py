def test_login_and_me(client, create_user):
    # Seed an admin user
    admin = create_user(user_type="admin", username="adminuser", email="admin@example.com", password="adminpass")

    # Login with username
    r = client.post("/api/auth/login", json={"username_or_email": "adminuser", "password": "adminpass"})
    assert r.status_code == 200
    body = r.json()
    assert "access_token" in body
    token = body["access_token"]

    # Call /me
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    me = r.json()
    assert me["email"] == "admin@example.com"
    assert me["user_type"] == "admin"


def test_login_with_email(client, create_user):
    user = create_user(user_type="contact", username=None, email="contact@example.com", password="contpass", primary_branch_id="branch-x")

    r = client.post("/api/auth/login", json={"username_or_email": "contact@example.com", "password": "contpass"})
    assert r.status_code == 200
    body = r.json()
    assert body["user"]["user_type"] == "contact"
