def test_create_user_and_lists(client, auth_headers):
    admin_headers, admin = auth_headers(user_type="admin", username="admin2", password="adminpass2")

    # Create an agent
    r = client.post("/api/users/", json={
        "username": "agent1",
        "email": "agent1@example.com",
        "full_name": "Agent One",
        "password": "agentpass",
        "user_type": "agent",
        "workgroup_id": "wg-1"
    }, headers=admin_headers)
    assert r.status_code == 201
    agent = r.json()
    assert agent["user_type"] == "agent"

    # Create a contact
    r = client.post("/api/users/", json={
        "username": None,
        "email": "contact1@example.com",
        "full_name": "Contact One",
        "password": "contactpass",
        "user_type": "contact",
        "primary_branch_id": "b-1"
    }, headers=admin_headers)
    assert r.status_code == 201
    contact = r.json()
    assert contact["user_type"] == "contact"

    # List team (admin+agent)
    r = client.get("/api/users/team", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert any(u["email"] == "agent1@example.com" for u in body["data"])

    # List customers
    r = client.get("/api/users/customers", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert any(u["email"] == "contact1@example.com" for u in body["data"])
