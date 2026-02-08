def test_agent_cannot_change_user_type(client, auth_headers):
    # Admin creates a contact user
    admin_headers, admin = auth_headers(user_type="admin", username="admin_role", password="adminrole")
    r = client.post("/api/users/", json={
        "username": "victim",
        "email": "victim@example.com",
        "full_name": "Victim User",
        "password": "victimpw",
        "user_type": "contact",
        "primary_branch_id": "b-1"
    }, headers=admin_headers)
    assert r.status_code == 201
    victim = r.json()
    vid = victim["id"]

    # Agent tries to change victim's user_type -> 403
    agent_headers, agent = auth_headers(user_type="agent", username="role_agent", password="agentpw", workgroup_id="wg-1")
    r = client.patch(f"/api/users/{vid}", json={"user_type": "admin"}, headers=agent_headers)
    assert r.status_code == 403

    # Agent tries to change their own user_type -> 403
    r = client.patch(f"/api/users/{agent.id}", json={"user_type": "admin"}, headers=agent_headers)
    assert r.status_code == 403

    # Admin can change a user's user_type -> 200
    r = client.patch(f"/api/users/{vid}", json={"user_type": "agent"}, headers=admin_headers)
    assert r.status_code == 200
    updated = r.json()
    assert updated["user_type"] == "agent"


def test_contact_cannot_access_team_or_customers(client, auth_headers):
    contact_headers, contact = auth_headers(user_type="contact", email="nocust@example.com", password="nocustpw", primary_branch_id="pb-1")

    r = client.get("/api/users/team", headers=contact_headers)
    assert r.status_code == 403

    r = client.get("/api/users/customers", headers=contact_headers)
    assert r.status_code == 403


def test_user_can_update_own_profile_but_not_user_type(client, auth_headers):
    # Create a contact via auth_headers helper
    headers, user = auth_headers(user_type="contact", email="selfup@example.com", password="selfpw", primary_branch_id="pb-2")

    # Update full_name (allowed)
    r = client.patch(f"/api/users/{user.id}", json={"full_name": "New Name"}, headers=headers)
    assert r.status_code == 200
    body = r.json()
    assert body["full_name"] == "New Name"

    # Attempt to change own user_type -> 403
    r = client.patch(f"/api/users/{user.id}", json={"user_type": "agent"}, headers=headers)
    assert r.status_code == 403
