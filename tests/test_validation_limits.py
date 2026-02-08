import string


def test_ticket_missing_fields_and_types(client, auth_headers):
    headers, contact = auth_headers(user_type="contact", email="valcust@example.com", password="valpass", primary_branch_id="b-val")

    # Missing subject
    r = client.post("/api/tickets", json={"description": "desc"}, headers=headers)
    assert r.status_code == 422

    # Missing description
    r = client.post("/api/tickets", json={"subject": "Hi"}, headers=headers)
    assert r.status_code == 422

    # Subject too long (>200)
    long_subject = "x" * 201
    r = client.post("/api/tickets", json={"subject": long_subject, "description": "desc"}, headers=headers)
    assert r.status_code == 422

    # Description too long (>5000)
    long_desc = "x" * 5001
    r = client.post("/api/tickets", json={"subject": "ok", "description": long_desc}, headers=headers)
    assert r.status_code == 422

    # Invalid priority
    r = client.post("/api/tickets", json={"subject": "ok", "description": "ok", "priority": "super-urgent"}, headers=headers)
    assert r.status_code == 422

    # Wrong type for subject (int)
    r = client.post("/api/tickets", json={"subject": 123, "description": "desc"}, headers=headers)
    assert r.status_code == 422


def test_ticket_accepts_special_characters(client, auth_headers):
    headers, contact = auth_headers(user_type="contact", email="specchars@example.com", password="specpass", primary_branch_id="b-spec")

    subject = "¡Hola! 🚀 — Subject with punctuation & emojis"
    description = "Descripción con caracteres especiales: ñ, é, 漢字, emojis 😊"

    r = client.post("/api/tickets", json={"subject": subject, "description": description}, headers=headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    assert ticket["subject"] == subject
    assert ticket["description"] == description


def test_user_creation_field_validations(client, auth_headers):
    admin_headers, admin = auth_headers(user_type="admin", username="admin_val", password="adminvalpw")

    # Password too short
    r = client.post("/api/users/", json={
        "username": "u1",
        "email": "u1@example.com",
        "full_name": "U One",
        "password": "short",
        "user_type": "contact",
        "primary_branch_id": "b1"
    }, headers=admin_headers)
    assert r.status_code == 422

    # Agent without workgroup_id
    r = client.post("/api/users/", json={
        "username": "agent-x",
        "email": "agentx@example.com",
        "full_name": "Agent X",
        "password": "agentpassword",
        "user_type": "agent"
    }, headers=admin_headers)
    assert r.status_code == 422

    # Admin without username
    r = client.post("/api/users/", json={
        "email": "adminx@example.com",
        "full_name": "Admin X",
        "password": "adminpassword",
        "user_type": "admin"
    }, headers=admin_headers)
    assert r.status_code == 422

    # Invalid email
    r = client.post("/api/users/", json={
        "username": "user2",
        "email": "not-an-email",
        "full_name": "User Two",
        "password": "strongpassword",
        "user_type": "contact",
        "primary_branch_id": "b2"
    }, headers=admin_headers)
    assert r.status_code == 422


def test_message_validation(client, auth_headers):
    headers, contact = auth_headers(user_type="contact", email="msgval@example.com", password="msgvalpw", primary_branch_id="b-mv")

    # Create ticket
    r = client.post("/api/tickets", json={"subject": "MsgVal", "description": "desc"}, headers=headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Empty content
    r = client.post(f"/api/tickets/{ticket_id}/messages", json={"ticket_id": ticket_id, "content": ""}, headers=headers)
    assert r.status_code == 422

    # Missing ticket_id: allowed when path ticket_id is provided; should succeed
    r = client.post(f"/api/tickets/{ticket_id}/messages", json={"content": "hi"}, headers=headers)
    assert r.status_code == 201
