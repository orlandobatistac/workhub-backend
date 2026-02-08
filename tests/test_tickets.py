from datetime import datetime, timedelta, timezone


def test_ticket_creation_and_sla(client, create_user, auth_headers):
    # Create contact user and token
    headers, contact = auth_headers(user_type="contact", username=None, email="cust1@example.com", password="custpass", primary_branch_id="branch-101")

    # Create ticket as contact (should auto-set branch_id and contact_id)
    r = client.post("/api/tickets", json={
        "subject": "Help needed",
        "description": "Please help",
        "priority": "urgent"
    }, headers=headers)
    assert r.status_code == 201
    body = r.json()

    # New behavior: ticket creation returns both ticket and first_message when description present
    assert "ticket" in body and "first_message" in body
    ticket = body["ticket"]
    first = body["first_message"]

    assert ticket["priority"] == "urgent"
    assert ticket["status"] == "new"
    assert ticket["branch_id"] == contact.primary_branch_id if hasattr(contact, "primary_branch_id") else contact["primary_branch_id"]

    # due_date ~ created_at + SLA days
    created_at = datetime.fromisoformat(ticket["created_at"]) if isinstance(ticket["created_at"], str) else ticket["created_at"]
    due_date = datetime.fromisoformat(ticket["due_date"]) if isinstance(ticket["due_date"], str) else ticket["due_date"]
    assert (due_date - created_at).days == 1  # urgent -> 1 day

    # Verify first message created from description
    assert first["content"] == "Please help"
    assert first["sender_type"] == "contact"


def test_agent_auto_assign_on_message(client, create_user, auth_headers):
    # Create contact and agent
    contact_headers, contact = auth_headers(user_type="contact", username=None, email="cust2@example.com", password="custpass2", primary_branch_id="b-2")
    agent_headers, agent = auth_headers(user_type="agent", username="agent-xyz", password="agentpass2", workgroup_id="wg-x")

    # Contact creates ticket
    r = client.post("/api/tickets", json={"subject": "Issue", "description": "desc"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]
    assert ticket["status"] == "new"

    # Agent posts message -> should auto-assign and open ticket
    r = client.post(f"/api/tickets/{ticket_id}/messages", json={"ticket_id": ticket_id, "content": "I'm on it"}, headers=agent_headers)
    assert r.status_code == 201

    # Fetch ticket and verify assignment
    r = client.get(f"/api/tickets/{ticket_id}", headers=agent_headers)
    assert r.status_code == 200
    t = r.json()
    assert t["assignee_id"] == agent.id
    assert t["status"] == "open"


def test_ticket_create_with_first_message_multipart(client, auth_headers):
    # Contact creates a ticket and includes first message with file attachment in one multipart request
    contact_headers, contact = auth_headers(user_type="contact", username=None, email="multipart@example.com", password="mpass", primary_branch_id="b-mp")

    files = [("attachments", ("note.txt", b"hello multipart", "text/plain"))]
    data = {"subject": "Multi", "description": "This is the first message with attachment", "priority": "low"}

    r = client.post("/api/tickets", data=data, files=files, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()

    assert "ticket" in body and "first_message" in body
    ticket = body["ticket"]
    first = body["first_message"]

    assert ticket["subject"] == "Multi"
    assert first["content"] == "This is the first message with attachment"
    assert first["attachments"] is not None and len(first["attachments"]) == 1

    att = first["attachments"][0]
    assert att.get("path") and att.get("url")

    # Verify file on disk
    from urllib.parse import urlparse
    path = att["path"]
    assert path and path.startswith("uploads/messages/")
    import os
    assert os.path.exists(path)

    # Contact (owner) can download
    dl = client.get(att["url"], headers=contact_headers)
    assert dl.status_code == 200
    assert dl.content == b"hello multipart"
