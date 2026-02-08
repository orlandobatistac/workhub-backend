def test_end_to_end_flow(client, create_user, auth_headers):
    """E2E: contact registers (fixture), logs in, creates ticket; agent replies -> ticket auto-assigns -> agent closes ticket."""

    # 1) Create contact and obtain token via auth_headers helper
    contact_headers, contact = auth_headers(user_type="contact", username=None, email="e2e_contact@example.com", password="custpass", primary_branch_id="branch-e2e")

    # 2) Contact creates a ticket
    r = client.post("/api/tickets", json={
        "subject": "E2E Issue",
        "description": "This is an end-to-end test",
        "priority": "medium",
    }, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]
    assert ticket["status"] == "new"
    assert ticket["contact_id"] == contact.id

    # 3) Create an agent and obtain token
    agent_headers, agent = auth_headers(user_type="agent", username="e2e_agent", password="agentpass", workgroup_id="wg-e2e")

    # 4) Agent posts a message -> should auto-assign and open ticket
    r = client.post(f"/api/tickets/{ticket_id}/messages", json={"ticket_id": ticket_id, "content": "I'll take this"}, headers=agent_headers)
    assert r.status_code == 201

    # 5) Fetch ticket and verify agent assignment and status
    r = client.get(f"/api/tickets/{ticket_id}", headers=agent_headers)
    assert r.status_code == 200
    t = r.json()
    assert t["assignee_id"] == agent.id
    assert t["status"] == "open"

    # 6) Agent closes the ticket
    r = client.patch(f"/api/tickets/{ticket_id}/close", json={"resolution": "resolved"}, headers=agent_headers)
    assert r.status_code == 200
    closed = r.json()
    assert closed["status"] == "closed"
    assert closed["resolution"] == "resolved"
