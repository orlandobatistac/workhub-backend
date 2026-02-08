def test_message_lifecycle(client, create_user, auth_headers):
    contact_headers, contact = auth_headers(user_type="contact", email="msgcust@example.com", password="msgpass", primary_branch_id="b-msg")
    agent_headers, agent = auth_headers(user_type="agent", username="agent-msg", password="agentmsgpass", workgroup_id="wg-msg")

    # Create ticket
    r = client.post("/api/tickets", json={"subject": "MsgTest", "description": "desc"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Contact posts message
    r = client.post(f"/api/tickets/{ticket_id}/messages", json={"ticket_id": ticket_id, "content": "contact here"}, headers=contact_headers)
    assert r.status_code == 201
    msg = r.json()
    assert msg["sender_type"] == "contact"

    # Agent posts message and should auto-assign
    r = client.post(f"/api/tickets/{ticket_id}/messages", json={"ticket_id": ticket_id, "content": "agent reply"}, headers=agent_headers)
    assert r.status_code == 201

    # List messages
    r = client.get(f"/api/tickets/{ticket_id}/messages", headers=agent_headers)
    assert r.status_code == 200
    body = r.json()
    assert len(body["data"]) >= 2

    # Get single message
    mid = body["data"][0]["id"]
    r = client.get(f"/api/messages/{mid}", headers=agent_headers)
    assert r.status_code == 200
    m = r.json()
    assert m["ticket_id"] == ticket_id
