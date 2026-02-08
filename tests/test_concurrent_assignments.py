import threading


def _assign(client, ticket_id, assignee_id, headers, result_list, idx):
    r = client.patch(f"/api/tickets/{ticket_id}/assign", json={"assignee_id": assignee_id}, headers=headers)
    result_list[idx] = (r.status_code, r.json() if r.text else None)


def test_concurrent_agent_assignment(client, create_user, auth_headers):
    # Create contact and ticket
    contact_headers, contact = auth_headers(user_type="contact", email="concurrent@example.com", password="cpass", primary_branch_id="b-conc")

    r = client.post("/api/tickets", json={"subject": "Concurrency", "description": "Test concurrent assign"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Create two agents
    agent1_headers, agent1 = auth_headers(user_type="agent", username="conc_agent1", password="ap1", workgroup_id="wg-conc")
    agent2_headers, agent2 = auth_headers(user_type="agent", username="conc_agent2", password="ap2", workgroup_id="wg-conc")

    # Use admin for assignment privileges (require_agent_or_admin allows agent itself too)
    # Simulate a stale-client attempting to assign using an old version (If-Match/X-IF-VERSION)
    current = client.get(f"/api/tickets/{ticket_id}", headers=agent1_headers)
    assert current.status_code == 200
    current_version = current.json().get("version", 0)

    headers1 = {**agent1_headers, "X-IF-VERSION": str(current_version)}
    headers2 = {**agent2_headers, "X-IF-VERSION": str(current_version)}

    # First assignment should succeed
    r1 = client.patch(f"/api/tickets/{ticket_id}/assign", json={"assignee_id": agent1.id}, headers=headers1)
    assert r1.status_code in (200, 201)

    # Second assignment using the same stale version should fail with 409
    r2 = client.patch(f"/api/tickets/{ticket_id}/assign", json={"assignee_id": agent2.id}, headers=headers2)
    assert r2.status_code == 409

    # Verify ticket is assigned to the first agent
    r = client.get(f"/api/tickets/{ticket_id}", headers=agent1_headers)
    assert r.status_code == 200
    t = r.json()
    assert t["assignee_id"] == agent1.id
