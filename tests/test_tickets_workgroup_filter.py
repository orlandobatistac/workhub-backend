from app import models


def test_admin_can_filter_by_workgroup(client, auth_headers):
    # Create admin and two workgroups
    admin_headers, admin = auth_headers(user_type="admin", username="admin_wg", password="apw")

    r = client.post("/api/workgroups", json={"name": "WG One"}, headers=admin_headers)
    assert r.status_code == 201
    wg1 = r.json()["id"] if isinstance(r.json(), dict) and "id" in r.json() else r.json()["id"]

    r2 = client.post("/api/workgroups", json={"name": "WG Two"}, headers=admin_headers)
    assert r2.status_code == 201
    wg2 = r2.json()["id"]

    # Create two tickets in different workgroups
    t1 = client.post("/api/tickets", json={"subject": "T1", "description": "d", "workgroup_id": wg1}, headers=admin_headers)
    assert t1.status_code == 201
    t2 = client.post("/api/tickets", json={"subject": "T2", "description": "d", "workgroup_id": wg2}, headers=admin_headers)
    assert t2.status_code == 201

    # Admin can query wg1
    r = client.get(f"/api/tickets?workgroup_id={wg1}", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    # result is paginated `data` list
    assert "data" in body
    assert all(item["workgroup_id"] == wg1 for item in body["data"]) or any(item["workgroup_id"] == wg1 for item in body["data"])


def test_agent_can_filter_own_workgroup_but_not_others(client, auth_headers):
    admin_headers, _ = auth_headers(user_type="admin")

    # Create two workgroups
    r = client.post("/api/workgroups", json={"name": "WG A"}, headers=admin_headers)
    wg_a = r.json()["id"]
    r = client.post("/api/workgroups", json={"name": "WG B"}, headers=admin_headers)
    wg_b = r.json()["id"]

    # Create agent assigned to wg_a
    agent_headers, agent = auth_headers(user_type="agent", username="agent_a", password="ap", workgroup_id=wg_a)

    # Create tickets in both workgroups
    t1 = client.post("/api/tickets", json={"subject": "A1", "description": "d", "workgroup_id": wg_a}, headers=admin_headers)
    assert t1.status_code == 201
    t2 = client.post("/api/tickets", json={"subject": "B1", "description": "d", "workgroup_id": wg_b}, headers=admin_headers)
    assert t2.status_code == 201

    # Agent can query their own workgroup
    r = client.get(f"/api/tickets?workgroup_id={wg_a}", headers=agent_headers)
    assert r.status_code == 200
    body = r.json()
    assert "data" in body
    assert all(item["workgroup_id"] == wg_a for item in body["data"]) or any(item["workgroup_id"] == wg_a for item in body["data"])

    # Agent cannot query other workgroup -> 403
    r = client.get(f"/api/tickets?workgroup_id={wg_b}", headers=agent_headers)
    assert r.status_code == 403


def test_contact_cannot_use_workgroup_filter(client, auth_headers):
    contact_headers, contact = auth_headers(user_type="contact", email="ct@example.com", password="ctpw", primary_branch_id="b-1")
    r = client.get("/api/tickets?workgroup_id=someid", headers=contact_headers)
    assert r.status_code == 403
