def test_branches_and_workgroups_crud(client, auth_headers):
    admin_headers, admin = auth_headers(user_type="admin", username="admin-crud", password="admcrud")

    # Create branch
    r = client.post("/api/branches/", json={"branch_code": "B1", "name": "Main Branch", "address": "Street 1"}, headers=admin_headers)
    assert r.status_code == 201
    branch = r.json()
    branch_id = branch["id"]

    # Get branch
    r = client.get(f"/api/branches/{branch_id}", headers=admin_headers)
    assert r.status_code == 200

    # Update branch
    r = client.patch(f"/api/branches/{branch_id}", json={"name": "Main Branch 2"}, headers=admin_headers)
    assert r.status_code == 200

    # Create workgroup
    r = client.post("/api/workgroups/", json={"name": "Support"}, headers=admin_headers)
    assert r.status_code == 201
    wg = r.json()
    wg_id = wg["id"]

    # List workgroups
    r = client.get("/api/workgroups/", headers=admin_headers)
    assert r.status_code == 200
    body = r.json()
    assert any(w["name"] == "Support" for w in body["data"])
