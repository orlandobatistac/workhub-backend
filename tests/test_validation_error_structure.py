def test_validation_error_structure_on_missing_ticket_subject(client, auth_headers):
    headers, contact = auth_headers(user_type="contact", email="valstruct@example.com", password="valstructpw", primary_branch_id="b-vs")

    r = client.post("/api/tickets", json={"description": "missing subject"}, headers=headers)
    assert r.status_code == 422
    body = r.json()
    assert "error" in body and isinstance(body["error"], dict)
    assert body["error"].get("code") == "validation_error"
    assert "message" in body["error"]
    assert isinstance(body["error"].get("details"), list)
