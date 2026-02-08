def _extract_messages(body):
    """Normalize different error shapes to a list of message strings.

    Accepts either the full response body (our standardized format) or a
    legacy FastAPI `detail` list/dict/string value.
    """
    # Standardized: {"error": {"code":..., "message":..., "details": [...]}}
    if isinstance(body, dict) and "error" in body:
        err = body["error"]
        details = err.get("details")
        if isinstance(details, list):
            return _extract_messages(details)
        # fallback to message
        return [err.get("message", "")]

    # Legacy FastAPI/Pydantic detail
    detail = body.get("detail") if isinstance(body, dict) else body

    if isinstance(detail, str):
        return [detail]
    if isinstance(detail, list):
        msgs = []
        for it in detail:
            if isinstance(it, dict):
                # Typical Pydantic error
                msgs.append(it.get("msg", ""))
            else:
                msgs.append(str(it))
        return msgs
    return [str(detail)]


def test_ticket_subject_required_message(client, auth_headers):
    headers, contact = auth_headers(user_type="contact", email="msgerr@example.com", password="errpw", primary_branch_id="b-msgerr")

    r = client.post("/api/tickets", json={"description": "missing subject"}, headers=headers)
    assert r.status_code == 422
    body = r.json()
    msgs = _extract_messages(body)

    assert any("subject" in m.lower() or "field required" in m.lower() or "required" in m.lower() for m in msgs)


def test_ticket_priority_invalid_message(client, auth_headers):
    headers, _ = auth_headers(user_type="contact", email="prioerr@example.com", password="errpw2", primary_branch_id="b-prio")

    r = client.post("/api/tickets", json={"subject": "ok", "description": "ok", "priority": "super-urgent"}, headers=headers)
    assert r.status_code == 422
    msgs = _extract_messages(r.json())

    assert any("priority" in m.lower() and ("one of" in m.lower() or "must be" in m.lower()) for m in msgs)


def test_user_agent_requires_workgroup_message(client, auth_headers):
    admin_headers, _ = auth_headers(user_type="admin", username="admin_err", password="adminpw")

    r = client.post("/api/users/", json={
        "username": "agent-no-wg",
        "email": "agentnowg@example.com",
        "full_name": "Agent Nowg",
        "password": "agentpassword",
        "user_type": "agent"
    }, headers=admin_headers)
    assert r.status_code == 422
    msgs = _extract_messages(r.json())

    # The model validator should indicate the missing workgroup_id in English
    assert any("workgroup" in m.lower() or "workgroup_id" in m.lower() or "required" in m.lower() for m in msgs)


def test_message_missing_content_user_friendly(client, auth_headers):
    headers, contact = auth_headers(user_type="contact", email="merr2@example.com", password="errpw3", primary_branch_id="b-merr")
    r = client.post("/api/tickets", json={"subject": "ErrTest2", "description": "desc"}, headers=headers)
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Post with no content -> our endpoint raises HTTPException detail="Missing content"
    r = client.post(f"/api/tickets/{ticket_id}/messages/", data={}, headers=headers)
    assert r.status_code == 422
    detail = r.json().get("detail")
    if isinstance(detail, list):
        assert any("missing content" in str(m).lower() or "content" in str(m).lower() for m in detail)
    else:
        assert "missing content" in str(detail).lower()
