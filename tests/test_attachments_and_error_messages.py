import os


def test_message_file_upload_and_storage(client, auth_headers):
    # Create contact and agent
    contact_headers, contact = auth_headers(user_type="contact", email="filecust@example.com", password="filepass", primary_branch_id="b-file")
    agent_headers, agent = auth_headers(user_type="agent", username="file_agent", password="agentfile", workgroup_id="wg-file")

    # Contact creates ticket
    r = client.post("/api/tickets", json={"subject": "FileTest", "description": "desc"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Sanity check: ticket is retrievable
    rr = client.get(f"/api/tickets/{ticket_id}", headers=contact_headers)
    assert rr.status_code == 200

    # Quick sanity check: posting JSON (existing behavior) should succeed
    r = client.post(f"/api/tickets/{ticket_id}/messages", json={"ticket_id": ticket_id, "content": "precheck"}, headers=agent_headers)
    assert r.status_code == 201, f"Unexpected response: {r.status_code} {r.text}"

    # Agent uploads a small text file
    files = [("attachments", ("note.txt", b"hello world", "text/plain"))]
    data = {"content": "Here is a file"}
    r = client.post(f"/api/tickets/{ticket_id}/messages/", data=data, files=files, headers=agent_headers)
    assert r.status_code == 201
    msg = r.json()
    assert msg["attachments"] is not None and len(msg["attachments"]) == 1

    # Attachment should be normalized to an object with path and url
    att = msg["attachments"][0]
    assert isinstance(att, dict)
    assert "path" in att and "url" in att

    # Verify file exists on disk using the stored path
    path = att["path"]
    assert os.path.exists(path)

    # Verify we can download the file via the provided URL
    dl = client.get(att["url"], headers=agent_headers)
    assert dl.status_code == 200
    assert dl.content == b"hello world"

    # Anonymous (no auth) cannot download
    dl_no_auth = client.get(att["url"])
    assert dl_no_auth.status_code == 401

    # Contact (owner) can download
    dl_owner = client.get(att["url"], headers=contact_headers)
    assert dl_owner.status_code == 200
    assert dl_owner.content == b"hello world"

    # Another contact (not owner) cannot download
    other_headers, other_contact = auth_headers(user_type="contact", email="otherfilecust@example.com", password="filepass2", primary_branch_id="b-file2")
    dl_other = client.get(att["url"], headers=other_headers)
    assert dl_other.status_code == 403


def test_ticket_attachment_download_via_app_route(client, auth_headers):
    # Create contact and agent
    contact_headers, contact = auth_headers(user_type="contact", email="ticketfile@example.com", password="tpass", primary_branch_id="b-ticket")
    agent_headers, agent = auth_headers(user_type="agent", username="ticket_agent", password="agentticket", workgroup_id="wg-ticket")

    # Create a ticket
    r = client.post("/api/tickets", json={"subject": "TicketFile", "description": "desc"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Simulate a legacy ticket attachment creation by writing a file under uploads/tickets
    import uuid, os
    unique = f"{uuid.uuid4().hex}_note.txt"
    base = os.path.abspath(os.path.join(os.getcwd(), "uploads", "tickets"))
    os.makedirs(base, exist_ok=True)
    path = os.path.join(base, unique)
    with open(path, "wb") as f:
        f.write(b"ticket data")

    # Access via bare filename (agent) should succeed
    r1 = client.get(f"/api/attachments/tickets/{unique}", headers=agent_headers)
    assert r1.status_code == 200
    assert r1.content == b"ticket data"

    # Anonymous cannot download ticket attachments
    r_no_auth = client.get(f"/api/attachments/tickets/{unique}")
    assert r_no_auth.status_code == 401

    # Contact (owner) cannot download legacy ticket attachments (agents/admins only)
    r_contact = client.get(f"/api/attachments/tickets/{unique}", headers=contact_headers)
    assert r_contact.status_code == 403

    # Access via quoted full path (agent)
    from urllib.parse import quote
    full = quote(f"uploads/tickets/{unique}", safe="")
    r2 = client.get(f"/api/attachments/tickets/{full}", headers=agent_headers)
    assert r2.status_code == 200
    assert r2.content == b"ticket data"


def test_attachment_mime_type_restrictions(client, auth_headers):
    contact_headers, contact = auth_headers(user_type="contact", email="mimecust@example.com", password="mimepass", primary_branch_id="b-mime")
    agent_headers, agent = auth_headers(user_type="agent", username="mime_agent", password="magent", workgroup_id="wg-mime")

    # Create ticket
    r = client.post("/api/tickets", json={"subject": "MimeTest", "description": "desc"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Upload disallowed mime (zip) -> should be rejected
    files = [("attachments", ("bad.zip", b"PK\x03\x04", "application/zip"))]
    data = {"content": "bad mime"}
    r = client.post(f"/api/tickets/{ticket_id}/messages/", data=data, files=files, headers=agent_headers)
    assert r.status_code == 400
    body = r.json()
    error = body.get("error") or (body.get("detail") and body["detail"].get("error"))
    assert isinstance(error, dict)
    assert error.get("code") == "attachment_invalid_type"

    # Upload allowed image mime -> success
    files = [("attachments", ("img.png", b"\x89PNG\r\n\x1a\n", "image/png"))]
    r = client.post(f"/api/tickets/{ticket_id}/messages/", data={"content":"img"}, files=files, headers=agent_headers)
    assert r.status_code == 201


def test_attachment_too_large_rejected(client, auth_headers):
    contact_headers, contact = auth_headers(user_type="contact", email="bigcust@example.com", password="bigpass", primary_branch_id="b-big")
    agent_headers, agent = auth_headers(user_type="agent", username="big_agent", password="agentbig", workgroup_id="wg-big")

    # Create ticket
    r = client.post("/api/tickets", json={"subject": "BigFile", "description": "desc"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Create a large payload > 10MB
    big = b"0" * (10 * 1024 * 1024 + 10)
    files = [("attachments", ("big.bin", big, "application/octet-stream"))]
    data = {"content": "This is too big"}
    r = client.post(f"/api/tickets/{ticket_id}/messages/", data=data, files=files, headers=agent_headers)
    assert r.status_code == 400
    body = r.json()
    # Accept both direct {"error": {...}} and wrapped {'detail': {'error': {...}}}
    error = body.get("error") or (body.get("detail") and body["detail"].get("error"))
    assert isinstance(error, dict)
    assert error.get("code") == "attachment_too_large"
    assert "Attachment too large" in error.get("message", "")


def test_attachment_too_many_rejected(client, auth_headers):
    contact_headers, contact = auth_headers(user_type="contact", email="manycust@example.com", password="manypass", primary_branch_id="b-many")
    agent_headers, agent = auth_headers(user_type="agent", username="many_agent", password="manyagent", workgroup_id="wg-many")

    # Create ticket
    r = client.post("/api/tickets", json={"subject": "ManyFiles", "description": "desc"}, headers=contact_headers)
    assert r.status_code == 201
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]

    # Build 6 small files
    files = [("attachments", (f"f{i}.txt", b"ok", "text/plain")) for i in range(6)]
    data = {"content": "too many"}
    r = client.post(f"/api/tickets/{ticket_id}/messages/", data=data, files=files, headers=agent_headers)
    assert r.status_code == 400
    body = r.json()
    error = body.get("error") or (body.get("detail") and body["detail"].get("error"))
    assert isinstance(error, dict)
    assert error.get("code") == "attachment_too_many"


def test_error_message_for_missing_fields_returns_422(client, auth_headers):
    headers, contact = auth_headers(user_type="contact", email="errcust@example.com", password="errpass", primary_branch_id="b-err")

    # Missing content -> 422 (via schema)
    r = client.post("/api/tickets/doesnotmatter/messages", data={}, headers=headers)
    # Note: invalid ticket id will 404 before validation; use a real ticket but missing content
    r = client.post("/api/tickets", json={"subject": "ErrTest", "description": "desc"}, headers=headers)
    body = r.json()
    ticket = body["ticket"] if isinstance(body, dict) and "ticket" in body else body
    ticket_id = ticket["id"]
    r = client.post(f"/api/tickets/{ticket_id}/messages/", data={}, headers=headers)
    assert r.status_code == 422
    body = r.json()
    detail = body.get("detail")
    if isinstance(detail, list):
        assert any("content" in (err.get("loc") or []) or "content" in str(err.get("msg", "")) for err in detail)
    else:
        # could be a simple string detail from our explicit HTTPException
        assert "Missing content" in str(detail)
