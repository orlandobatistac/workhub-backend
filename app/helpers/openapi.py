"""OpenAPI augmentation helpers.

Moved from top-level `app/openapi_helper.py` into `app/helpers/` for better organization.
"""
from __future__ import annotations

from typing import Any, Dict


def augment_openapi(spec: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of `spec` augmented with examples for key operations.

    Adds:
    - request/response examples for POST /api/tickets
    - error examples for attachment errors
    """
    # Operate on a shallow copy to avoid mutating caller's object unexpectedly
    s = spec

    # Ensure paths exist
    paths = s.setdefault("paths", {})

    post_tickets = paths.get("/api/tickets", {}).get("post")

    if post_tickets is not None:
        # Request body example (JSON)
        rb = post_tickets.setdefault("requestBody", {})
        content = rb.setdefault("content", {})
        app_json = content.setdefault("application/json", {})
        app_json_examples = app_json.setdefault("examples", {})
        app_json_examples["create_ticket_example"] = {
            "summary": "Example JSON ticket creation (no files)",
            "value": {
                "subject": "Sistema lento",
                "description": "Desde ayer el sistema está muy lento",
                "priority": "medium",
                "workgroup_id": "wg-soporte-tecnico",
            },
        }

        # Response 201 example including first_message
        responses = post_tickets.setdefault("responses", {})
        resp_201 = responses.setdefault("201", {})
        resp_content = resp_201.setdefault("content", {})
        app_json_resp = resp_content.setdefault("application/json", {})
        app_json_resp_examples = app_json_resp.setdefault("examples", {})
        app_json_resp_examples["ticket_with_first_message"] = {
            "summary": "Created ticket with first message",
            "value": {
                "ticket": {
                    "id": "ticket-123",
                    "subject": "Sistema lento",
                    "description": "Desde ayer el sistema está muy lento",
                    "priority": "medium",
                    "status": "new",
                    "branch_id": "branch-main",
                    "workgroup_id": "wg-soporte-tecnico",
                    "assignee_id": None,
                    "contact_id": 5,
                    "due_date": "2026-02-12T10:00:00Z",
                    "created_by_id": 5,
                    "created_at": "2026-02-07T10:00:00Z",
                    "updated_at": "2026-02-07T10:00:00Z",
                },
                "first_message": {
                    "id": "msg-456",
                    "ticket_id": "ticket-123",
                    "sender_id": 5,
                    "sender_type": "contact",
                    "content": "Desde ayer el sistema está muy lento",
                    "attachments": [
                        {
                            "path": "uploads/messages/msg-456/abcd123_screenshot.png",
                            "url": "/api/attachments/messages/uploads%2Fmessages%2Fmsg-456%2Fabcd123_screenshot.png",
                            "name": "screenshot.png",
                            "type": "image/png",
                            "size": 1234567,
                        }
                    ],
                    "created_at": "2026-02-07T10:00:00Z",
                },
            },
        }

    # Error examples for attachment errors
    components = s.setdefault("components", {})
    schemas = components.setdefault("schemas", {})

    # Add general Error schema if not present
    schemas.setdefault(
        "APIError",
        {
            "type": "object",
            "properties": {
                "error": {
                    "type": "object",
                    "properties": {
                        "code": {"type": "string"},
                        "message": {"type": "string"},
                        "details": {"type": "array", "items": {"type": "string"}},
                    },
                }
            },
        },
    )

    # Add examples under components/examples
    examples = components.setdefault("examples", {})
    examples.setdefault(
        "attachment_too_large_example",
        {
            "summary": "Attachment too large error",
            "value": {"error": {"code": "attachment_too_large", "message": "Attachment too large: big.bin"}},
        },
    )
    examples.setdefault(
        "attachment_too_many_example",
        {
            "summary": "Attachment too many files error",
            "value": {"error": {"code": "attachment_too_many", "message": "Too many attachments: max 5 files allowed"}},
        },
    )

    return s
