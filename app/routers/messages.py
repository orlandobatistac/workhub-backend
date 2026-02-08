"""Message routes: create and manage messages attached to tickets.

Implements:
- POST /api/tickets/{ticket_id}/messages  -> create message (auth required)
- GET  /api/tickets/{ticket_id}/messages  -> list messages for a ticket (auth + access rules)
- GET  /api/messages/{message_id}         -> get single message (auth + access rules)
- DELETE /api/messages/{message_id}       -> delete message (admin or sender)

Includes auto-assignment: when an agent posts a message to a ticket with status 'new',
that agent becomes the assignee and ticket.status -> 'open'.
"""

from __future__ import annotations

import io
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, Query, UploadFile, status, Form
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import get_current_user
from app.database import get_db
from app.dependencies import can_access_ticket

logger = logging.getLogger(__name__)

UPLOAD_BASE = os.path.abspath(os.path.join(os.getcwd(), "uploads", "messages"))
os.makedirs(UPLOAD_BASE, exist_ok=True)

# Upload limits
MAX_UPLOAD_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_ATTACHMENTS = 5  # max number of attachments per message

# Allowed MIME types for attachments (comma-separated in env var)
ALLOWED_ATTACHMENT_MIME_TYPES = os.getenv("ALLOWED_ATTACHMENT_MIME_TYPES", "image/*,text/plain,application/pdf")
ALLOWED_ATTACHMENT_MIME = [m.strip() for m in ALLOWED_ATTACHMENT_MIME_TYPES.split(",") if m.strip()]

def _mime_allowed(content_type: Optional[str]) -> bool:
    """Return True if content_type matches any allowed pattern (supports wildcard like image/*)."""
    if not content_type:
        return False
    for allowed in ALLOWED_ATTACHMENT_MIME:
        if allowed.endswith("/*"):
            prefix = allowed.split("/")[0]
            if content_type.startswith(prefix + "/"):
                return True
        elif content_type == allowed:
            return True
    return False

router = APIRouter(tags=["Messages"])

def _log_audit(db: Session, user_id: Optional[int], action: str, resource: str, resource_id: Optional[str], status_str: str, ip_address: Optional[str]) -> None:
    try:
        entry = models.AuditLogModel(
            user_id=user_id,
            username=None if user_id is None else None,
            action=action,
            resource=resource,
            resource_id=resource_id,
            details=None,
            status=status_str,
            ip_address=ip_address,
        )
        db.add(entry)
        db.commit()
    except Exception:
        logger.exception("Failed to write audit log")


from app.errors import api_error


def get_ticket_or_404(ticket_id: str, db: Session) -> models.TicketModel:
    ticket = db.query(models.TicketModel).filter(models.TicketModel.id == ticket_id).first()
    if not ticket:
        raise api_error(status.HTTP_404_NOT_FOUND, "ticket_not_found", "Ticket not found")
    return ticket


def get_message_or_404(message_id: str, db: Session) -> models.MessageModel:
    msg = db.query(models.MessageModel).filter(models.MessageModel.id == message_id).first()
    if not msg:
        raise api_error(status.HTTP_404_NOT_FOUND, "message_not_found", "Message not found")
    return msg


@router.post("/api/tickets/{ticket_id}/messages", response_model=schemas.MessageResponse, status_code=status.HTTP_201_CREATED)
async def create_message(ticket_id: str, payload: Optional[schemas.MessageCreate] = None, content: Optional[str] = Form(None), attachments: Optional[List[UploadFile]] = File(None), request: Request = None, db: Session = Depends(get_db), current_user: models.UserModel = Depends(get_current_user)) -> schemas.MessageResponse:
    """Create a message attached to a ticket. Accepts JSON body or multipart/form-data with optional files."""
    client_ip = None

    ticket = get_ticket_or_404(ticket_id, db)

    # Access control
    if not can_access_ticket(ticket, current_user):
        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Access to this ticket is forbidden")

    now = datetime.now(timezone.utc)

    # Support both JSON `payload` and form `content` for backwards compatibility
    body_content = None
    if payload is not None:
        body_content = payload.content

    # If clients POST JSON but payload wasn't auto-parsed (e.g., because File param present),
    # attempt to read JSON manually from request
    if body_content is None and request is not None:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("application/json"):
            try:
                body_json = await request.json()
                body_content = body_json.get("content")
            except Exception:
                # ignore json parsing errors; will validate below
                body_content = None

    if content is not None:
        body_content = content

    if not body_content:
        raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "missing_content", "Missing content")

    msg = models.MessageModel(
        id=str(uuid.uuid4()),
        ticket_id=ticket.id,
        sender_id=current_user.id,
        sender_type=current_user.user_type,
        content=body_content,
        attachments=None,
        created_at=now,
    )

    db.add(msg)

    # Handle attachments (if any)
    # We persist attachments as a list of dicts with metadata: {path, name, type, size}
    attachments_list: list[dict] = []
    if attachments:
        # Enforce maximum attachments count
        if len(attachments) > MAX_ATTACHMENTS:
            raise api_error(status.HTTP_400_BAD_REQUEST, "attachment_too_many", f"Too many attachments: max {MAX_ATTACHMENTS} files allowed")

        # Ensure message directory exists
        msg_dir = os.path.join(UPLOAD_BASE, msg.id)
        os.makedirs(msg_dir, exist_ok=True)
        for upload in attachments:
            # Read file to check size (do this before MIME check to return size error for huge payloads)
            data = await upload.read()
            if len(data) > MAX_UPLOAD_SIZE:
                raise api_error(status.HTTP_400_BAD_REQUEST, "attachment_too_large", f"Attachment too large: {upload.filename}")
            # Validate MIME type
            mimetype = getattr(upload, "content_type", None)
            if not _mime_allowed(mimetype):
                raise api_error(status.HTTP_400_BAD_REQUEST, "attachment_invalid_type", f"Attachment type not allowed: {mimetype or 'unknown'}")
            # Save file
            safe_name = f"{uuid.uuid4().hex}_{os.path.basename(upload.filename)}"
            path = os.path.join(msg_dir, safe_name)
            with open(path, "wb") as f:
                f.write(data)
            # Store relative path and metadata
            rel = os.path.relpath(path, os.getcwd()).replace("\\", "/")
            attachments_list.append({
                "path": rel,
                "name": os.path.basename(upload.filename),
                "type": mimetype,
                "size": len(data),
            })

    # Persist attachments as JSON
    if attachments_list:
        msg.attachments = json.dumps(attachments_list)

    # Auto-assign: if agent responds to a 'new' ticket
    if current_user.user_type == "agent" and ticket.status == "new":
        ticket.assignee_id = current_user.id
        ticket.status = "open"
        ticket.updated_at = now
        if not ticket.workgroup_id and getattr(current_user, "workgroup_id", None):
            ticket.workgroup_id = current_user.workgroup_id

    db.commit()
    db.refresh(msg)
    db.refresh(ticket)

    _log_audit(db, current_user.id, "CREATE", "Message", msg.id, "SUCCESS", client_ip)

    # Convert stored JSON attachments back to list for response and normalize to public URLs
    if msg.attachments:
        try:
            raw_list = json.loads(msg.attachments)
        except Exception:
            raw_list = []

        normalized = []
        from urllib.parse import quote

        for item in raw_list:
            # item may be either a legacy string path or a dict with metadata
            if isinstance(item, str):
                path = item
                name = None
                atype = None
                size = None
            else:
                path = item.get("path")
                name = item.get("name")
                atype = item.get("type")
                size = item.get("size")
            quoted = quote(path, safe="")
            base = str(request.base_url).rstrip("/") if request is not None else ""
            url = f"{base}/api/attachments/messages/{quoted}"
            normalized.append({"path": path, "url": url, "name": name, "type": atype, "size": size})
    else:
        normalized = None

    return schemas.MessageResponse.model_validate(
        {
            "id": msg.id,
            "ticket_id": msg.ticket_id,
            "sender_id": msg.sender_id,
            "sender_type": msg.sender_type,
            "content": msg.content,
            "attachments": normalized,
            "created_at": msg.created_at,
        }
    )

@router.get("/api/tickets/{ticket_id}/messages")
async def list_messages(ticket_id: str, request: Request, page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=500), db: Session = Depends(get_db), current_user: models.UserModel = Depends(get_current_user)) -> dict:
    """List messages for a ticket. Requires access to the ticket."""
    client_ip = request.client.host if request.client else None

    ticket = get_ticket_or_404(ticket_id, db)
    if not can_access_ticket(ticket, current_user):
        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Access to this ticket is forbidden")

    q = db.query(models.MessageModel).filter(models.MessageModel.ticket_id == ticket.id)
    total = q.count()
    offset = (page - 1) * limit
    messages = q.order_by(models.MessageModel.created_at.asc()).offset(offset).limit(limit).all()

    data: List[schemas.MessageResponse] = [schemas.MessageResponse.model_validate(m) for m in messages]

    _log_audit(db, current_user.id, "READ", "Message", None, "SUCCESS", client_ip)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@router.get("/api/messages/{message_id}", response_model=schemas.MessageResponse)
async def get_message(message_id: str, request: Request, db: Session = Depends(get_db), current_user: models.UserModel = Depends(get_current_user)) -> schemas.MessageResponse:
    client_ip = request.client.host if request.client else None

    msg = get_message_or_404(message_id, db)
    ticket = get_ticket_or_404(msg.ticket_id, db)

    if not can_access_ticket(ticket, current_user):
        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Access to this message is forbidden")

    _log_audit(db, current_user.id, "READ", "Message", message_id, "SUCCESS", client_ip)

    return schemas.MessageResponse.model_validate(msg)


@router.delete("/api/messages/{message_id}")
async def delete_message(message_id: str, request: Request, db: Session = Depends(get_db), current_user: models.UserModel = Depends(get_current_user)) -> None:
    client_ip = request.client.host if request.client else None

    msg = get_message_or_404(message_id, db)

    # Only admin or the original sender can delete
    if current_user.user_type != "admin" and msg.sender_id != current_user.id:
        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Not allowed to delete this message")

    db.delete(msg)
    db.commit()

    _log_audit(db, current_user.id, "DELETE", "Message", message_id, "SUCCESS", client_ip)

    return None
