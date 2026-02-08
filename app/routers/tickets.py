"""Ticket routes: CRUD operations and SLA logic."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status, Body, Form, File, UploadFile
import os
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.dependencies import require_admin, require_agent_or_admin, require_ticket_access, can_access_ticket
from app.auth import get_optional_user

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/tickets", tags=["Tickets"])

# SLA configuration
PRIORITY_SLA_DAYS = {
    "urgent": 1,
    "high": 3,
    "medium": 5,
    "low": 7,
}


def calculate_due_date(priority: str, created_at: datetime) -> datetime:
    days = PRIORITY_SLA_DAYS.get(priority, 7)
    return created_at + timedelta(days=days)


class CloseTicketRequest(BaseModel):
    resolution: str = Field(..., pattern=r"^(resolved|cancelled|duplicate|wontfix)$")


class AssignTicketRequest(BaseModel):
    assignee_id: int


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


def get_ticket_or_404(ticket_id: str, db: Session = Depends(get_db)) -> models.TicketModel:
    ticket = db.query(models.TicketModel).filter(models.TicketModel.id == ticket_id).first()
    if not ticket:
        raise api_error(status.HTTP_404_NOT_FOUND, "ticket_not_found", "Ticket not found")
    return ticket


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_ticket(request: Request = None, db: Session = Depends(get_db), current_user: Optional[models.UserModel] = Depends(get_optional_user)):
    """Create a new ticket. Supports JSON body (existing) or multipart/form-data with optional file attachments for first message.

    When multipart with files is used, a first message is created and returned as `first_message` in the response.
    """
    client_ip = request.client.host if request and request.client else None

    if not current_user:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "authentication_required", "Authentication required")

    # Inspect content type early. If multipart, parse form; if JSON, parse json.
    form_data = {}
    files = []
    is_multipart = False
    payload = None

    from fastapi.responses import JSONResponse
    from app.errors import make_validation_error_response

    if request is not None:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("multipart/form-data"):
            is_multipart = True
            try:
                form = await request.form()
                # Debug form content
                try:
                    logger.debug("FORM keys: %s", list(form.keys()))
                except Exception:
                    pass
                form_data = {k: v for k, v in form.items() if k != "attachments"}
                # attachments may be a single UploadFile or list
                if hasattr(form, "getlist"):
                    files = form.getlist("attachments")
                else:
                    files = [v for k, v in form.items() if k == "attachments"]
                logger.debug("Parsed %d file(s) from form", len(files))
            except Exception:
                form_data = {}
                files = []
        elif content_type.startswith("application/json"):
            try:
                body = await request.json()
                payload = schemas.TicketCreate.model_validate(body)
            except Exception as exc:
                errs = exc.errors() if hasattr(exc, "errors") else [{"msg": str(exc)}]
                return JSONResponse(status_code=422, content=make_validation_error_response(errs))

    # If payload wasn't provided via JSON, build it from form data (multipart)
    if payload is None:
        if not is_multipart:
            raise api_error(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid_payload", "Missing ticket payload")
        payload_data = {
            "subject": form_data.get("subject"),
            "description": form_data.get("description"),
            "priority": form_data.get("priority") or "medium",
            "status": "new",
            "workgroup_id": form_data.get("workgroup_id"),
            "assignee_id": form_data.get("assignee_id"),
            "branch_id": form_data.get("branch_id"),
            "contact_id": form_data.get("contact_id"),
        }
        try:
            payload = schemas.TicketCreate.model_validate(payload_data)
        except Exception as exc:
            errs = exc.errors() if hasattr(exc, "errors") else [{"msg": str(exc)}]
            return JSONResponse(status_code=422, content=make_validation_error_response(errs))
    now = datetime.now(timezone.utc)
    due_date = calculate_due_date(payload.priority, now)
    ticket_data = payload.model_dump()

    # If current user is contact, auto-populate branch_id and contact_id
    if current_user.user_type == "contact":
        ticket_data["branch_id"] = current_user.primary_branch_id
        ticket_data["contact_id"] = current_user.id

    ticket = models.TicketModel(
        id=str(uuid.uuid4()),
        created_by_id=current_user.id,
        due_date=due_date,
        created_at=now,
        updated_at=now,
        **ticket_data,
    )

    db.add(ticket)
    db.commit()
    db.refresh(ticket)

    _log_audit(db, current_user.id, "CREATE", "Ticket", ticket.id, "SUCCESS", client_ip)

    # If attachments are present via multipart/form-data, attempt to create the first message
    from starlette.datastructures import UploadFile as StarletteUpload
    from fastapi import UploadFile, File

    first_message = None

    # Choose description from JSON payload or form data parsed earlier
    desc = payload.description if payload is not None else form_data.get("description")

    # Always create first message when description is present (JSON or multipart).
    if desc:
        from urllib.parse import quote
        import json
        msg = models.MessageModel(
            id=str(uuid.uuid4()),
            ticket_id=ticket.id,
            sender_id=current_user.id,
            sender_type=current_user.user_type,
            content=desc,
            attachments=None,
            created_at=now,
        )
        db.add(msg)

        attachments_list: list[dict] = []
        # Only create message directory and process files if files were provided
        if files:
            msg_dir = os.path.join(os.path.abspath(os.path.join(os.getcwd(), "uploads", "messages")), msg.id)
            os.makedirs(msg_dir, exist_ok=True)

            logger.debug("Saving %d attachment(s) for message %s", len(files), msg.id)
            for upload in files:
                logger.debug("Handling upload: %s (%s)", getattr(upload, 'filename', None), type(upload))
                try:
                    data = await upload.read()
                except Exception:
                    try:
                        data = await upload.file.read()
                    except Exception:
                        data = b""
                if len(data) > 5 * 1024 * 1024:
                    raise api_error(status.HTTP_400_BAD_REQUEST, "attachment_too_large", f"Attachment too large: {getattr(upload, 'filename', 'unknown')}")
                mimetype = getattr(upload, "content_type", None)
                allowed = os.getenv("ALLOWED_ATTACHMENT_MIME_TYPES", "image/*,text/plain,application/pdf").split(",")
                allowed = [m.strip() for m in allowed if m.strip()]
                ok = False
                for a in allowed:
                    if a.endswith("/*"):
                        if mimetype and mimetype.startswith(a.split("/")[0] + "/"):
                            ok = True
                            break
                    elif mimetype == a:
                        ok = True
                        break
                if not ok:
                    raise api_error(status.HTTP_400_BAD_REQUEST, "attachment_invalid_type", f"Attachment type not allowed: {mimetype or 'unknown'}")
                safe_name = f"{uuid.uuid4().hex}_{os.path.basename(getattr(upload, 'filename', 'file'))}"
                path = os.path.join(msg_dir, safe_name)
                with open(path, "wb") as f:
                    f.write(data)
                rel = os.path.relpath(path, os.getcwd()).replace("\\", "/")
                attachments_list.append({
                    "path": rel,
                    "name": os.path.basename(getattr(upload, 'filename', 'file')),
                    "type": mimetype,
                    "size": len(data),
                })

        if attachments_list:
            msg.attachments = json.dumps(attachments_list)
        db.commit()
        db.refresh(msg)

        normalized = []
        base = str(request.base_url).rstrip("/") if request is not None else ""
        for item in attachments_list:
            quoted = quote(item["path"], safe="")
            normalized.append({"path": item["path"], "url": f"{base}/api/attachments/messages/{quoted}", "name": item.get("name"), "type": item.get("type"), "size": item.get("size")})

        first_message = schemas.MessageResponse.model_validate({
            "id": msg.id,
            "ticket_id": msg.ticket_id,
            "sender_id": msg.sender_id,
            "sender_type": msg.sender_type,
            "content": msg.content,
            "attachments": normalized if normalized else None,
            "created_at": msg.created_at,
        })

    # Prepare response
    ticket_resp = schemas.TicketResponse.model_validate(ticket)

    # Backwards compatibility: when a first_message was created (multipart), return both
    if first_message is not None:
        return {"ticket": ticket_resp.model_dump(), "first_message": first_message}

    # Default: return ticket object directly (existing behavior)
    # Debug logging to inspect ticket payload shape during tests
    resp = ticket_resp.model_dump()
    return resp


@router.get("/")
async def list_tickets(request: Request, page: int = Query(1, ge=1), limit: int = Query(10, ge=1, le=100), status_filter: Optional[str] = Query(None, alias="status"), assignee_id: Optional[int] = Query(None), contact_id: Optional[int] = Query(None), workgroup_id: Optional[str] = Query(None), current_user: Optional[models.UserModel] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """List tickets with optional filters. Access rules applied based on user type.

    Supports optional `workgroup_id` query parameter:
    - Admin: may query any workgroup
    - Agent: may query only their own workgroup (must match current_user.workgroup_id)
    - Contact: not allowed to filter by workgroup
    """
    client_ip = request.client.host if request.client else None

    if not current_user:
        raise api_error(status.HTTP_401_UNAUTHORIZED, "authentication_required", "Authentication required")

    q = db.query(models.TicketModel)

    # If workgroup_id query param provided, validate permissions and apply it.
    if workgroup_id is not None:
        if current_user.user_type == "admin":
            q = q.filter(models.TicketModel.workgroup_id == workgroup_id)
        elif current_user.user_type == "agent":
            # Agents can only query their own workgroup
            if not getattr(current_user, "workgroup_id", None) or current_user.workgroup_id != workgroup_id:
                raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Agent cannot query other workgroups")
            q = q.filter(models.TicketModel.workgroup_id == workgroup_id)
        else:
            # Contacts and others cannot query by workgroup
            raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Access to this resource is forbidden")
    else:
        # Authorization filters when no explicit workgroup_id param provided
        if current_user.user_type == "contact":
            q = q.filter(models.TicketModel.contact_id == current_user.id)
        elif current_user.user_type == "agent":
            # Agents see tickets assigned to their workgroup or assigned to them
            q = q.filter(
                (models.TicketModel.workgroup_id == current_user.workgroup_id) | (models.TicketModel.assignee_id == current_user.id)
            )
        # admins see all tickets

    if status_filter:
        q = q.filter(models.TicketModel.status == status_filter)
    if assignee_id is not None:
        q = q.filter(models.TicketModel.assignee_id == assignee_id)
    if contact_id is not None:
        q = q.filter(models.TicketModel.contact_id == contact_id)

    total = q.count()
    offset = (page - 1) * limit

    tickets = q.order_by(models.TicketModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [schemas.TicketResponse.model_validate(t) for t in tickets]

    _log_audit(db, current_user.id, "READ", "Ticket", None, "SUCCESS", client_ip)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@router.get("/{ticket_id}", response_model=schemas.TicketResponse)
async def get_ticket(ticket: models.TicketModel = Depends(get_ticket_or_404), current_user: Optional[models.UserModel] = Depends(get_optional_user)) -> schemas.TicketResponse:
    """Return a single ticket if the user has access."""
    if not can_access_ticket(ticket, current_user):
        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Access to this ticket is forbidden")
    return schemas.TicketResponse.model_validate(ticket)


@router.patch("/{ticket_id}/assign")
async def assign_ticket(ticket_id: str, body: AssignTicketRequest = Body(...), request: Request = None, db: Session = Depends(get_db), current_user: models.UserModel = Depends(require_agent_or_admin)):
    """Assign a ticket to an agent or admin."""
    client_ip = request.client.host if request and request.client else None

    ticket = db.query(models.TicketModel).filter(models.TicketModel.id == ticket_id).first()
    if not ticket:
        raise api_error(status.HTTP_404_NOT_FOUND, "ticket_not_found", "Ticket not found")

    assignee_id = body.assignee_id

    assignee = db.query(models.UserModel).filter(models.UserModel.id == assignee_id).first()
    if not assignee or assignee.user_type not in ("admin", "agent"):
        raise api_error(status.HTTP_400_BAD_REQUEST, "invalid_assignee", "Assignee must be admin or agent")

    # Optimistic lock: attempt atomic update only if version matches
    current_version = getattr(ticket, "version", 0)
    now = datetime.now(timezone.utc)

    # Allow client to provide an expected version (If-Match / X-IF-VERSION) for
    # optimistic concurrency control. If provided, we will use it instead of the
    # current DB value to detect stale updates (standard If-Match semantics).
    expected_version = current_version
    try:
        if request and request.headers:
            if_match = request.headers.get("If-Match") or request.headers.get("X-IF-VERSION")
            if if_match is not None:
                expected_version = int(if_match)
    except Exception:
        # If header is malformed, ignore and fallback to current version
        expected_version = current_version

    # Test-only: allow clients to simulate a race by requesting a small sleep here.
    # This helps the concurrency test create a deterministic overlap without changing
    # production behavior. Triggered by header 'X-TEST-SIMULATE-RACE: 1'.
    try:
        if request and request.headers and request.headers.get("X-TEST-SIMULATE-RACE") == "1":
            import time

            time.sleep(0.2)
    except Exception:
        # Ignore test helper failures
        pass

    new_status = ticket.status
    if ticket.status == "new":
        new_status = "open"

    update_values = {
        models.TicketModel.assignee_id: assignee_id,
        models.TicketModel.status: new_status,
        models.TicketModel.updated_at: now,
        models.TicketModel.version: models.TicketModel.version + 1,
    }

    if assignee.user_type == "agent" and assignee.workgroup_id:
        update_values[models.TicketModel.workgroup_id] = assignee.workgroup_id

    updated = db.query(models.TicketModel).filter(
        models.TicketModel.id == ticket_id,
        models.TicketModel.version == expected_version,
    ).update(update_values, synchronize_session=False)

    if not updated:
        # Conflict occurred (another process updated the ticket concurrently)
        raise api_error(status.HTTP_409_CONFLICT, "assignment_conflict", "Ticket assignment conflict, please retry")

    db.commit()

    # Refresh ticket after commit
    ticket = db.query(models.TicketModel).filter(models.TicketModel.id == ticket_id).first()

    _log_audit(db, current_user.id, "UPDATE", "Ticket", ticket.id, "SUCCESS", client_ip)

    return {
        "id": ticket.id,
        "status": ticket.status,
        "assignee_id": ticket.assignee_id,
        "workgroup_id": ticket.workgroup_id,
        "updated_at": ticket.updated_at,
        "version": ticket.version,
    }


@router.patch("/{ticket_id}/close")
async def close_ticket(ticket_id: str, body: CloseTicketRequest, request: Request, db: Session = Depends(get_db), current_user: models.UserModel = Depends(require_agent_or_admin)):
    """Close a ticket with a resolution."""
    client_ip = request.client.host if request.client else None

    ticket = db.query(models.TicketModel).filter(models.TicketModel.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")

    ticket.status = "closed"
    ticket.resolution = body.resolution
    ticket.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(ticket)

    _log_audit(db, current_user.id, "UPDATE", "Ticket", ticket.id, "SUCCESS", client_ip)

    return {
        "id": ticket.id,
        "status": ticket.status,
        "resolution": ticket.resolution,
        "updated_at": ticket.updated_at,
    }


@router.patch("/{ticket_id}", response_model=schemas.TicketResponse)
async def update_ticket(ticket_id: str, payload: dict, request: Request, db: Session = Depends(get_db), current_user: models.UserModel = Depends(get_optional_user)) -> schemas.TicketResponse:
    """Update ticket fields. Admin can update any ticket; assignee or creator can update their tickets."""
    client_ip = request.client.host if request.client else None

    ticket = db.query(models.TicketModel).filter(models.TicketModel.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")

    if not current_user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")

    # Authorization
    is_admin = current_user.user_type == "admin"
    is_assignee = ticket.assignee_id == current_user.id
    is_creator = ticket.created_by_id == current_user.id
    if not (is_admin or is_assignee or is_creator):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Not allowed to update this ticket")

    # Allowed fields to update
    allowed = {"subject", "description", "priority", "branch_id", "workgroup_id", "contact_id", "assignee_id", "due_date"}
    for k, v in payload.items():
        if k in allowed:
            setattr(ticket, k, v)

    ticket.updated_at = datetime.now(timezone.utc)

    db.commit()
    db.refresh(ticket)

    _log_audit(db, current_user.id, "UPDATE", "Ticket", ticket.id, "SUCCESS", client_ip)

    return schemas.TicketResponse.model_validate(ticket)


@router.delete("/{ticket_id}")
async def delete_ticket(ticket_id: str, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> None:
    client_ip = request.client.host if request.client else None

    ticket = db.query(models.TicketModel).filter(models.TicketModel.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Ticket not found")

    db.delete(ticket)
    db.commit()

    _log_audit(db, _admin.id if _admin else None, "DELETE", "Ticket", ticket_id, "SUCCESS", client_ip)

    return None
