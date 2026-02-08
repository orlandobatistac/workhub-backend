"""Workgroup management routes (CRUD)."""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.database import get_db
from app.dependencies import require_admin, require_agent_or_admin

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/workgroups", tags=["Workgroups"])


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


def get_workgroup_or_404(workgroup_id: str, db: Session) -> models.WorkgroupModel:
    wg = db.query(models.WorkgroupModel).filter(models.WorkgroupModel.id == workgroup_id).first()
    if not wg:
        raise api_error(status.HTTP_404_NOT_FOUND, "workgroup_not_found", "Workgroup not found")
    return wg


@router.post("/", response_model=schemas.WorkgroupResponse, status_code=status.HTTP_201_CREATED)
async def create_workgroup(payload: schemas.WorkgroupCreate, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> schemas.WorkgroupResponse:
    """Create a workgroup (admin only)."""
    client_ip = request.client.host if request.client else None

    now = datetime.now(timezone.utc)
    wg = models.WorkgroupModel(
        id=str(uuid.uuid4()),
        name=payload.name,
        description=payload.description,
        created_at=now,
    )

    db.add(wg)
    db.commit()
    db.refresh(wg)

    _log_audit(db, _admin.id if _admin else None, "CREATE", "Workgroup", wg.id, "SUCCESS", client_ip)

    return schemas.WorkgroupResponse.model_validate(wg)


@router.get("/")
async def list_workgroups(request: Request, page: int = Query(1, ge=1), limit: int = Query(10, ge=1, le=100), name: Optional[str] = Query(None), db: Session = Depends(get_db), current_user: models.UserModel = Depends(require_agent_or_admin)) -> dict:
    """List workgroups (admin/agent)."""
    client_ip = request.client.host if request.client else None

    q = db.query(models.WorkgroupModel)
    if name:
        q = q.filter(models.WorkgroupModel.name.ilike(f"%{name}%"))

    total = q.count()
    offset = (page - 1) * limit
    wgs = q.order_by(models.WorkgroupModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [schemas.WorkgroupResponse.model_validate(w) for w in wgs]

    _log_audit(db, current_user.id if current_user else None, "READ", "Workgroup", None, "SUCCESS", client_ip)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@router.get("/{workgroup_id}", response_model=schemas.WorkgroupResponse)
async def get_workgroup(workgroup_id: str, db: Session = Depends(get_db), current_user: models.UserModel = Depends(require_agent_or_admin)) -> schemas.WorkgroupResponse:
    wg = get_workgroup_or_404(workgroup_id, db)
    return schemas.WorkgroupResponse.model_validate(wg)


@router.patch("/{workgroup_id}", response_model=schemas.WorkgroupResponse)
async def update_workgroup(workgroup_id: str, payload: dict, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> schemas.WorkgroupResponse:
    """Update workgroup (admin only)."""
    client_ip = request.client.host if request.client else None

    wg = get_workgroup_or_404(workgroup_id, db)

    allowed = {"name", "description"}
    for k, v in payload.items():
        if k in allowed:
            setattr(wg, k, v)

    db.commit()
    db.refresh(wg)

    _log_audit(db, _admin.id if _admin else None, "UPDATE", "Workgroup", wg.id, "SUCCESS", client_ip)

    return schemas.WorkgroupResponse.model_validate(wg)


@router.delete("/{workgroup_id}")
async def delete_workgroup(workgroup_id: str, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> None:
    client_ip = request.client.host if request.client else None

    wg = get_workgroup_or_404(workgroup_id, db)

    db.delete(wg)
    db.commit()

    _log_audit(db, _admin.id if _admin else None, "DELETE", "Workgroup", workgroup_id, "SUCCESS", client_ip)

    return None
