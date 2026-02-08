"""Branch management routes (CRUD)."""

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

router = APIRouter(prefix="/api/branches", tags=["Branches"])


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


def get_branch_or_404(branch_id: str, db: Session) -> models.BranchModel:
    branch = db.query(models.BranchModel).filter(models.BranchModel.id == branch_id).first()
    if not branch:
        raise api_error(status.HTTP_404_NOT_FOUND, "branch_not_found", "Branch not found")
    return branch


@router.post("/", response_model=schemas.BranchResponse, status_code=status.HTTP_201_CREATED)
async def create_branch(payload: schemas.BranchCreate, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> schemas.BranchResponse:
    """Create a branch (admin only)."""
    client_ip = request.client.host if request.client else None

    # unique branch_code
    existing = db.query(models.BranchModel).filter(models.BranchModel.branch_code == payload.branch_code).first()
    if existing:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="branch_code already exists")

    now = datetime.now(timezone.utc)
    branch = models.BranchModel(
        id=str(uuid.uuid4()),
        branch_code=payload.branch_code,
        name=payload.name,
        address=payload.address,
        status=payload.status or "active",
        created_at=now,
    )

    db.add(branch)
    db.commit()
    db.refresh(branch)

    _log_audit(db, _admin.id if _admin else None, "CREATE", "Branch", branch.id, "SUCCESS", client_ip)

    return schemas.BranchResponse.model_validate(branch)


@router.get("/")
async def list_branches(request: Request, page: int = Query(1, ge=1), limit: int = Query(10, ge=1, le=100), status: Optional[str] = Query(None), db: Session = Depends(get_db), current_user: models.UserModel = Depends(require_agent_or_admin)) -> dict:
    """List branches (admin/agent)."""
    client_ip = request.client.host if request.client else None

    q = db.query(models.BranchModel)
    if status:
        q = q.filter(models.BranchModel.status == status)

    total = q.count()
    offset = (page - 1) * limit
    branches = q.order_by(models.BranchModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [schemas.BranchResponse.model_validate(b) for b in branches]

    _log_audit(db, current_user.id if current_user else None, "READ", "Branch", None, "SUCCESS", client_ip)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@router.get("/{branch_id}", response_model=schemas.BranchResponse)
async def get_branch(branch_id: str, db: Session = Depends(get_db), current_user: models.UserModel = Depends(require_agent_or_admin)) -> schemas.BranchResponse:
    branch = get_branch_or_404(branch_id, db)
    return schemas.BranchResponse.model_validate(branch)


@router.patch("/{branch_id}", response_model=schemas.BranchResponse)
async def update_branch(branch_id: str, payload: dict, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> schemas.BranchResponse:
    """Update branch (admin only)."""
    client_ip = request.client.host if request.client else None

    branch = get_branch_or_404(branch_id, db)

    allowed = {"branch_code", "name", "address", "status"}
    if "branch_code" in payload and payload["branch_code"] != branch.branch_code:
        # ensure unique
        existing = db.query(models.BranchModel).filter(models.BranchModel.branch_code == payload["branch_code"]).first()
        if existing:
            raise api_error(status.HTTP_400_BAD_REQUEST, "branch_code_exists", "branch_code already exists")

    for k, v in payload.items():
        if k in allowed:
            setattr(branch, k, v)

    db.commit()
    db.refresh(branch)

    _log_audit(db, _admin.id if _admin else None, "UPDATE", "Branch", branch.id, "SUCCESS", client_ip)

    return schemas.BranchResponse.model_validate(branch)


@router.delete("/{branch_id}")
async def delete_branch(branch_id: str, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> None:
    client_ip = request.client.host if request.client else None

    branch = get_branch_or_404(branch_id, db)

    db.delete(branch)
    db.commit()

    _log_audit(db, _admin.id if _admin else None, "DELETE", "Branch", branch_id, "SUCCESS", client_ip)

    return None
