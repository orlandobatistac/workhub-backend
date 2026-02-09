"""User management routes: create, read, update, delete and list users.

Endpoints implemented:
- POST /api/users           (admin only)
- GET  /api/users/{id}      (admin/agent or the user themself)
- PATCH /api/users/{id}     (admin or the user themself)
- DELETE /api/users/{id}    (admin only)
- GET /api/users/team       (list admins+agents)
- GET /api/users/customers  (list contacts/customers)
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import get_password_hash, get_current_user
from app.database import get_db
from app.dependencies import require_admin, require_agent_or_admin, get_db as dependency_get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/users", tags=["Users"])


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


def get_user_or_404(db: Session, user_id: int) -> models.UserModel:
    user = db.query(models.UserModel).filter(models.UserModel.id == user_id).first()
    if not user:
        raise api_error(status.HTTP_404_NOT_FOUND, "user_not_found", "User not found")
    return user


@router.post("/", response_model=schemas.UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(user_in: schemas.UserCreate, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> schemas.UserResponse:
    """Create a new user (admin only)."""
    client_ip = request.client.host if request.client else None

    # Validate unique email
    existing = db.query(models.UserModel).filter(models.UserModel.email == user_in.email).first()
    if existing:
        raise api_error(status.HTTP_400_BAD_REQUEST, "email_in_use", "Email already in use")

    # If username provided, ensure uniqueness
    if user_in.username:
        existing = db.query(models.UserModel).filter(models.UserModel.username == user_in.username).first()
        if existing:
            raise api_error(status.HTTP_400_BAD_REQUEST, "username_in_use", "Username already in use")

    hashed = get_password_hash(user_in.password)

    db_user = models.UserModel(
        username=user_in.username,
        email=user_in.email,
        full_name=user_in.full_name,
        hashed_password=hashed,
        user_type=user_in.user_type.value if hasattr(user_in.user_type, "value") else str(user_in.user_type),
        phone=user_in.phone,
        is_active=True,
        workgroup_id=user_in.workgroup_id,
        primary_branch_id=user_in.primary_branch_id,
        external_id=user_in.external_id,
    )

    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    _log_audit(db, _admin.id if _admin else None, "CREATE", "User", str(db_user.id), "SUCCESS", client_ip)

    return schemas.UserResponse.model_validate(db_user)


@router.get("/team")
async def list_team_members(request: Request, page: int = Query(1, ge=1), limit: int = Query(10, ge=1, le=100), current_user: models.UserModel = Depends(require_agent_or_admin), db: Session = Depends(get_db)):
    """List admin and agent users."""
    client_ip = request.client.host if request.client else None

    offset = (page - 1) * limit
    total = db.query(models.UserModel).filter(models.UserModel.user_type.in_([models.UserType.ADMIN.value, models.UserType.AGENT.value])).count()

    users = db.query(models.UserModel).filter(models.UserModel.user_type.in_([models.UserType.ADMIN.value, models.UserType.AGENT.value])).order_by(models.UserModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [schemas.UserResponse.model_validate(u) for u in users]

    _log_audit(db, current_user.id if current_user else None, "READ", "User", None, "SUCCESS", client_ip)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@router.get("/customers")
async def list_customers(request: Request, page: int = Query(1, ge=1), limit: int = Query(10, ge=1, le=100), current_user: models.UserModel = Depends(require_agent_or_admin), db: Session = Depends(get_db)):
    """List contacts (customers)."""
    client_ip = request.client.host if request.client else None

    offset = (page - 1) * limit
    total = db.query(models.UserModel).filter(models.UserModel.user_type == models.UserType.CONTACT.value).count()

    users = db.query(models.UserModel).filter(models.UserModel.user_type == models.UserType.CONTACT.value).order_by(models.UserModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [schemas.UserResponse.model_validate(u) for u in users]

    _log_audit(db, current_user.id if current_user else None, "READ", "User", None, "SUCCESS", client_ip)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@router.get("/")
async def list_all_users(request: Request, page: int = Query(1, ge=1), limit: int = Query(10, ge=1, le=100), current_user: models.UserModel = Depends(require_admin), db: Session = Depends(get_db)) -> dict:
    """List all users (admin only)."""
    client_ip = request.client.host if request.client else None

    offset = (page - 1) * limit
    total = db.query(models.UserModel).count()

    users = db.query(models.UserModel).order_by(models.UserModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [schemas.UserResponse.model_validate(u) for u in users]

    _log_audit(db, current_user.id if current_user else None, "READ", "User", None, "SUCCESS", client_ip)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@router.get("/{user_id}", response_model=schemas.UserResponse)
async def get_user(user_id: int, current_user: models.UserModel = Depends(get_current_user), db: Session = Depends(get_db)) -> schemas.UserResponse:  # type: ignore
    """Get a single user by id. Admin/agent can read any user; others only themselves."""
    user = get_user_or_404(db, user_id)

    # Authorization: admins and agents can read any user; others only themselves
    if current_user.user_type in (models.UserType.ADMIN.value, models.UserType.AGENT.value) or current_user.id == user_id:
        return schemas.UserResponse.model_validate(user)
    raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Access to this user is forbidden")


@router.patch("/{user_id}", response_model=schemas.UserResponse)
async def update_user(user_id: int, payload: dict, request: Request, db: Session = Depends(get_db), current_user: models.UserModel = Depends(get_current_user)) -> schemas.UserResponse:  # type: ignore
    """Update user. Admins can update any user; users can update themselves. Only admins can change `user_type` and `is_active`."""
    client_ip = request.client.host if request.client else None

    user = get_user_or_404(db, user_id)

    is_admin = current_user.user_type == models.UserType.ADMIN.value
    is_self = current_user.id == user_id

    if not (is_admin or is_self):
        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Not allowed to update this user")

    # Disallow non-admins from changing user_type or is_active
    if not is_admin and ("user_type" in payload or "is_active" in payload):
        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Only admins can change user_type or is_active")

    # Validate email uniqueness if provided
    if "email" in payload and payload["email"] != user.email:
        existing = db.query(models.UserModel).filter(models.UserModel.email == payload["email"]).first()
        if existing:
            raise api_error(status.HTTP_400_BAD_REQUEST, "email_in_use", "Email already in use")

    # Apply updates
    allowed = {"username", "email", "full_name", "phone", "user_type", "is_active", "workgroup_id", "primary_branch_id", "external_id", "password"}
    for k, v in list(payload.items()):
        if k not in allowed:
            continue
        if k == "password":
            user.hashed_password = get_password_hash(v)
        elif k == "user_type":
            user.user_type = v
        else:
            setattr(user, k, v)

    user.updated_at = getattr(user, "updated_at", None) or None

    db.commit()
    db.refresh(user)

    _log_audit(db, current_user.id if current_user else None, "UPDATE", "User", str(user.id), "SUCCESS", client_ip)

    return schemas.UserResponse.model_validate(user)

@router.delete("/{user_id}")
async def delete_user(user_id: int, request: Request, db: Session = Depends(get_db), _admin: models.UserModel = Depends(require_admin)) -> None:
    """Delete a user (admin only)."""
    client_ip = request.client.host if request.client else None
    user = get_user_or_404(db, user_id)

    db.delete(user)
    db.commit()

    _log_audit(db, _admin.id if _admin else None, "DELETE", "User", str(user_id), "SUCCESS", client_ip)

    return None
