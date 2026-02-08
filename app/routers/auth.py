"""Authentication API routes: login and current-user endpoint."""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app import models, schemas
from app.auth import ACCESS_TOKEN_EXPIRE_MINUTES, authenticate_user, create_access_token, get_current_user
from app.database import get_db

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


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


@router.post("/login", response_model=schemas.TokenResponse)
async def login(credentials: schemas.LoginRequest, request: Request, db: Session = Depends(get_db)) -> schemas.TokenResponse:
    """Authenticate user with username or email and return a JWT token and user info."""
    client_ip = request.client.host if request.client else None

    user = authenticate_user(db, credentials.username_or_email, credentials.password)
    from app.errors import api_error

    if not user:
        _log_audit(db, None, "LOGIN", "User", credentials.username_or_email, "FAILED", client_ip)
        raise api_error(status.HTTP_401_UNAUTHORIZED, "invalid_credentials", "Invalid credentials")

    if not user.is_active:
        _log_audit(db, user.id, "LOGIN", "User", str(user.id), "FAILED_INACTIVE", client_ip)
        raise api_error(status.HTTP_401_UNAUTHORIZED, "user_inactive", "User inactive")

    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(data={"sub": user.username or user.email}, expires_delta=access_token_expires)

    _log_audit(db, user.id, "LOGIN", "User", str(user.id), "SUCCESS", client_ip)

    return schemas.TokenResponse(
        access_token=access_token,
        token_type="bearer",
        user=schemas.UserResponse.model_validate(user),
    )


@router.get("/me", response_model=schemas.UserResponse)
async def me(current_user: models.UserModel = Depends(get_current_user)) -> schemas.UserResponse:
    """Return current authenticated user."""
    return schemas.UserResponse.model_validate(current_user)
