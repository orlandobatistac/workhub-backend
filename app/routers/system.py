"""System routes: seed data and health operations for app package.

This router provides the development-friendly `/api/seed` endpoint using the
shared `app.seed.seed_database` function. It is the modern, package-scoped
implementation intended for development and testing. The top-level
`main.py` file contains a legacy, production-mounted `/api/seed` which must
remain unchanged unless a migration plan is in place.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.database import get_db
from app.auth import get_password_hash, get_optional_user
from app import models

router = APIRouter(prefix="/api", tags=["System"])


from app.seed import seed_database


@router.post("/seed")
async def seed_data(request: Request, current_user: Optional[models.UserModel] = Depends(get_optional_user), db: Session = Depends(get_db)):
    """Seed demo data for frontend development (idempotent).

    This endpoint is intended for development and test environments only.
    It is safe to call multiple times: it will only create objects when
    corresponding tables are empty.
    """
    return seed_database(db=db, current_user=current_user, request=request)
