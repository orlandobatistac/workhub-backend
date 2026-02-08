"""Authentication helpers: JWT, password hashing and user retrieval dependencies."""

from __future__ import annotations

import logging
import os
import warnings
from datetime import datetime, timedelta, timezone
from typing import Optional

# Suppress third-party deprecation warnings raised during password hashing
# Suppress specific deprecation warnings that come from third-party libs we depend on.
# See `docs/WARNING_SUPPRESSION.md` for details, rationale, upstream links, and when to remove these.
warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*argon2.*")
warnings.filterwarnings("ignore", category=DeprecationWarning, message=r".*datetime\.datetime\.utcnow.*")

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.database import get_db
from app import models

logger = logging.getLogger(__name__)

# Config from environment with sensible defaults for dev
SECRET_KEY = os.getenv("JWT_SECRET", "change-this-secret-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60"))

pwd_context = CryptContext(schemes=["argon2", "bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode.update({"exp": expire, "iat": now})
    token = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return token


def _get_user_by_sub(db: Session, sub: str) -> Optional[models.UserModel]:
    # Prefer username if it matches, otherwise try email
    user = db.query(models.UserModel).filter(models.UserModel.username == sub).first()
    if user:
        return user
    return db.query(models.UserModel).filter(models.UserModel.email == sub).first()


def authenticate_user(db: Session, username_or_email: str, password: str) -> Optional[models.UserModel]:
    user = db.query(models.UserModel).filter(
        (models.UserModel.username == username_or_email) | (models.UserModel.email == username_or_email)
    ).first()
    if not user:
        return None
    if not verify_password(password, user.hashed_password):
        return None
    return user


def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.UserModel:
    """Dependency that returns the authenticated user or raises 401."""
    from app.errors import api_error

    credentials_exception = api_error(
        status.HTTP_401_UNAUTHORIZED,
        "invalid_credentials",
        "Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub: Optional[str] = payload.get("sub")
        if not sub:
            raise credentials_exception
    except JWTError as exc:
        logger.debug("JWT decode error: %s", exc)
        raise credentials_exception

    user = _get_user_by_sub(db, sub)
    if not user:
        raise credentials_exception
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    return user


def get_optional_user(request: Request, db: Session = Depends(get_db)) -> Optional[models.UserModel]:
    """Return the authenticated user if a valid Bearer token is present, otherwise None.

    This function purposely does not raise on missing/invalid token so it can be used
    in endpoints that accept both authenticated and anonymous access.
    """
    auth: Optional[str] = request.headers.get("Authorization")
    if not auth:
        return None

    parts = auth.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None

    token = parts[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        sub: Optional[str] = payload.get("sub")
        if not sub:
            return None
        user = _get_user_by_sub(db, sub)
        if not user or not user.is_active:
            return None
        return user
    except JWTError:
        logger.debug("Invalid bearer token provided to get_optional_user")
        return None


__all__ = [
    "verify_password",
    "get_password_hash",
    "create_access_token",
    "authenticate_user",
    "get_current_user",
    "get_optional_user",
    "oauth2_scheme",
]
