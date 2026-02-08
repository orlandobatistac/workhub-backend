"""Common FastAPI dependency helpers for permissions and DB access.

Provides:
- get_db (re-export of app.database.get_db)
- require_admin
- require_agent_or_admin
- can_access_ticket (boolean check)
- require_ticket_access (raises 403 when access denied)

These helpers follow the rules in /docs/DATABASE_SCHEMA.md and the implementation plan.
"""

from __future__ import annotations

import logging
from typing import Optional

from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app import models
from app.auth import get_current_user, get_optional_user
from app.database import get_db

logger = logging.getLogger(__name__)


# Re-export get_db for convenience
def _get_db() -> Session:
    """Alias to be used as a dependency: `db: Session = Depends(_get_db)`."""
    return get_db()


def require_admin(current_user: models.UserModel = Depends(get_current_user)) -> models.UserModel:
    """Dependency that ensures the current user is an admin.

    Raises HTTP 403 if the user is not an admin.
    """
    if not current_user or current_user.user_type != "admin":
        logger.debug("require_admin: denied for user=%s", getattr(current_user, "id", None))
        from app.errors import api_error

        raise api_error(status.HTTP_403_FORBIDDEN, "admin_required", "Admin access required")
    return current_user


def require_agent_or_admin(current_user: models.UserModel = Depends(get_current_user)) -> models.UserModel:
    """Dependency that ensures the current user is an agent or an admin.

    Raises HTTP 403 if the user is neither.
    """
    if not current_user or current_user.user_type not in ("admin", "agent"):
        logger.debug("require_agent_or_admin: denied for user=%s", getattr(current_user, "id", None))
        from app.errors import api_error

        raise api_error(status.HTTP_403_FORBIDDEN, "agent_or_admin_required", "Agent or admin access required")
    return current_user


def can_access_ticket(ticket: models.TicketModel, current_user: Optional[models.UserModel] = Depends(get_optional_user)) -> bool:
    """Return True if `current_user` can access the given ticket.

    Rules:
    - Admin and agent can access all tickets
    - Contact can only access tickets where ticket.contact_id == current_user.id
    - Anonymous users cannot access tickets
    """
    if not current_user:
        return False

    if current_user.user_type in ("admin", "agent"):
        return True

    if current_user.user_type == "contact":
        return ticket.contact_id == current_user.id

    return False


def require_ticket_access(ticket: models.TicketModel, current_user: Optional[models.UserModel] = Depends(get_optional_user)) -> models.UserModel:
    """Dependency that raises 403 if the current user cannot access the ticket.

    Returns the `current_user` when access is allowed. This is useful in endpoints
    that need both the ticket (loaded earlier) and the authenticated user.
    """
    if not can_access_ticket(ticket, current_user):
        logger.debug("require_ticket_access: denied for ticket=%s user=%s", ticket.id, getattr(current_user, "id", None))
        from app.errors import api_error

        raise api_error(status.HTTP_403_FORBIDDEN, "forbidden", "Access to this ticket is forbidden")
    assert current_user is not None
    return current_user


__all__ = [
    "get_db",
    "require_admin",
    "require_agent_or_admin",
    "can_access_ticket",
    "require_ticket_access",
]
