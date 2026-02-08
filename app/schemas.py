"""Pydantic schemas for WorkHub API.

Includes request/response models and validation logic consistent with
`DATABASE_SCHEMA.md` and the implementation plan.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


class UserType(str, Enum):
    ADMIN = "admin"
    AGENT = "agent"
    CONTACT = "contact"


# ----------------------------- Users ---------------------------------
class UserCreate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    email: EmailStr
    full_name: str
    password: str = Field(..., min_length=8)
    user_type: UserType
    phone: Optional[str] = None
    workgroup_id: Optional[str] = None
    primary_branch_id: Optional[str] = None
    external_id: Optional[str] = None

    @model_validator(mode="after")
    def check_user_requirements(self):
        """Validate inter-field requirements depending on `user_type`."""
        if self.user_type == UserType.AGENT and not self.workgroup_id:
            raise ValueError("workgroup_id is required for agents")
        if self.user_type == UserType.CONTACT and not self.primary_branch_id:
            raise ValueError("primary_branch_id is required for contacts")
        if self.user_type in (UserType.ADMIN, UserType.AGENT) and not self.username:
            raise ValueError("username is required for admin and agent")
        return self


class UserResponse(BaseModel):
    id: int
    username: Optional[str]
    email: EmailStr
    full_name: str
    user_type: UserType
    phone: Optional[str] = None
    is_active: bool
    workgroup_id: Optional[str] = None
    primary_branch_id: Optional[str] = None
    external_id: Optional[str] = None
    created_at: datetime

    # Pydantic v2 compatibility
    model_config = {"from_attributes": True}


# ----------------------------- Auth ----------------------------------
class LoginRequest(BaseModel):
    username_or_email: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


# ----------------------------- Tickets -------------------------------
PRIORITY_VALUES = {"low", "medium", "high", "urgent"}
STATUS_VALUES = {"new", "open", "closed"}


class TicketCreate(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=5000)
    priority: str = Field(default="medium")
    status: str = Field(default="new")
    resolution: Optional[str] = None
    branch_id: Optional[str] = None
    workgroup_id: Optional[str] = None
    assignee_id: Optional[int] = None
    contact_id: Optional[int] = None

    @field_validator("priority")
    def validate_priority(cls, v):
        if v not in PRIORITY_VALUES:
            raise ValueError(f"priority must be one of {sorted(PRIORITY_VALUES)}")
        return v

    @field_validator("status")
    def validate_status(cls, v):
        if v not in STATUS_VALUES:
            raise ValueError(f"status must be one of {sorted(STATUS_VALUES)}")
        return v


class TicketResponse(BaseModel):
    id: str
    subject: str
    description: str
    priority: str
    status: str
    resolution: Optional[str]
    branch_id: Optional[str]
    workgroup_id: Optional[str]
    assignee_id: Optional[int]
    contact_id: Optional[int]
    due_date: Optional[datetime]
    created_by_id: Optional[int]
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


# ----------------------------- Messages ------------------------------
class MessageCreate(BaseModel):
    # Keep for API compatibility when sending JSON payloads (non-multipart).
    ticket_id: str
    content: str = Field(..., min_length=1)
    attachments: Optional[str] = None


class Attachment(BaseModel):
    path: str
    url: str
    name: Optional[str] = None
    type: Optional[str] = None
    size: Optional[int] = None


class MessageResponse(BaseModel):
    id: str
    ticket_id: str
    sender_id: int
    sender_type: UserType
    content: str
    attachments: Optional[list[Attachment]]
    created_at: datetime

    model_config = {"from_attributes": True}


# ----------------------------- Branches -----------------------------
class BranchCreate(BaseModel):
    branch_code: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=255)
    address: Optional[str] = None
    status: Optional[str] = Field(default="active")


class BranchResponse(BaseModel):
    id: str
    branch_code: str
    name: str
    address: Optional[str]
    status: str
    created_at: datetime

    model_config = {"from_attributes": True}


# --------------------------- Workgroups ----------------------------
class WorkgroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class WorkgroupResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    created_at: datetime

    model_config = {"from_attributes": True}


__all__ = [
    "UserType",
    "UserCreate",
    "UserResponse",
    "LoginRequest",
    "TokenResponse",
    "TicketCreate",
    "TicketResponse",
    "MessageCreate",
    "MessageResponse",
    "BranchCreate",
    "BranchResponse",
    "WorkgroupCreate",
    "WorkgroupResponse",
]
