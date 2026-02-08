"""SQLAlchemy models for WorkHub backend.

Models implemented:
- UserModel (consolidated users/agents/contacts)
- BranchModel
- WorkgroupModel
- TicketModel
- MessageModel
- AuditLogModel

Uses SQLAlchemy 2.0 typing (Mapped, mapped_column) and the declarative Base from `app.database`.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum as PyEnum
from typing import List, Optional

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


class UserType(str, PyEnum):
    ADMIN = "admin"
    AGENT = "agent"
    CONTACT = "contact"


class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String(150), unique=True, index=True, nullable=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    user_type: Mapped[str] = mapped_column(String(32), nullable=False)
    phone: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    workgroup_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("workgroups.id"), nullable=True)
    primary_branch_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("branches.id"), nullable=True)
    external_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    workgroup = relationship("WorkgroupModel", back_populates="members", foreign_keys=[workgroup_id])
    primary_branch = relationship("BranchModel", back_populates="contacts", foreign_keys=[primary_branch_id])
    tickets_assigned = relationship("TicketModel", back_populates="assignee", foreign_keys="TicketModel.assignee_id")
    tickets_created = relationship("TicketModel", back_populates="creator", foreign_keys="TicketModel.created_by_id")
    messages = relationship("MessageModel", back_populates="sender")

    def __repr__(self) -> str:  # pragma: no cover - convenience only
        return f"<User id={self.id} email={self.email} type={self.user_type}>"


class BranchModel(Base):
    __tablename__ = "branches"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    branch_code: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    address: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    contacts: Mapped[List[UserModel]] = relationship("UserModel", back_populates="primary_branch", foreign_keys="UserModel.primary_branch_id")
    tickets: Mapped[List["TicketModel"]] = relationship("TicketModel", back_populates="branch", foreign_keys="TicketModel.branch_id")

    def __repr__(self) -> str:
        return f"<Branch id={self.id} code={self.branch_code}>"


class WorkgroupModel(Base):
    __tablename__ = "workgroups"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    members: Mapped[List[UserModel]] = relationship("UserModel", back_populates="workgroup", foreign_keys="UserModel.workgroup_id")
    tickets: Mapped[List["TicketModel"]] = relationship("TicketModel", back_populates="workgroup", foreign_keys="TicketModel.workgroup_id")

    def __repr__(self) -> str:
        return f"<Workgroup id={self.id} name={self.name}>"


class TicketModel(Base):
    __tablename__ = "tickets"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    subject: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    description: Mapped[str] = mapped_column(String(5000), nullable=False)
    priority: Mapped[str] = mapped_column(String(32), default="medium")
    status: Mapped[str] = mapped_column(String(32), default="new")
    resolution: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    branch_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("branches.id"), nullable=True)
    workgroup_id: Mapped[Optional[str]] = mapped_column(String(64), ForeignKey("workgroups.id"), nullable=True)

    assignee_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    contact_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Optimistic locking/version column for concurrent updates
    version: Mapped[int] = mapped_column(Integer, default=0)

    # Relationships
    branch = relationship("BranchModel", back_populates="tickets", foreign_keys=[branch_id])
    workgroup = relationship("WorkgroupModel", back_populates="tickets", foreign_keys=[workgroup_id])
    assignee = relationship("UserModel", back_populates="tickets_assigned", foreign_keys=[assignee_id])
    creator = relationship("UserModel", back_populates="tickets_created", foreign_keys=[created_by_id])
    messages: Mapped[List["MessageModel"]] = relationship("MessageModel", back_populates="ticket", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Ticket id={self.id} subject={self.subject} status={self.status}>"


class MessageModel(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String(64), primary_key=True, index=True)
    ticket_id: Mapped[str] = mapped_column(String(64), ForeignKey("tickets.id"), index=True, nullable=False)
    sender_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id"), nullable=False)
    sender_type: Mapped[str] = mapped_column(String(32), nullable=False)
    content: Mapped[str] = mapped_column(String(5000), nullable=False)
    attachments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    # Relationships
    ticket = relationship("TicketModel", back_populates="messages")
    sender = relationship("UserModel", back_populates="messages")

    def __repr__(self) -> str:
        return f"<Message id={self.id} ticket_id={self.ticket_id} sender_id={self.sender_id}>"


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("users.id"), nullable=True)
    username: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<Audit id={self.id} action={self.action} resource={self.resource}>"


__all__ = [
    "UserType",
    "UserModel",
    "BranchModel",
    "WorkgroupModel",
    "TicketModel",
    "MessageModel",
    "AuditLogModel",
]
