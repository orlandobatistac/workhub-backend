"""Seed utilities for creating demo data.

Contains `seed_database` function that can be reused by routers or scripts.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request
from sqlalchemy.orm import Session

from app import models
from app.auth import get_password_hash


def seed_database(db: Session, current_user: Optional[models.UserModel] = None, request: Optional[Request] = None) -> dict:
    """Create demo data if tables are empty. Returns a dict describing counts created.

    This function is idempotent: it only creates records when the corresponding
    tables are empty.
    """
    created = {
        "users": 0,
        "branches": 0,
        "workgroups": 0,
        "agents": 0,
        "contacts": 0,
        "tickets": 0,
        "messages": 0,
    }

    # Users
    if db.query(models.UserModel).count() == 0:
        users = [
            models.UserModel(
                username="admin",
                email="admin@workhub.local",
                full_name="System Administrator",
                hashed_password=get_password_hash("admin123"),
                user_type="admin",
                is_active=True,
            ),
            models.UserModel(
                username="agent1",
                email="agent1@workhub.local",
                full_name="Agent Smith",
                hashed_password=get_password_hash("agent123"),
                user_type="agent",
                is_active=True,
            ),
            models.UserModel(
                username="agent2",
                email="agent2@workhub.local",
                full_name="Agent Johnson",
                hashed_password=get_password_hash("agent123"),
                user_type="agent",
                is_active=True,
            ),
            models.UserModel(
                username="user1",
                email="user1@workhub.local",
                full_name="John User",
                hashed_password=get_password_hash("user123"),
                user_type="contact",
                is_active=True,
            ),
            models.UserModel(
                username="user2",
                email="user2@workhub.local",
                full_name="Jane User",
                hashed_password=get_password_hash("user123"),
                user_type="contact",
                is_active=True,
            ),
        ]
        db.add_all(users)
        db.flush()
        created["users"] = len(users)

    # Branches
    if db.query(models.BranchModel).count() == 0:
        branches = []
        for idx in range(1, 6):
            branches.append(
                models.BranchModel(
                    id=str(uuid.uuid4()),
                    branch_code=f"BR-{idx:03d}",
                    name=f"Branch {idx}",
                    address=f"Address {idx}",
                    status="active",
                )
            )
        db.add_all(branches)
        created["branches"] = len(branches)

    # Workgroups
    if db.query(models.WorkgroupModel).count() == 0:
        workgroups = []
        for idx in range(1, 6):
            workgroups.append(
                models.WorkgroupModel(
                    id=str(uuid.uuid4()),
                    name=f"Workgroup {idx}",
                    description=f"Demo workgroup {idx}",
                )
            )
        db.add_all(workgroups)
        created["workgroups"] = len(workgroups)

    # Persist preliminary objects so tickets can reference them
    db.flush()

    # Tickets
    if db.query(models.TicketModel).count() == 0:
        branches = db.query(models.BranchModel).all()
        contacts = db.query(models.UserModel).filter(models.UserModel.user_type == "contact").all()
        agents = db.query(models.UserModel).filter(models.UserModel.user_type == "agent").all()

        statuses = ["new", "open", "closed"]
        resolutions = ["resolved", "cancelled", "duplicate", "wontfix"]
        priorities = ["low", "medium", "high", "urgent"]

        tickets = []
        for idx in range(1, 61):
            branch = branches[(idx - 1) % len(branches)] if branches else None
            contact = contacts[(idx - 1) % len(contacts)] if contacts else None
            agent = agents[(idx - 1) % len(agents)] if agents and idx % 3 != 0 else None

            status = statuses[idx % 3]
            resolution = None
            if status == "closed":
                resolution = resolutions[(idx // 3) % 4]

            due_date = None
            if idx % 2 == 0:
                days_delta = (idx % 20) - 10
                due_date = datetime.now(timezone.utc) + timedelta(days=days_delta)

            tickets.append(
                models.TicketModel(
                    id=str(uuid.uuid4()),
                    subject=f"Issue #{idx}",
                    description=f"This is ticket #{idx}.",
                    priority=priorities[idx % 4],
                    status=status,
                    resolution=resolution,
                    branch_id=branch.id if branch else None,
                    assignee_id=agent.id if agent else None,
                    contact_id=contact.id if contact else None,
                    due_date=due_date,
                    created_by_id=None,
                )
            )
        db.add_all(tickets)
        created["tickets"] = len(tickets)

    # Messages
    if db.query(models.MessageModel).count() == 0:
        db.flush()
        messages = []
        tickets = db.query(models.TicketModel).all()
        for ticket in tickets:
            ticket_status = str(ticket.status) if ticket.status else "open"
            ticket_resolution = str(ticket.resolution) if ticket.resolution else None

            if ticket_status == "closed" and ticket_resolution:
                resolution_messages = {
                    "resolved": "Issue resolved successfully.",
                    "cancelled": "Ticket cancelled by request.",
                    "duplicate": "Ticket closed as duplicate.",
                    "wontfix": "Ticket closed as won't fix.",
                }
                message_content = resolution_messages.get(ticket_resolution, "Ticket closed.")
            else:
                status_messages = {
                    "new": "Ticket created and awaiting assignment.",
                    "open": "Ticket assigned to agent. Work in progress.",
                    "closed": "Ticket closed.",
                }
                message_content = status_messages.get(ticket_status, "Ticket created.")

            messages.append(
                models.MessageModel(
                    id=str(uuid.uuid4()),
                    ticket_id=ticket.id,
                    sender_type="system",
                    sender_id=0,
                    content=message_content,
                )
            )
        if messages:
            db.add_all(messages)
        created["messages"] = len(messages)

    db.commit()

    # Simple audit: write an audit record if AuditLogModel exists
    try:
        audit = models.AuditLogModel(
            user_id=None,
            username=None,
            action="CREATE",
            resource="Seed",
            resource_id=None,
            details="Seed data created",
            status="SUCCESS",
            ip_address=request.client.host if (request and request.client) else None,
        )
        db.add(audit)
        db.commit()
    except Exception:
        # non-critical
        pass

    return {"message": "Seed completed", "data": created}
