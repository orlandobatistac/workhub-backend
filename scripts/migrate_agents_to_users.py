"""migrate_agents_to_users.py

Idempotent migration helper that:
- Ensures necessary columns exist in `users`, `tickets`, and `contacts` (uses ALTER TABLE ADD COLUMN when needed)
- Creates `users` for rows in `agents` when no matching user exists
- Maps tickets.assignee_agent_id -> tickets.assignee_user_id (resolving by agent.agent_id or agent.id)
- Optionally links contacts.email -> users.id by email

Usage:
  python scripts/migrate_agents_to_users.py --db ./workhub.db         # dry run (default)
  python scripts/migrate_agents_to_users.py --db ./workhub.db --apply # apply changes

This script is safe to run multiple times. It will report collisions and a summary.

IMPORTANT: Backup your DB before running with --apply.
"""

from __future__ import annotations

import argparse
import logging
import os
import sqlite3
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("migrator")

DEFAULT_DB = os.getenv("DATABASE_PATH", "./workhub.db")

@dataclass
class AgentRow:
    id: str
    agent_id: str
    name: str
    role: str
    workgroup_id: Optional[str]
    external_id: Optional[str]


def sqlite_path_from_arg(path_or_url: str) -> str:
    # Accept "sqlite:///./workhub.db" or "./workhub.db"
    if path_or_url.startswith("sqlite:///"):
        return path_or_url[len("sqlite:///"):]
    return path_or_url


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    cur = conn.execute(f"PRAGMA table_info({table})")
    cols = [r[1] for r in cur.fetchall()]
    if column in cols:
        logger.debug("Column %s.%s already exists", table, column)
        return

    logger.info("Adding column %s.%s", table, column)
    conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def fetch_agents(conn: sqlite3.Connection) -> List[AgentRow]:
    cur = conn.execute("SELECT id, agent_id, name, role, workgroup_id, external_id FROM agents")
    rows = [AgentRow(*r) for r in cur.fetchall()]
    logger.info("Found %d agents", len(rows))
    return rows


def find_user_by_agent_external(conn: sqlite3.Connection, agent_id: str) -> List[Tuple[int]]:
    cur = conn.execute("SELECT id FROM users WHERE agent_external_id = ?", (agent_id,))
    return cur.fetchall()


def find_user_by_username(conn: sqlite3.Connection, username: str) -> List[Tuple[int]]:
    cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
    return cur.fetchall()


def find_user_by_fullname(conn: sqlite3.Connection, full_name: str) -> List[Tuple[int]]:
    cur = conn.execute("SELECT id FROM users WHERE full_name = ?", (full_name,))
    return cur.fetchall()


def create_user_for_agent(conn: sqlite3.Connection, agent: AgentRow) -> int:
    # Insert user with minimal data; hashed_password left empty for admin to setup later
    # Some DB schemas require users.email NOT NULL; use a placeholder and log it so it can be fixed later.
    placeholder_email = f"{agent.agent_id}@no-email.local"
    cur = conn.execute(
        "INSERT INTO users (username, email, full_name, hashed_password, role, agent_external_id, workgroup_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        (agent.agent_id, placeholder_email, agent.name, "", "agent", agent.agent_id, agent.workgroup_id, 1),
    )
    user_id = cur.lastrowid
    logger.info("Created user id=%d for agent %s (placeholder email=%s)", user_id, agent.agent_id, placeholder_email)
    return user_id


def map_agents_to_users(conn: sqlite3.Connection, apply: bool) -> Dict[str, int]:
    agents = fetch_agents(conn)
    mapping: Dict[str, int] = {}
    collisions: List[Tuple[str, List[int]]] = []

    for agent in agents:
        # Try agent_external_id match
        by_ext = find_user_by_agent_external(conn, agent.agent_id)
        if len(by_ext) == 1:
            user_id = by_ext[0][0]
            mapping[agent.agent_id] = user_id
            logger.debug("Mapped agent %s -> user %d (by agent_external_id)", agent.agent_id, user_id)
            continue
        elif len(by_ext) > 1:
            collisions.append((agent.agent_id, [r[0] for r in by_ext]))
            logger.warning("Collision: agent %s has %d matching users by agent_external_id", agent.agent_id, len(by_ext))
            continue

        # Try by username
        by_un = find_user_by_username(conn, agent.agent_id)
        if len(by_un) == 1:
            user_id = by_un[0][0]
            mapping[agent.agent_id] = user_id
            logger.debug("Mapped agent %s -> user %d (by username)", agent.agent_id, user_id)
            # ensure agent_external_id is set
            if apply:
                conn.execute("UPDATE users SET agent_external_id = ? WHERE id = ?", (agent.agent_id, user_id))
            continue
        elif len(by_un) > 1:
            collisions.append((agent.agent_id, [r[0] for r in by_un]))
            logger.warning("Collision: agent %s has %d matching users by username", agent.agent_id, len(by_un))
            continue

        # Try by full_name
        by_name = find_user_by_fullname(conn, agent.name)
        if len(by_name) == 1:
            user_id = by_name[0][0]
            mapping[agent.agent_id] = user_id
            logger.debug("Mapped agent %s -> user %d (by full_name)", agent.agent_id, user_id)
            if apply:
                conn.execute("UPDATE users SET agent_external_id = ? WHERE id = ?", (agent.agent_id, user_id))
            continue
        elif len(by_name) > 1:
            collisions.append((agent.agent_id, [r[0] for r in by_name]))
            logger.warning("Collision: agent %s has %d matching users by full_name", agent.agent_id, len(by_name))
            continue

        # No match: create user
        if apply:
            user_id = create_user_for_agent(conn, agent)
            mapping[agent.agent_id] = user_id
        else:
            logger.info("Would create user for agent %s (%s)", agent.agent_id, agent.name)

    if collisions:
        logger.warning("There are %d collisions; manual resolution required before apply", len(collisions))
        for agent_id, user_ids in collisions:
            logger.warning(" Agent %s -> user ids: %s", agent_id, user_ids)

    return mapping


def update_tickets_assignees(conn: sqlite3.Connection, mapping: Dict[str, int], apply: bool) -> int:
    cur = conn.execute("SELECT id, assignee_agent_id FROM tickets WHERE assignee_agent_id IS NOT NULL")
    rows = cur.fetchall()
    updated = 0

    for ticket_id, assignee_agent in rows:
        if not assignee_agent:
            continue
        # try mapping by agent_id string
        user_id = mapping.get(assignee_agent)
        if user_id is None:
            # maybe assignee_agent stores agent.id instead of agent.agent_id: try lookup
            r = conn.execute("SELECT agent_id FROM agents WHERE id = ?", (assignee_agent,)).fetchone()
            if r:
                mapped = r[0]
                user_id = mapping.get(mapped)
        if user_id:
            logger.debug("Ticket %s assigned -> user %s", ticket_id, user_id)
            if apply:
                conn.execute("UPDATE tickets SET assignee_user_id = ? WHERE id = ?", (user_id, ticket_id))
            updated += 1
        else:
            logger.info("Ticket %s has assignee_agent_id=%s but no mapped user", ticket_id, assignee_agent)

    logger.info("Tickets to update: %d", updated)
    return updated


def link_contacts_to_users_by_email(conn: sqlite3.Connection, apply: bool) -> int:
    cur = conn.execute("SELECT id, email FROM contacts WHERE email IS NOT NULL")
    rows = cur.fetchall()
    linked = 0

    for contact_id, email in rows:
        if not email:
            continue
        r = conn.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
        if r:
            user_id = r[0]
            logger.debug("Linking contact %s -> user %s by email %s", contact_id, user_id, email)
            if apply:
                conn.execute("UPDATE contacts SET user_id = ? WHERE id = ?", (user_id, contact_id))
            linked += 1

    logger.info("Contacts to link by email: %d", linked)
    return linked


def run_migration(db_path: str, apply: bool) -> None:
    p = sqlite_path_from_arg(db_path)
    if not os.path.exists(p):
        logger.error("Database file not found: %s", p)
        sys.exit(1)

    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row

    try:
        # Ensure columns exist (idempotent)
        ensure_column(conn, "users", "role", "TEXT DEFAULT 'agent'")
        ensure_column(conn, "users", "agent_external_id", "TEXT")
        ensure_column(conn, "users", "workgroup_id", "TEXT")
        ensure_column(conn, "users", "is_active", "INTEGER DEFAULT 1")
        ensure_column(conn, "users", "email_verified", "INTEGER DEFAULT 0")
        ensure_column(conn, "tickets", "assignee_user_id", "INTEGER")
        ensure_column(conn, "contacts", "user_id", "INTEGER")

        logger.info("Beginning %s run", "apply" if apply else "dry-run")
        # Use a transaction for apply
        if apply:
            conn.execute("BEGIN")

        mapping = map_agents_to_users(conn, apply=apply)
        updated_tickets = update_tickets_assignees(conn, mapping, apply=apply)
        linked_contacts = link_contacts_to_users_by_email(conn, apply=apply)

        if apply:
            conn.commit()
            logger.info("Migration applied: %d tickets updated, %d contacts linked, %d agents mapped", updated_tickets, linked_contacts, len(mapping))
        else:
            logger.info("Dry-run complete: %d tickets would be updated, %d contacts would be linked, %d agents mapped", updated_tickets, linked_contacts, len(mapping))

    except Exception:
        logger.exception("Migration failed; rolling back")
        if apply:
            conn.rollback()
        raise
    finally:
        conn.close()


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default=DEFAULT_DB, help="Path or sqlite URL to DB (e.g., sqlite:///./workhub.db)")
    parser.add_argument("--apply", action="store_true", help="Apply changes (default is dry-run)")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)

    logger.info("DB: %s", args.db)
    run_migration(args.db, apply=args.apply)
