"""map_remaining_assignees.py

Find tickets where `assignee_agent_id` is not NULL and `assignee_user_id` is NULL
and try to resolve assignee_agent_id -> users.id via AgentModel.agent_id -> User.agent_external_id/username.

Usage:
  python scripts/map_remaining_assignees.py --db ./workhub.db         # dry-run
  python scripts/map_remaining_assignees.py --db ./workhub.db --apply # apply

Logs how many tickets were updated and which could not be resolved.
"""

import argparse
import logging
import os
import sqlite3
import sys

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("map_assignees")

DEFAULT_DB = os.getenv("DATABASE_PATH", "./workhub.db")


def sqlite_path_from_arg(path_or_url: str) -> str:
    if path_or_url.startswith("sqlite:///"):
        return path_or_url[len("sqlite:///"):]
    return path_or_url


def run(db_path: str, apply: bool):
    p = sqlite_path_from_arg(db_path)
    if not os.path.exists(p):
        logger.error("Database file not found: %s", p)
        sys.exit(1)

    conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    rows = cur.execute("SELECT id, assignee_agent_id FROM tickets WHERE assignee_agent_id IS NOT NULL AND assignee_user_id IS NULL").fetchall()
    logger.info("Found %d tickets with legacy assignee", len(rows))

    updated = 0
    unresolved = []

    for ticket in rows:
        ticket_id = ticket['id']
        assignee_agent = ticket['assignee_agent_id']
        if not assignee_agent:
            continue

        # Attempt to resolve agent -> user
        # First try to find a user with agent_external_id == assignee_agent
        r = cur.execute("SELECT id FROM users WHERE agent_external_id = ?", (assignee_agent,)).fetchone()
        if r:
            user_id = r[0]
        else:
            # Try where username == assignee_agent
            r = cur.execute("SELECT id FROM users WHERE username = ?", (assignee_agent,)).fetchone()
            if r:
                user_id = r[0]
            else:
                # Try to find agent by agents.id -> agents.agent_id then map
                r = cur.execute("SELECT agent_id FROM agents WHERE id = ?", (assignee_agent,)).fetchone()
                if r and r[0]:
                    agent_key = r[0]
                    r2 = cur.execute("SELECT id FROM users WHERE agent_external_id = ?", (agent_key,)).fetchone()
                    if r2:
                        user_id = r2[0]
                    else:
                        r3 = cur.execute("SELECT id FROM users WHERE username = ?", (agent_key,)).fetchone()
                        user_id = r3[0] if r3 else None
                else:
                    user_id = None

        if user_id:
            logger.debug("Mapping ticket %s -> user %s", ticket_id, user_id)
            if apply:
                cur.execute("UPDATE tickets SET assignee_user_id = ? WHERE id = ?", (user_id, ticket_id))
            updated += 1
        else:
            unresolved.append((ticket_id, assignee_agent))

    if apply:
        conn.commit()

    logger.info("Updated %d tickets", updated)
    if unresolved:
        logger.info("Unresolved tickets: %d", len(unresolved))
        for t in unresolved:
            logger.info(" - ticket %s has assignee_agent_id=%s", t[0], t[1])
    else:
        logger.info("All legacy assignees resolved")

    conn.close()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--db', default=DEFAULT_DB)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--verbose', action='store_true')
    args = parser.parse_args()
    if args.verbose:
        logger.setLevel(logging.DEBUG)
    run(args.db, apply=args.apply)