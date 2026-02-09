"""clear_legacy_assignee_field.py

Set tickets.assignee_agent_id = NULL for tickets where assignee_user_id IS NOT NULL.
Dry-run reports number of rows that would be updated; --apply executes the changes.
"""

import argparse
import logging
import os
import sqlite3
import sys

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger('clear_legacy')

DEFAULT_DB = os.getenv('DATABASE_PATH', './workhub.db')


def sqlite_path_from_arg(path_or_url: str) -> str:
    if path_or_url.startswith('sqlite:///'):
        return path_or_url[len('sqlite:///'):]
    return path_or_url


def run(db_path: str, apply: bool):
    p = sqlite_path_from_arg(db_path)
    if not os.path.exists(p):
        logger.error('Database file not found: %s', p)
        sys.exit(1)

    conn = sqlite3.connect(p)
    cur = conn.cursor()

    rows = cur.execute("SELECT COUNT(*) FROM tickets WHERE assignee_agent_id IS NOT NULL AND assignee_user_id IS NOT NULL").fetchone()[0]
    logger.info('Rows to clear: %d', rows)

    if not apply:
        logger.info('Dry-run mode; no changes applied')
        conn.close()
        return

    cur.execute("UPDATE tickets SET assignee_agent_id = NULL WHERE assignee_agent_id IS NOT NULL AND assignee_user_id IS NOT NULL")
    conn.commit()
    logger.info('Cleared legacy assignee_agent_id for %d tickets', rows)
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