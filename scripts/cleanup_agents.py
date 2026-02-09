"""cleanup_agents.py

Performs safe cleanup to remove legacy `agents` table and `assignee_agent_id` column from `tickets`.

Workflow:
- Checks for any tickets still referencing assignee_agent_id (must be zero to proceed).
- Creates a new `tickets_new` table with same schema except without assignee_agent_id.
- Copies data from `tickets` to `tickets_new` using assignee_user_id (already migrated).
- Renames tables and drops the old `tickets` and `agents` tables.

USE WITH CAUTION. Always run in staging first.
"""

import sqlite3
import os
import sys

DB = os.getenv('DATABASE_PATH', './workhub.db')

CREATE_TICKETS_NEW = '''
CREATE TABLE tickets_new (
    id TEXT PRIMARY KEY,
    subject TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'medium',
    status TEXT NOT NULL DEFAULT 'open',
    resolution TEXT,
    branch_id TEXT,
    assignee_user_id INTEGER,
    contact_id TEXT,
    due_date DATETIME,
    created_by_id INTEGER,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
'''

def main(db_path=DB, apply=False):
    if not os.path.exists(db_path):
        print('DB not found:', db_path); sys.exit(1)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Check tickets referencing legacy field
    cur.execute("SELECT COUNT(*) FROM tickets WHERE assignee_agent_id IS NOT NULL")
    count = cur.fetchone()[0]
    print('tickets with assignee_agent_id:', count)
    if count > 0:
        print('Aborting: resolve remaining tickets with assignee_agent_id before cleanup')
        conn.close()
        return

    # Check agents existence
    try:
        cur.execute('SELECT COUNT(*) FROM agents')
        agents_count = cur.fetchone()[0]
    except sqlite3.OperationalError:
        agents_count = 0
    print('agents table count:', agents_count)

    if not apply:
        print('Dry run complete. To apply, re-run with --apply')
        conn.close()
        return

    # Begin destructive cleanup
    print('Creating tickets_new...')
    cur.execute(CREATE_TICKETS_NEW)

    print('Copying data from tickets to tickets_new...')
    cur.execute('''
        INSERT INTO tickets_new (id, subject, description, priority, status, resolution, branch_id, assignee_user_id, contact_id, due_date, created_by_id, created_at, updated_at)
        SELECT id, subject, description, priority, status, resolution, branch_id, assignee_user_id, contact_id, due_date, created_by_id, created_at, updated_at FROM tickets;
    ''')

    print('Renaming tables...')
    cur.execute('ALTER TABLE tickets RENAME TO tickets_old')
    cur.execute('ALTER TABLE tickets_new RENAME TO tickets')

    print('Dropping old tickets table...')
    cur.execute('DROP TABLE IF EXISTS tickets_old')

    print('Dropping agents table...')
    cur.execute('DROP TABLE IF EXISTS agents')

    conn.commit()
    conn.close()
    print('Cleanup applied successfully.')

if __name__ == '__main__':
    apply = '--apply' in sys.argv
    main(apply=apply)
