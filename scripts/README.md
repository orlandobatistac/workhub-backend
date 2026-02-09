Migration scripts README

Purpose
-------
These helpers support migrating the schema so that `users` becomes the canonical staff entity and `contacts` remains the public portal entity.

Files
-----
- `001_add_user_role_and_fk.sql` : SQL to add non-destructive columns (role, agent_external_id, assignee_user_id, contacts.user_id, indexes)
- `migrate_agents_to_users.py` : Python migration helper that performs dry-run and apply steps to create users for agents, map tickets and optionally link contacts to users by email.

Usage
-----
1) BACKUP your database file before proceeding.

2) In a staging environment, run the SQL to add the columns (SQLite):
   sqlite3 ./workhub.db < scripts/001_add_user_role_and_fk.sql

3) Dry run the python script to see what would happen (no changes):
   python scripts/migrate_agents_to_users.py --db ./workhub.db

4) Review the dry-run log carefully. If satisfied, run with --apply:
   python scripts/migrate_agents_to_users.py --db ./workhub.db --apply

Notes & Safety
--------------
- The script is idempotent and logs collisions that need manual resolution.
- It does NOT drop legacy columns or the `agents` table; cleanup should be done after verification.
- Use staging and review audit logs before running in production.
