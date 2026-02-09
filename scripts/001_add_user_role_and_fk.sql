-- 001_add_user_role_and_fk.sql
-- Adds non-destructive columns required for migration to make `users` the canonical staff entity
-- Note: SQLite ALTER TABLE only supports ADD COLUMN; we keep legacy columns until verification.
-- Make a backup before running.

PRAGMA foreign_keys=OFF;
BEGIN TRANSACTION;

-- Add role to users (default: 'agent' for backwards compatibility during migration)
ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'agent';
ALTER TABLE users ADD COLUMN agent_external_id TEXT;
ALTER TABLE users ADD COLUMN workgroup_id TEXT;
ALTER TABLE users ADD COLUMN is_active INTEGER DEFAULT 1;
ALTER TABLE users ADD COLUMN email_verified INTEGER DEFAULT 0;

-- Add assignee_user_id to tickets (new canonical FK to users.id)
ALTER TABLE tickets ADD COLUMN assignee_user_id INTEGER;
-- Add secret_token to tickets for public ticket operations
ALTER TABLE tickets ADD COLUMN secret_token TEXT;

-- Add user_id to contacts to optionally link a contact to a user account
ALTER TABLE contacts ADD COLUMN user_id INTEGER;

-- Add indexes to speed up migration queries
CREATE INDEX IF NOT EXISTS idx_users_agent_external_id ON users(agent_external_id);
CREATE INDEX IF NOT EXISTS idx_tickets_assignee_user_id ON tickets(assignee_user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_email ON contacts(email);

COMMIT;
PRAGMA foreign_keys=ON;

-- NOTES / next steps:
-- 1) Run the accompanying Python script `migrate_agents_to_users.py` in dry-run mode to see mappings.
-- 2) After validating results, run the script with --apply to actually create users and update tickets.
-- 3) After full validation in staging, you may DROP legacy columns/tables (agents.assignee_agent_id) if desired.
