-- 002_cleanup_agents.sql
-- Cleanup script to remove legacy agents table and assignee_agent_id column
-- IMPORTANT: Run this ONLY after verifying migration and ensuring no legacy references remain.
-- Steps performed by this SQL should be executed in staging first.

-- 1) Quick checks
SELECT (SELECT COUNT(*) FROM tickets WHERE assignee_agent_id IS NOT NULL) AS tickets_with_assignee_agent_id;
SELECT (SELECT COUNT(*) FROM agents) AS agents_count;
SELECT (SELECT COUNT(*) FROM users WHERE role = 'agent') AS users_with_role_agent;

-- If tickets_with_assignee_agent_id > 0 : DO NOT PROCEED. Resolve remaining rows first.

-- NOTE: SQLite supports DROP TABLE. Dropping a column is supported in newer SQLite versions (>= 3.35).
-- To be maximally compatible, consider using a Python helper (cleanup_agents.py) that recreates the table without the legacy column.

-- Example (DESCTRUCTIVE) steps for SQLite 3.35+:
-- ALTER TABLE tickets DROP COLUMN assignee_agent_id;
-- DROP TABLE IF EXISTS agents;

-- After running these, update any application code and remove related tests that reference the old columns/tables.
