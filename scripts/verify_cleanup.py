import sqlite3

conn=sqlite3.connect('workhub.db')
cur=conn.cursor()
# Check agents table exists
try:
    c=cur.execute("SELECT COUNT(*) FROM agents").fetchone()
    exists=True
except sqlite3.OperationalError:
    exists=False
print('agents_table_exists:', exists)
# Check tickets columns
cols=[r[1] for r in cur.execute("PRAGMA table_info(tickets)").fetchall()]
print('tickets_columns:', cols)
# Count users with role agent
cnt=cur.execute("SELECT COUNT(*) FROM users WHERE role='agent'").fetchone()[0]
print('users_role_agent:', cnt)
conn.close()