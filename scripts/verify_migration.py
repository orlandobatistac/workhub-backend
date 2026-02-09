import sqlite3

def main(db='workhub.db'):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    rows = cur.execute("SELECT id, username, email, full_name, role, agent_external_id, workgroup_id, created_at FROM users WHERE role='agent' ORDER BY id").fetchall()
    print('AGENTS:', len(rows))
    for r in rows:
        print(r)
    rows2 = cur.execute("SELECT id, assignee_agent_id, assignee_user_id FROM tickets WHERE assignee_user_id IS NOT NULL LIMIT 30").fetchall()
    print('\nTICKETS_UPDATED:', len(rows2))
    for r in rows2:
        print(r)
    conn.close()

if __name__ == '__main__':
    main()
