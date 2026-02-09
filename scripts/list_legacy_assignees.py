import sqlite3

def main(db='workhub.db'):
    conn = sqlite3.connect(db)
    cur = conn.cursor()

    total_with_legacy = cur.execute("SELECT COUNT(*) FROM tickets WHERE assignee_agent_id IS NOT NULL").fetchone()[0]
    migrated = cur.execute("SELECT id, assignee_agent_id, assignee_user_id FROM tickets WHERE assignee_agent_id IS NOT NULL AND assignee_user_id IS NOT NULL").fetchall()
    unresolved = cur.execute("SELECT id, assignee_agent_id FROM tickets WHERE assignee_agent_id IS NOT NULL AND assignee_user_id IS NULL").fetchall()

    print('TOTAL_WITH_LEGACY:', total_with_legacy)
    print('\nMIGRATED (assignee_user_id set):', len(migrated))
    for r in migrated[:200]:
        print(r)

    print('\nUNRESOLVED (need manual resolution):', len(unresolved))
    for r in unresolved[:200]:
        print(r)

    conn.close()

if __name__ == '__main__':
    main()