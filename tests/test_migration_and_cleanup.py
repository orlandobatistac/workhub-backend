import os
import tempfile
import sqlite3
from pathlib import Path
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure scripts import use the temp DB path
from scripts.migrate_agents_to_users import run_migration
from scripts.cleanup_agents import main as cleanup_main
import main
from main import Base, UserModel, AgentModel, TicketModel


def setup_temp_db():
    tmp = tempfile.NamedTemporaryFile(prefix="workhub_test_", suffix=".db", delete=False)
    tmp.close()
    db_path = tmp.name

    engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return db_path, engine, Session


def test_migrate_agents_to_users_and_cleanup():
    db_path, engine, Session = setup_temp_db()
    session = Session()

    # Create an agent
    agent = AgentModel(id="a1", agent_id="AG-001", name="Agent One", workgroup_id="wg-1")
    session.add(agent)
    session.commit()

    # Create a ticket referencing the agent (assignee_agent_id)
    ticket = TicketModel(id="t1", subject="Need help", description="desc", assignee_agent_id="AG-001")
    session.add(ticket)
    session.commit()

    session.close()

    # Run migration (apply)
    run_migration(db_path, apply=True)

    # Verify: user created and ticket.assignee_user_id set
    session = Session()
    user = session.query(UserModel).filter(UserModel.agent_external_id == 'AG-001').first()
    assert user is not None

    t = session.query(TicketModel).filter(TicketModel.id == 't1').first()
    assert t is not None
    assert t.assignee_user_id == user.id

    # Clear legacy assignee_agent_id where assignee_user_id is set
    # (simulate running clear_legacy_assignee_field.py)
    conn = sqlite3.connect(db_path)
    conn.execute("UPDATE tickets SET assignee_agent_id = NULL WHERE assignee_user_id IS NOT NULL")
    conn.commit()
    conn.close()

    # Run cleanup (apply)
    cleanup_main(db_path=db_path, apply=True)

    # Verify agents table dropped or empty and tickets table has no assignee_agent_id column
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    # Check agents table count (should be 0 or no table)
    try:
        agents_cnt = cur.execute("SELECT COUNT(*) FROM agents").fetchone()[0]
    except sqlite3.OperationalError:
        agents_cnt = 0

    assert agents_cnt == 0

    # Check tickets columns
    cols = [r[1] for r in cur.execute("PRAGMA table_info(tickets)").fetchall()]
    assert 'assignee_agent_id' not in cols

    conn.close()

    # Cleanup file
    Path(db_path).unlink()
