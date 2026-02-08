from app.main import app


def test_messages_route_registered():
    paths = [(r.path, list(r.methods)) for r in app.routes if 'messages' in r.path]
    assert any(p == '/api/tickets/{ticket_id}/messages' and 'POST' in m for p, m in paths)
