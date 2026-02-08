from app.main import app

for r in app.routes:
    if 'messages' in r.path:
        print(r.path, r.methods, getattr(r, 'endpoint', None))
