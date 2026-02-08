from app.main import app
paths = [r.path for r in app.router.routes]
print('/api/auth/login' in paths)
print([r.path for r in app.router.routes if r.path.startswith('/api/auth')])
