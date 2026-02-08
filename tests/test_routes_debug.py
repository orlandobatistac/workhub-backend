from app.main import app


def test_auth_route_exists():
    paths = [r.path for r in app.router.routes]
    print(paths)
    assert '/api/auth/login' in paths
