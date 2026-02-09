from datetime import timedelta

import pytest

from app.auth import create_access_token
from app.main import app


def test_rate_limit_on_login(client, create_user):
    # Temporarily enable limiter and set a low default for the scope of this test.
    limiter = getattr(app.state, "limiter", None)
    if limiter is None:
        pytest.skip("Rate limiter not configured")

    prev_enabled = getattr(limiter, "enabled", None)
    # store either attribute name we can find for limits
    prev_limits = getattr(limiter, "default_limits", None)
    if prev_limits is None:
        prev_limits = getattr(limiter, "_default_limits", None)

    try:
        limiter.enabled = True

        # Force a small default for the scope of this test so we reliably hit 429
        try:
            if hasattr(limiter, "default_limits"):
                limiter.default_limits = ["1/second"]
            else:
                limiter._default_limits = ["1/second"]
        except Exception:
            pass

        # Don't attempt to mutate other internals; hammer the login endpoint until we see a 429
        user = create_user(user_type="contact", username="rl_user", password="pw1")

        last_resp = None
        # Attempt up to 30 times; default limiter is 10/min so we should hit 429
        # well before the cap in a fresh test environment.
        for i in range(30):
            r = client.post("/api/auth/login", json={"username_or_email": user.username, "password": "wrongpass"})
            last_resp = r
            if r.status_code == 429:
                break
            assert r.status_code in (401, 400)

        assert last_resp is not None and last_resp.status_code == 429

    finally:
        # restore limiter state
        try:
            if prev_enabled is not None:
                limiter.enabled = prev_enabled
            if hasattr(limiter, "default_limits") and prev_limits is not None:
                limiter.default_limits = prev_limits
            elif prev_limits is not None:
                limiter._default_limits = prev_limits
        except Exception:
            pass


def test_jwt_expiration_invalid_and_missing_token(client, create_user):
    user = create_user(user_type="contact", username="tok_user", password="pw2")

    # Expired token (set negative expiration)
    expired = create_access_token({"sub": user.username}, expires_delta=timedelta(seconds=-1))
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert r.status_code == 401

    # Altered token should also be rejected
    valid = create_access_token({"sub": user.username}, expires_delta=timedelta(minutes=60))
    # Append a character to invalidate the signature reliably
    altered = valid + "a"
    r = client.get("/api/auth/me", headers={"Authorization": f"Bearer {altered}"})
    assert r.status_code == 401

    # Missing token should produce 401 for an endpoint that requires authentication
    r = client.get("/api/auth/me")
    assert r.status_code == 401
