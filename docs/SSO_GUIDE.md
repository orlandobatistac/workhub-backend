# WorkHub SSO Guide (PHP Portal)

This guide explains how to integrate WorkHub (FastAPI + React) as a module inside a PHP portal using SSO.
It includes the token contract, backend config, frontend flow, and deployment notes.

---

## 1) SSO Token Contract (JWT)

**Algorithm:** HS256 (shared secret)
**TTL:** 5-10 minutes
**Purpose:** Exchange this token for a WorkHub JWT via `/api/sso/exchange`.

### Required claims
- `iss`: issuer id, ex: `php-portal`
- `aud`: audience id, ex: `workhub-support`
- `sub`: unique user id from portal
- `email`: user email
- `name`: user full name
- `role`: `admin` | `agent` | `contact`
- `iat`: issued-at unix seconds
- `exp`: expiration unix seconds
- `jti`: unique token id (optional but recommended)

### Example payload
```
{
  "iss": "php-portal",
  "aud": "workhub-support",
  "sub": "user-12345",
  "email": "ana@empresa.com",
  "name": "Ana Perez",
  "role": "agent",
  "iat": 1700000000,
  "exp": 1700000600,
  "jti": "a1b2c3d4"
}
```

---

## 2) Backend config (FastAPI)

Add these environment variables in the backend:

```
SSO_ISSUER=php-portal
SSO_AUDIENCE=workhub-support
SSO_ALGORITHM=HS256
SSO_SECRET=your-shared-sso-secret
```

**Notes**
- The same values must be used in PHP when signing the JWT.
- If `SSO_SECRET` is empty, the exchange endpoint will return 500.

---

## 3) Exchange flow

### Step A: PHP portal issues SSO JWT
The PHP portal signs a JWT using the shared secret.

### Step B: redirect to WorkHub module
Send the user to the module with the SSO token in the URL:

```
https://your-domain/support?sso=JWT_HERE
```

### Step C: Frontend exchanges token
The React app reads `?sso=...`, calls `/api/sso/exchange`, stores the WorkHub JWT, and continues normally.

---

## 4) Example PHP (HS256) pseudocode

This is an example for the portal to issue the SSO JWT. Adjust to your PHP JWT library.

```
$payload = [
  "iss" => "php-portal",
  "aud" => "workhub-support",
  "sub" => $userId,
  "email" => $email,
  "name" => $fullName,
  "role" => $role, // admin|agent|contact
  "iat" => time(),
  "exp" => time() + 600,
  "jti" => bin2hex(random_bytes(8))
];

$jwt = JWT::encode($payload, $SSO_SECRET, "HS256");

header("Location: https://your-domain/support?sso=" . urlencode($jwt));
exit;
```

---

## 5) What WorkHub does on exchange

- Validates signature, issuer, audience, and expiration.
- Creates or updates a minimal local user.
- Returns a normal WorkHub JWT.

Minimal local user fields:
- `username` (from `sub`)
- `email`
- `full_name`
- `role`
- `is_active = true`

---

## 6) Deployment notes (Ubuntu)

### Recommended routing (same domain)
- PHP portal: `/`
- WorkHub frontend: `/support`
- WorkHub API: `/support/api` or `/api`

This avoids CORS and keeps cookies simple.

### Nginx example

```
server {
  server_name your-domain;

  # WorkHub frontend
  location /support/ {
    root /var/www/workhub-frontend;
    try_files $uri /support/index.html;
  }

  # WorkHub API
  location /support/api/ {
    proxy_pass http://127.0.0.1:8000/api/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
  }
}
```

---

## 7) Troubleshooting

- 401 from `/api/sso/exchange`: check secret, iss, aud, exp.
- 500 from `/api/sso/exchange`: check `SSO_SECRET` env var.
- Still seeing login page: confirm `?sso=...` param is present in the URL.

---

## 8) Next steps

- Confirm issuer/audience strings with the client.
- Generate the shared secret and set it in both PHP and FastAPI.
- Provide final Nginx/systemd configs if needed.
