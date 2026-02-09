# WorkHub API

FastAPI backend for ticket management system.

## Setup

```bash
# Create and activate a virtual environment (cross-platform)
python -m venv .venv
# macOS / Linux
source .venv/bin/activate
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1
# Install dependencies
pip install -r requirements.txt
# Copy example env
cp .env.example .env  # or copy .env.example .env on Windows

# Run the server (application entry is `app.main:app`)
uvicorn app.main:app --reload
```

Server: `http://localhost:8000`

## API Endpoints

### Base URL: `/api`

| Method | Endpoint | Description |
|--------|----------|---|
| **Branches** |
| GET | `/branches` | List (paginated) |
| POST | `/branches` | Create |
| GET | `/branches/{id}` | Get one |
| PUT | `/branches/{id}` | Update |
| DELETE | `/branches/{id}` | Delete |
| **Agents** |
| GET | `/agents` | List (paginated) |
| POST | `/agents` | Create |
| GET | `/agents/{id}` | Get one |
| PUT | `/agents/{id}` | Update |
| DELETE | `/agents/{id}` | Delete |
| **Workgroups** |
| GET | `/workgroups` | List (paginated) |
| POST | `/workgroups` | Create |
| GET | `/workgroups/{id}` | Get one |
| PUT | `/workgroups/{id}` | Update |
| DELETE | `/workgroups/{id}` | Delete |
| **Contacts** |
| GET | `/contacts` | List (paginated) |
| POST | `/contacts` | Create |
| GET | `/contacts/{id}` | Get one |
| PUT | `/contacts/{id}` | Update |
| DELETE | `/contacts/{id}` | Delete |
| **Tickets** |
| GET | `/tickets` | List (paginated) |
| POST | `/tickets` | Create |
| GET | `/tickets/{id}` | Get one |
| PUT | `/tickets/{id}` | Update |
| DELETE | `/tickets/{id}` | Delete |
| **Messages** |
| GET | `/tickets/{ticketId}/messages` | List by ticket |
| POST | `/tickets/{ticketId}/messages` | Create message |
| **System** |
| GET | `/health` | Health check |
| POST | `/seed` | Generate demo data |
| POST | `/token` | Login (JWT) |
| POST | `/register` | Create user |

## Response Format

### Pagination
```
GET /api/branches?page=1&limit=10
```

### Paginated Response
```json
{
  "data": [...],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 50,
    "totalPages": 5
  }
}
```

### Error Response
```json
{
  "message": "Error description",
  "status": 400
}
```

## Authentication

```bash
# Login
curl -X POST http://localhost:8000/api/token \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'

# Use token
curl -H "Authorization: Bearer {token}" \
  http://localhost:8000/api/branches
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|---|
| SECRET_KEY | (auto-generated) | JWT secret key |
| ALGORITHM | HS256 | JWT algorithm |
| ACCESS_TOKEN_EXPIRE_MINUTES | 30 | Token expiration |
| RATE_LIMIT | 100/second | Rate limit per IP |
| DATABASE_URL | sqlite:///./workhub.db | Database URL |
| ALLOWED_ORIGINS | localhost:3000, localhost:8000 | CORS origins |

## Database

SQLite by default. Change via `DATABASE_URL` in `.env`.

Tables: users, branches, agents, workgroups, contacts, tickets, messages, audit_logs

## Docs / API Contract

- Swagger: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

**API Contract (OpenAPI)**

- A generated, augmented OpenAPI (with examples) is stored at `docs/openapi.json` and serves as the machine-readable API contract.
- The generation script is at `scripts/generate_openapi.py` — run it to regenerate the contract.
- CI validates `docs/openapi.json` on PRs via `.github/workflows/verify_openapi.yml` to prevent accidental API drift. ✅

**Notable API behaviour**

- POST `/api/tickets` will **always** create a first message when a `description` is supplied (works for JSON and multipart requests). The response may include a `first_message` object when created.
- Attachments: maximum **10 MB** per file and **maximum 5 attachments** per message. If these limits are exceeded, the API returns documented errors such as `attachment_too_large` and `attachment_too_many`.

## Security Scans 🔒

This repository includes basic automated security checks:

- **Dependabot** (`.github/dependabot.yml`) — checks for dependency updates weekly and raises PRs for upgrades.
- **Bandit** — a Python security scanner. A helper script is available at `scripts/bandit_check.py` that runs Bandit and fails when issues of configured severities are found (env var `BANDIT_FAIL_SEVERITIES`, default `HIGH`).
- **CodeQL** — GitHub CodeQL analysis is executed via `CodeQL` job in `.github/workflows/ci.yml`.

Run Bandit locally:

```bash
pip install bandit
python scripts/bandit_check.py
```

You can configure the severities that cause the CI job to fail with `BANDIT_FAIL_SEVERITIES` (e.g. `MEDIUM, HIGH`).

---

## License

MIT
