# WorkHub API

FastAPI backend for ticket management system.

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
uvicorn main:app --reload
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
| RATE_LIMIT | 100/minute | Rate limit per IP |
| DATABASE_URL | sqlite:///./workhub.db | Database URL |
| ALLOWED_ORIGINS | localhost:3000, localhost:8000 | CORS origins |

## Database

SQLite by default. Change via `DATABASE_URL` in `.env`.

Tables: users, branches, agents, workgroups, contacts, tickets, messages, audit_logs

## Docs

- Swagger: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## License

MIT
