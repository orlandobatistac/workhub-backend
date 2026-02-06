# WorkHub API Contract v2.0

**Base URL:** `http://localhost:8000/api` | **Version:** 2.0

## Ticket Model

```json
{
  "id": "uuid",
  "subject": "string (1-200 chars)",
  "description": "string (1-5000 chars)",
  "priority": "low | medium | high | critical",
  "status": "open | in_progress | closed",
  "resolution": "resolved | cancelled | duplicate | wontfix (null if status != closed)",
  "branch_id": "uuid (optional)",
  "assignee_agent_id": "uuid (optional)",
  "contact_id": "uuid (optional)",
  "due_date": "ISO8601 (optional)",
  "created_at": "ISO8601",
  "updated_at": "ISO8601"
}
```

## Contact Model

```json
{
  "id": "uuid",
  "contact_id": "string (unique, e.g., CT-001)",
  "name": "string (1-100 chars)",
  "email": "string email format (optional)",
  "phone": "string (7-20 chars, optional)",
  "primary_branch_id": "uuid",
  "external_id": "string (optional)",
  "created_at": "ISO8601"
}
```

## User Model

```json
{
  "id": "integer",
  "username": "string (3-50 chars, unique)",
  "email": "string (email format, unique)",
  "full_name": "string (2-100 chars)",
  "role": "user | agent | admin",
  "is_active": "boolean",
  "created_at": "ISO8601"
}
```

## Endpoints

### Create Ticket
`POST /api/tickets`

### Get Ticket
`GET /api/tickets/{ticket_id}` → Returns ticket object | 404 if not found

### List Tickets
`GET /api/tickets?page=1&limit=10` → Returns `{data: Ticket[], pagination: {page, limit, total, totalPages}}`

### Update Ticket
`PUT /api/tickets/{ticket_id}` → All fields optional | Returns updated ticket

### Delete Ticket
`DELETE /api/tickets/{ticket_id}` → 204 No Content

### List Messages
`GET /api/tickets/{ticket_id}/messages?page=1&limit=10` → Returns paginated messages

### Create Message
`POST /api/tickets/{ticket_id}/messages` → Multipart form data (sender_name, sender_type, content, attachments[])

## Contact Endpoints

### Create Contact
`POST /api/contacts` → Fields: contact_id, name, primary_branch_id, email (optional), phone (optional)

### List Contacts
`GET /api/contacts?page=1&limit=10` → Returns paginated contacts

### Get Contact
`GET /api/contacts/{contact_id}` → Returns contact object | 404 if not found

### Update Contact
`PUT /api/contacts/{contact_id}` → All fields optional | Returns updated contact

### Delete Contact
`DELETE /api/contacts/{contact_id}` → 204 No Content

## Authentication Endpoints

### Register User
`POST /api/register` → Creates new user account. Fields: username, email, full_name, password, role (default: "user")

### Login (Get Token)
`POST /api/token` → Returns JWT token. Body: `{username, password}` → Response: `{access_token, token_type}`

### Get Current User
`GET /api/me` → Returns authenticated user info (requires Bearer token)

## Statuses | Resolutions | Validations

**Valid Statuses:** `open` (new) | `in_progress` (assigned) | `closed` (complete)

**Valid Resolutions (only when closed):** `resolved` | `cancelled` | `duplicate` | `wontfix`

**Field Validation:**
- subject: 1-200 chars
- description: 1-5000 chars
- priority: `low|medium|high|critical`
- status: `^(open|in_progress|closed)$`
- resolution: `^(resolved|cancelled|duplicate|wontfix)$`
- due_date: ISO8601 format
- UUIDs: branch_id, assignee_agent_id, contact_id
- contact_id: 1-50 chars (unique)
- contact name: 1-100 chars
- email: Valid email format (optional), pattern: `^[\w\.-]+@[\w\.-]+\.\w+$`
- phone: 7-20 chars (optional)

**Important:** `resolution` is ignored if `status != 'closed'`. Calculate overdue on frontend: `due_date < now && status != 'closed'`

## Errors | Rate Limiting

**Error Format:** `{message: string, status: number}`

**HTTP Codes:** 200 OK | 201 Created | 204 No Content | 400 Bad Request | 401 Unauthorized | 403 Forbidden | 404 Not Found | 429 Rate Limited | 500 Server Error

**Rate Limit:** 100 requests/minute per IP (header: `X-RateLimit-*`)

## Examples

**Create Ticket:**
```javascript
POST /api/tickets
{ subject: "Bug", description: "...", priority: "high", status: "open" }
// → 201 { id, subject, status: "open", resolution: null, ... }
```

**Mark In Progress:**
```javascript
PUT /api/tickets/{id}
{ status: "in_progress", assignee_agent_id: "uuid" }
// → 200 { ...updated... }
```

**Close as Resolved:**
```javascript
PUT /api/tickets/{id}
{ status: "closed", resolution: "resolved" }
// → 200 { status: "closed", resolution: "resolved", ... }
```

**List with Pagination:**
```javascript
GET /api/tickets?page=1&limit=20
// → 200 { data: [...], pagination: { page, limit, total, totalPages } }
```

**Error Example:**
```javascript
POST /api/tickets
{ subject: "Bug", description: "...", status: "resolved" }  // ❌ Invalid status
// → 400 { message: "Invalid request data", status: 400 }
```

**Create Contact with Email:**
```javascript
POST /api/contacts
{ contact_id: "CT-001", name: "John Doe", email: "john@example.com", phone: "+1-555-1234", primary_branch_id: "uuid" }
// → 201 { id, contact_id, name, email, phone, primary_branch_id, created_at }
```

**Register & Login Flow:**
```javascript
// 1. Register new user
POST /api/register
{ username: "john", email: "john@example.com", full_name: "John Doe", password: "Pass123!", role: "user" }
// → 201 { id, username, email, full_name, role, is_active, created_at }

// 2. Login to get token
POST /api/token
{ username: "john", password: "Pass123!" }
// → 200 { access_token: "eyJ...", token_type: "bearer" }

// 3. Use token for authenticated requests
GET /api/me
Headers: { Authorization: "Bearer eyJ..." }
// → 200 { id, username, email, full_name, role, is_active, created_at }

// 4. Access protected resources
GET /api/tickets
Headers: { Authorization: "Bearer eyJ..." }
// → 200 { data: [...], pagination: {...} }
```
