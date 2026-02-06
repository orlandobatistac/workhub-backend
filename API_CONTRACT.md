# WorkHub API Contract v2.0

**Last Updated:** February 6, 2026  
**Status:** Stable

---

## Table of Contents

1. [Overview](#overview)
2. [Ticket Model](#ticket-model)
3. [Endpoints](#endpoints)
4. [Statuses & Resolutions](#statuses--resolutions)
5. [Validations](#validations)
6. [Error Handling](#error-handling)
7. [Examples](#examples)

---

## Overview

This document defines the API contract for ticket management in WorkHub backend. All endpoints follow RESTful conventions and return standardized JSON responses.

**Base URL:** `http://localhost:8000/api`

**Response Format:**
- List endpoints: `{ data: T[], pagination: { page, limit, total, totalPages } }`
- Single resource: Resource object directly
- Errors: `{ message: string, status: number }`

---

## Ticket Model

### Complete Ticket Object

```typescript
{
  // Identifiers
  id: string (UUID)
  
  // Core fields
  subject: string (1-200 chars)
  description: string (1-5000 chars)
  priority: string (low | medium | high | critical)
  
  // Status & Resolution
  status: string (open | in_progress | closed)
  resolution: string | null (resolved | cancelled | duplicate | wontfix)
  
  // Relationships
  branch_id: string | null (UUID)
  assignee_agent_id: string | null (UUID)
  contact_id: string | null (UUID)
  
  // Timing
  due_date: ISO8601 | null
  created_at: ISO8601
  updated_at: ISO8601
}
```

---

## Endpoints

### 1. Create Ticket

```http
POST /api/tickets
Content-Type: application/json

Request Body:
{
  "subject": "string (1-200 chars, required)",
  "description": "string (1-5000 chars, required)",
  "priority": "low|medium|high|critical (default: medium)",
  "status": "open|in_progress|closed (default: open)",
  "resolution": "resolved|cancelled|duplicate|wontfix (optional)",
  "branch_id": "string/UUID (optional)",
  "assignee_agent_id": "string/UUID (optional)",
  "contact_id": "string/UUID (optional)",
  "due_date": "ISO8601 (optional, e.g., 2026-02-10T12:00:00Z)"
}

Response 201 Created:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "subject": "Login button broken",
  "description": "Login button not responding on mobile",
  "priority": "high",
  "status": "open",
  "resolution": null,
  "branch_id": "550e8400-e29b-41d4-a716-446655440001",
  "assignee_agent_id": null,
  "contact_id": "550e8400-e29b-41d4-a716-446655440002",
  "due_date": "2026-02-10T12:00:00",
  "created_at": "2026-02-06T02:10:00Z",
  "updated_at": "2026-02-06T02:10:00Z"
}

Response 400 Bad Request:
{
  "message": "Invalid request data",
  "status": 400
}
```

---

### 2. Get Ticket

```http
GET /api/tickets/{ticket_id}

Response 200 OK:
{
  "id": "550e8400-e29b-41d4-a716-446655440000",
  "subject": "Login button broken",
  "description": "Login button not responding on mobile",
  "priority": "high",
  "status": "open",
  "resolution": null,
  "branch_id": "550e8400-e29b-41d4-a716-446655440001",
  "assignee_agent_id": null,
  "contact_id": "550e8400-e29b-41d4-a716-446655440002",
  "due_date": "2026-02-10T12:00:00",
  "created_at": "2026-02-06T02:10:00Z",
  "updated_at": "2026-02-06T02:10:00Z"
}

Response 404 Not Found:
{
  "message": "Ticket not found",
  "status": 404
}
```

---

### 3. List Tickets

```http
GET /api/tickets?page=1&limit=10

Query Parameters:
  page: int (default: 1, minimum: 1)
  limit: int (default: 10, minimum: 1, maximum: 100)

Response 200 OK:
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "subject": "Login button broken",
      "description": "Login button not responding on mobile",
      "priority": "high",
      "status": "open",
      "resolution": null,
      "branch_id": "550e8400-e29b-41d4-a716-446655440001",
      "assignee_agent_id": null,
      "contact_id": "550e8400-e29b-41d4-a716-446655440002",
      "due_date": "2026-02-10T12:00:00",
      "created_at": "2026-02-06T02:10:00Z",
      "updated_at": "2026-02-06T02:10:00Z"
    },
    ...
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 61,
    "totalPages": 7
  }
}
```

---

### 4. Update Ticket

```http
PUT /api/tickets/{ticket_id}
Content-Type: application/json

Request Body (all fields optional):
{
  "subject": "string (optional)",
  "description": "string (optional)",
  "priority": "low|medium|high|critical (optional)",
  "status": "open|in_progress|closed (optional)",
  "resolution": "resolved|cancelled|duplicate|wontfix (optional)",
  "branch_id": "UUID (optional)",
  "assignee_agent_id": "UUID (optional)",
  "contact_id": "UUID (optional)",
  "due_date": "ISO8601 (optional)"
}

Response 200 OK:
(Same as Create Ticket response)

Response 400 Bad Request:
{
  "message": "Invalid request data",
  "status": 400
}

Response 404 Not Found:
{
  "message": "Ticket not found",
  "status": 404
}
```

---

### 5. Delete Ticket

```http
DELETE /api/tickets/{ticket_id}

Response 204 No Content
(Empty response body)

Response 404 Not Found:
{
  "message": "Ticket not found",
  "status": 404
}
```

---

### 6. List Ticket Messages

```http
GET /api/tickets/{ticket_id}/messages?page=1&limit=10

Response 200 OK:
{
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440100",
      "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
      "sender_name": "John Doe",
      "sender_type": "agent",
      "content": "Working on the login issue",
      "attachments": null,
      "created_at": "2026-02-06T02:15:00Z"
    },
    ...
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 5,
    "totalPages": 1
  }
}
```

---

### 7. Create Ticket Message

```http
POST /api/tickets/{ticket_id}/messages
Content-Type: multipart/form-data

Form Data:
  sender_name: string (1-100 chars, required)
  sender_type: string (user|agent|system, required)
  content: string (1-10000 chars, required)
  attachments: File[] (optional, max 5 files, max 10MB each)

Response 201 Created:
{
  "id": "550e8400-e29b-41d4-a716-446655440100",
  "ticket_id": "550e8400-e29b-41d4-a716-446655440000",
  "sender_name": "John Doe",
  "sender_type": "agent",
  "content": "Working on the login issue",
  "attachments": [
    {
      "filename": "screenshot.png",
      "url": "/uploads/tickets/uuid_screenshot.png",
      "size": 102400,
      "content_type": "image/png"
    }
  ],
  "created_at": "2026-02-06T02:15:00Z"
}
```

---

## Statuses & Resolutions

### Valid Statuses (3 only)

| Status | Description | Use Case |
|--------|-------------|----------|
| `open` | Ticket is new and unassigned | New tickets, awaiting triage |
| `in_progress` | Ticket is assigned and being worked on | Active work, development |
| `closed` | Ticket workflow is complete | Final state, always use with `resolution` |

### Valid Resolutions (only when status = "closed")

| Resolution | Description | Use Case |
|------------|-------------|----------|
| `resolved` | Problem was fixed successfully | Issue solved, working as intended |
| `cancelled` | Ticket cancelled on request | User requested cancellation |
| `duplicate` | Same issue already tracked elsewhere | Consolidated with another ticket |
| `wontfix` | Decided not to implement | Out of scope, denied, low priority |

### Status Transitions

```
open
  ├→ in_progress (assigned to agent, work starts)
  └→ closed + resolution=cancelled (cancelled immediately)

in_progress
  ├→ closed + resolution=resolved (problem fixed)
  ├→ closed + resolution=duplicate (found duplicate)
  └→ closed + resolution=wontfix (decided not to fix)

closed (terminal state)
  └→ No transitions from closed state
```

### Overdue Logic (Frontend Only)

**Do NOT send `overdue` as status**. Instead, calculate on frontend:

```javascript
const isOverdue = (ticket) => {
  return ticket.due_date && 
         new Date(ticket.due_date) < new Date() && 
         ticket.status !== 'closed'
}

// Usage in UI
{isOverdue(ticket) && <span className="badge-overdue">Overdue</span>}
```

---

## Validations

### Field Validations

| Field | Validation | Error Code |
|-------|-----------|-----------|
| `subject` | Length 1-200 chars | 400 Bad Request |
| `description` | Length 1-5000 chars | 400 Bad Request |
| `priority` | `^(low\|medium\|high\|critical)$` | 400 Bad Request |
| `status` | `^(open\|in_progress\|closed)$` only | 400 Bad Request |
| `resolution` | `^(resolved\|cancelled\|duplicate\|wontfix)$` only | 400 Bad Request |
| `due_date` | Valid ISO8601 datetime | 400 Bad Request |
| `branch_id` | Valid UUID format | 400 Bad Request |
| `assignee_agent_id` | Valid UUID format | 400 Bad Request |
| `contact_id` | Valid UUID format | 400 Bad Request |

### Business Logic Validations

| Rule | Behavior |
|------|----------|
| `resolution` set when `status != "closed"` | Ignored (resolution only valid when closed) |
| `status` set to `resolved` or `overdue` | 400 Bad Request (invalid status values) |
| `resolution` set without `status="closed"` | Accepted but ignored by UI logic |
| Empty `subject` or `description` | 400 Bad Request |

---

## Error Handling

### Standard Error Response Format

```json
{
  "message": "Human-readable error message",
  "status": 400
}
```

### Common HTTP Status Codes

| Code | Meaning | Example |
|------|---------|---------|
| 200 | Request successful | GET, PUT successful |
| 201 | Resource created | POST ticket created |
| 204 | No content | DELETE successful |
| 400 | Bad request (validation error) | Invalid status value |
| 401 | Unauthorized | Missing/invalid auth token |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not found | Ticket doesn't exist |
| 429 | Rate limited | Too many requests (100/minute) |
| 500 | Server error | Unexpected backend error |

### Validation Error Example

```javascript
// Frontend sends invalid status
POST /api/tickets
{
  "subject": "Test",
  "description": "Test",
  "status": "resolved"  // ❌ Invalid, resolved is not a status
}

// Response 400
{
  "message": "Invalid request data",
  "status": 400
}
```

---

## Examples

### Example 1: Create New Ticket

```javascript
// Frontend code
const response = await fetch('/api/tickets', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    subject: 'Login button broken',
    description: 'Login button not responding on mobile devices',
    priority: 'critical',
    status: 'open',
    due_date: new Date(Date.now() + 2 * 24 * 60 * 60 * 1000).toISOString()
  })
})

const ticket = await response.json()
// {
//   id: "550e8400-e29b-41d4-a716-446655440000",
//   subject: "Login button broken",
//   ...
//   status: "open",
//   resolution: null,
//   due_date: "2026-02-08T02:15:00"
// }
```

### Example 2: Assign Ticket to Agent

```javascript
// Frontend code
const response = await fetch(`/api/tickets/${ticketId}`, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    status: 'in_progress',
    assignee_agent_id: 'agent-uuid-123'
  })
})

const updated = await response.json()
// {
//   ...
//   status: "in_progress",
//   assignee_agent_id: "agent-uuid-123"
// }
```

### Example 3: Close Ticket as Resolved

```javascript
// Frontend code
const response = await fetch(`/api/tickets/${ticketId}`, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    status: 'closed',
    resolution: 'resolved'
  })
})

const closed = await response.json()
// {
//   ...
//   status: "closed",
//   resolution: "resolved"
// }
```

### Example 4: Close Ticket as Duplicate

```javascript
// Frontend code
const response = await fetch(`/api/tickets/${ticketId}`, {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    status: 'closed',
    resolution: 'duplicate'
  })
})
```

### Example 5: List Open Tickets

```javascript
// Frontend code
const response = await fetch('/api/tickets?page=1&limit=20')

const result = await response.json()
// {
//   data: [
//     { id: "...", status: "open", due_date: "2026-02-08T..." },
//     ...
//   ],
//   pagination: {
//     page: 1,
//     limit: 20,
//     total: 34,
//     totalPages: 2
//   }
// }

// Filter overdue tickets on frontend
const overdue = result.data.filter(ticket => {
  return ticket.due_date && 
         new Date(ticket.due_date) < new Date() && 
         ticket.status !== 'closed'
})
```

### Example 6: Error Handling

```javascript
// Frontend code
try {
  const response = await fetch('/api/tickets', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      subject: 'Test',
      description: 'Test',
      status: 'resolved'  // ❌ Invalid status
    })
  })

  if (response.status === 400) {
    const error = await response.json()
    console.error(`Error: ${error.message}`)
    // Output: "Error: Invalid request data"
  }
} catch (err) {
  console.error('Network error:', err)
}
```

---

## Rate Limiting

- **Limit:** 100 requests per minute per IP
- **Response on limit exceeded:** 429 Too Many Requests
- **Headers:** Look for `X-RateLimit-*` headers in response

---

## Authentication

Optional authentication with Bearer token:

```http
Authorization: Bearer <jwt_token>

// Example
GET /api/tickets
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

For development testing:

```http
GET /api/test-token
// Returns { access_token, token_type, user }
```

---

## Changelog

### v2.0 (Current)
- **Breaking:** Reduced states from 5 to 3: `resolved` and `overdue` removed
- **New:** Added `resolution` field for closed tickets
- **New:** Added `due_date` field for ticket deadlines
- **Changed:** Overdue logic moved to frontend calculation

### v1.0
- Initial API contract
- 5 states: open, in_progress, closed, resolved, overdue

---

## Support

For API questions or issues:
- Check validation rules in this contract
- Review error response format
- Test with included examples
- Check HTTP status codes

---

**Last Updated:** February 6, 2026  
**Version:** 2.0  
**Stable:** ✅
