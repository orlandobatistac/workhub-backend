# Role-Based Access Control (RBAC) Implementation

## Overview
This document describes the implementation of Role-Based Access Control (RBAC) for the WorkHub backend API, specifically for ticket management.

## Phase 1 & 2 Implementation Complete ✅

### Changes Made

#### 1. Database Schema Updates

**TicketModel** - Added new field:
```python
created_by_id = Column(Integer, nullable=True)  # User ID who created the ticket
```

**Migration Required:**
- Run `python migrate_add_created_by.py` to add the column to existing database
- Or delete `workhub.db` and restart the server to recreate with new schema

#### 2. Permission System

Added four permission helper functions:

**`require_admin(current_user)`**
- Ensures the current user is an admin
- Raises 403 Forbidden if not admin

**`require_agent_or_admin(current_user)`**
- Ensures the current user is an agent or admin
- Raises 403 Forbidden if regular user

**`can_access_ticket(ticket, current_user)`**
- Returns `True` if user can view the ticket
- Admin/Agent: can access all tickets
- User: can only access their own tickets (created_by_id match)

**`can_modify_ticket(ticket, current_user)`**
- Returns `True` if user can modify the ticket
- Admin: can modify all tickets
- Agent: can modify all tickets
- User: can only modify their own tickets (created_by_id match)

#### 3. Endpoint Security

All ticket endpoints now require authentication and enforce role-based permissions:

**POST `/api/tickets`**
- ✅ Requires authentication
- ✅ Automatically assigns `created_by_id` to authenticated user
- All roles can create tickets

**GET `/api/tickets`**
- ✅ Requires authentication
- ✅ Filters results by role:
  - **Users**: only see their own tickets
  - **Agents/Admins**: see all tickets

**GET `/api/tickets/{ticket_id}`**
- ✅ Requires authentication
- ✅ Validates access using `can_access_ticket()`
- Returns 403 if user tries to access someone else's ticket

**PUT `/api/tickets/{ticket_id}`**
- ✅ Requires authentication
- ✅ Validates modification rights using `can_modify_ticket()`
- Returns 403 if user tries to modify someone else's ticket

**DELETE `/api/tickets/{ticket_id}`**
- ✅ Requires authentication
- ✅ Validates modification rights using `can_modify_ticket()`
- Returns 403 if user tries to delete someone else's ticket

#### 4. Seed Data Updates

Updated seed data to create demo users:
- **admin** (password: `admin123`) - role: admin
- **agent1** (password: `agent123`) - role: agent
- **agent2** (password: `agent123`) - role: agent
- **user1** (password: `user123`) - role: user
- **user2** (password: `user123`) - role: user

All seeded tickets are automatically assigned to users in rotation.

## Permission Matrix

| Action | User | Agent | Admin |
|--------|------|-------|-------|
| Create ticket | ✅ | ✅ | ✅ |
| View own tickets | ✅ | ✅ | ✅ |
| View all tickets | ❌ | ✅ | ✅ |
| Edit own tickets | ✅ | ✅ | ✅ |
| Edit all tickets | ❌ | ✅ | ✅ |
| Delete own tickets | ✅ | ✅ | ✅ |
| Delete all tickets | ❌ | ✅ | ✅ |
| Send messages (own tickets) | ✅ | ✅ | ✅ |
| Send messages (all tickets) | ❌ | ✅ | ✅ |
| User management | ❌ | ❌ | ✅ (Phase 3) |

## How to Test

### 1. Reset Database and Seed Data

```bash
# Option A: Delete database and restart server
rm workhub.db
# Server will recreate database on startup

# Option B: Run migration on existing database
python migrate_add_created_by.py
```

### 2. Seed Demo Data

```bash
curl -X POST "http://localhost:8000/api/seed"
```

### 3. Login as Different Users

**Login as User:**
```bash
curl -X POST "http://localhost:8000/api/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "user1", "password": "user123"}'
```

**Login as Agent:**
```bash
curl -X POST "http://localhost:8000/api/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "agent1", "password": "agent123"}'
```

**Login as Admin:**
```bash
curl -X POST "http://localhost:8000/api/token" \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "admin123"}'
```

### 4. Test Ticket Access

**Create a ticket (as user1):**
```bash
TOKEN="<user1_token>"

curl -X POST "http://localhost:8000/api/tickets" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Test Ticket",
    "description": "Testing RBAC",
    "priority": "medium",
    "status": "open"
  }'
```

**List tickets (as user1):**
```bash
# Should only see tickets created by user1
curl -X GET "http://localhost:8000/api/tickets" \
  -H "Authorization: Bearer $TOKEN"
```

**List tickets (as agent1):**
```bash
# Should see ALL tickets
curl -X GET "http://localhost:8000/api/tickets" \
  -H "Authorization: Bearer $AGENT_TOKEN"
```

**Try to access another user's ticket (as user1):**
```bash
# Should get 403 Forbidden
curl -X GET "http://localhost:8000/api/tickets/<another_user_ticket_id>" \
  -H "Authorization: Bearer $TOKEN"
```

## Error Responses

**401 Unauthorized** - No authentication provided
```json
{
  "detail": "Authentication required"
}
```

**403 Forbidden** - Insufficient permissions
```json
{
  "detail": "Access denied: You can only view your own tickets"
}
```

## Next Steps (Phase 3)

The following features are planned for Phase 3:
- ✅ User management endpoints (Admin only)
  - `GET /api/users` - List users
  - `GET /api/users/{user_id}` - Get user details
  - `PUT /api/users/{user_id}` - Update user (change role, etc.)
  - `DELETE /api/users/{user_id}` - Delete user
- ✅ Frontend admin panel
- ✅ Protected routes in UI
- ✅ Role-based UI components

## API Documentation Updates

All ticket endpoints now require authentication:
- Add `Authorization: Bearer <token>` header to all requests
- Obtain token via `POST /api/token` with `{username, password}`

## Breaking Changes

⚠️ **Breaking Changes:**
- All ticket endpoints now require authentication (previously optional)
- Users can only see/modify their own tickets (previously unrestricted)
- `created_by_id` field added to all ticket responses

## Migration Notes

For existing tickets without `created_by_id`:
1. They will have `created_by_id = null`
2. Only admins and agents can access these tickets
3. Regular users cannot see null-owner tickets
4. Consider assigning them to a default user or admin

## Technical Details

**Authentication:**
- Uses JWT Bearer tokens
- Token obtained via `POST /api/token`
- Token contains user ID and role

**Database:**
- SQLite3
- SQLAlchemy ORM
- created_by_id is Integer foreign key to users.id

**Performance:**
- Database indexes on created_by_id recommended for large datasets
- Query filtering happens at database level (efficient)
