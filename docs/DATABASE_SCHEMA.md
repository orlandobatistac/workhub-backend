# Database Schema

## `users`
- `id` (int, PK)
- `username` (string, unique, index)
- `email` (string, unique, index)
- `full_name` (string)
- `hashed_password` (string)
- `role` (string, default="user")
- `is_active` (bool, default=True)
- `created_at` (datetime)

---

## `audit_logs`
- `id` (int, PK)
- `user_id` (int, nullable)
- `username` (string)
- `action` (string)
- `resource` (string)
- `resource_id` (string, nullable)
- `details` (text, nullable)
- `status` (string)
- `ip_address` (string, nullable)
- `timestamp` (datetime)

---

## `branches`
- `id` (string, PK)
- `branch_code` (string, unique, index)
- `name` (string, index)
- `address` (string)
- `status` (string, default="active")
- `created_at` (datetime)

---

## `agents`
- `id` (string, PK)
- `agent_id` (string, unique, index)
- `name` (string, index)
- `role` (string, default="Agent")
- `workgroup_id` (string, nullable)
- `external_id` (string, nullable)
- `created_at` (datetime)

---

## `workgroups`
- `id` (string, PK)
- `name` (string, index)
- `description` (string)
- `created_at` (datetime)

---

## `contacts`
- `id` (string, PK)
- `contact_id` (string, unique, index)
- `name` (string, index)
- `email` (string, nullable, index)
- `phone` (string, nullable)
- `primary_branch_id` (string)
- `external_id` (string, nullable)
- `created_at` (datetime)

---

## `tickets`
- `id` (string, PK)
- `subject` (string, index)
- `description` (string)
- `priority` (string, default="medium")
- `status` (string, default="open")
- `resolution` (string, nullable)
- `branch_id` (string, nullable)
- `assignee_agent_id` (string, nullable)
- `contact_id` (string, nullable)
- `due_date` (datetime, nullable)
- `created_by_id` (int, nullable)
- `created_at` (datetime)
- `updated_at` (datetime)

---

## `messages`
- `id` (string, PK)
- `ticket_id` (string, index)
- `sender_name` (string)
- `sender_type` (string)
- `content` (string)
- `attachments` (text, nullable)
- `created_at` (datetime)
