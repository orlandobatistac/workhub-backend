# Database Schema

## `users`
Tabla unificada para todos los tipos de usuarios del sistema.

- `id` (int, PK, auto-increment)
- `email` (string, unique, index)
- `full_name` (string, index)
- `username` (string, unique, nullable, index) - NULL para contacts
- `hashed_password` (string)
- `user_type` (enum: 'admin', 'agent', 'contact')
- `phone` (string, nullable)
- `is_active` (bool, default=True)
- `workgroup_id` (string, nullable, FK→workgroups) - Solo para agents
- `primary_branch_id` (string, nullable, FK→branches) - Solo para contacts
- `external_id` (string, nullable)
- `created_at` (datetime)

### Reglas por tipo de usuario:
- **admin**: email + username + full_name + password
- **agent**: email + username + full_name + password + workgroup_id
- **contact**: email + full_name + password + primary_branch_id

### Autenticación:
- Login por username → admin, agent
- Login por email → admin, agent, contact

---

## `audit_logs`
- `id` (int, PK)
- `user_id` (int, nullable, FK→users)
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

## `workgroups`
- `id` (string, PK)
- `name` (string, index)
- `description` (string)
- `created_at` (datetime)

---

## `tickets`
- `id` (string, PK)
- `subject` (string, index)
- `description` (string)
- `priority` (string, default="medium")
- `status` (string, default="new")
- `resolution` (string, nullable)
- `branch_id` (string, nullable, FK→branches)
- `workgroup_id` (string, nullable, FK→workgroups)
- `assignee_id` (int, nullable, FK→users) - user_type='agent'
- `contact_id` (int, nullable, FK→users) - user_type='contact'
- `due_date` (datetime, nullable)
- `created_by_id` (int, nullable, FK→users)
- `created_at` (datetime)
- `updated_at` (datetime)

---

## `messages`
- `id` (string, PK)
- `ticket_id` (string, index, FK→tickets)
- `sender_id` (int, FK→users)
- `sender_type` (string) - 'admin', 'agent', 'contact'
- `content` (string)
- `attachments` (text, nullable)
- `created_at` (datetime)

---

## Tablas eliminadas (consolidadas en `users`)
- ~~`agents`~~ → Ahora son users con user_type='agent'
- ~~`contacts`~~ → Ahora son users con user_type='contact'

---

## Notas de implementación

### Backend Enum:
```python
class UserType(str, Enum):
    ADMIN = "admin"
    AGENT = "agent"
    CONTACT = "contact"
```

### Endpoints sugeridos:
- `GET /api/users/team` → Filtra user_type IN ['admin', 'agent']
- `GET /api/users/customers` → Filtra user_type='contact'
- `GET /api/users` → Todos los usuarios (admin only)

### Validaciones:
- `workgroup_id` requerido si user_type='agent'
- `primary_branch_id` requerido si user_type='contact'
- `username` requerido si user_type IN ['admin', 'agent']
- `email` requerido (todos los tipos)
- `full_name` requerido (todos los tipos)
