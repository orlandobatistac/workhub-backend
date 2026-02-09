# Frontend Integration Guide

Guía de integración del frontend con el backend unificado. Este documento detalla los flujos de usuario, formularios, estados y endpoints para el MVP.

---

## 1. Autenticación

### Login unificado

**Ruta:** `/login`

**Formulario:**
```
┌─────────────────────────────────────┐
│ Login                               │
├─────────────────────────────────────┤
│ Usuario/Email: [____________]       │
│ Password: [____________]            │
│                                     │
│          [Iniciar Sesión]           │
└─────────────────────────────────────┘
```

**Endpoint:**
```http
POST /api/auth/login
Content-Type: application/json

{
  "username_or_email": "admin@example.com",
  "password": "password123"
}
```

**Response:**
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbG...",
  "token_type": "bearer",
  "user": {
    "id": 1,
    "email": "admin@example.com",
    "full_name": "Admin User",
    "username": "admin",
    "user_type": "admin",
    "workgroup_id": null,
    "primary_branch_id": null
  }
}
```

**Redirección automática:**
```javascript
switch(user.user_type) {
  case 'admin':
    redirect('/admin/dashboard')
    break
  case 'agent':
    redirect('/agent/dashboard')
    break
  case 'contact':
    redirect('/portal/dashboard')
    break
}
```

---

## 2. Rutas y permisos

### Estructura de rutas

```
/login                     → Público
/admin/*                   → Solo admin
/agent/*                   → Solo agent
/portal/*                  → Solo contact
```

### Middleware de permisos

```javascript
// Protección por ruta
const routes = {
  '/admin/*': ['admin'],
  '/agent/*': ['agent'],
  '/portal/*': ['contact']
}

// Verificar acceso
if (!routes[currentRoute].includes(user.user_type)) {
  redirect('/unauthorized')
}
```

---

## 3. Estados de tickets

### Enums

```javascript
const TicketStatus = {
  NEW: 'new',         // 🟢 Verde - Recién creado
  OPEN: 'open',       // 🔵 Azul - Agent interactuando
  CLOSED: 'closed'    // ⚫ Gris - Finalizado
}

const TicketPriority = {
  LOW: 'low',
  MEDIUM: 'medium',
  HIGH: 'high',
  URGENT: 'urgent'
}
```

### Enums oficiales ✅

Estos valores son los *oficiales y autorizados* para el contrato entre el backend y el nuevo frontend (documentado aquí). Usarlos exactamente como se muestran en todas las llamadas API, validaciones y vistas.

- Status (campo `status` en `Ticket`): `new`, `open`, `closed`
- Priorities (campo `priority` en `Ticket`): `low`, `medium`, `high`, `urgent`

> Nota: el backend **valida** estos valores en `app/schemas.py` y los scripts de seed ya generan datos con estos enums.

### Badge colors

```css
/* Status badges */
.badge-new {
  background: #22c55e; /* Verde */
  color: white;
}

.badge-open {
  background: #3b82f6; /* Azul */
  color: white;
}

.badge-closed {
  background: #6b7280; /* Gris */
  color: white;
}

/* Filter badges */
.badge-filter-new {
  background: #22c55e; /* Verde */
}

.badge-filter-my-tickets {
  background: #3b82f6; /* Azul */
}

.badge-filter-unassigned {
  background: #9ca3af; /* Gris claro */
}
```

---

## 4. SLA (Service Level Agreement)

### Tiempos límite por prioridad (hardcoded)

```python
PRIORITY_SLA_DAYS = {
    "low": 7,      # 7 días
    "medium": 5,   # 5 días
    "high": 3,     # 3 días
    "urgent": 1    # 1 día
}
```

### Cálculo automático

```javascript
// Backend calcula al crear ticket:
due_date = created_at + PRIORITY_SLA_DAYS[priority]

// Frontend muestra tiempo restante:
const daysRemaining = Math.ceil((ticket.due_date - Date.now()) / (1000 * 60 * 60 * 24))

// Colores según días restantes:
const getDueDateColor = (daysRemaining) => {
  if (daysRemaining > 2) return 'green'   // 🟢 >2 días
  if (daysRemaining >= 1) return 'yellow' // 🟡 1-2 días
  return 'red'                            // 🔴 <1 día o vencido
}
```

---

## 5. Formularios de creación de tickets

### 5.1. Contact - `/portal/tickets/new`

**Formulario:**
```
┌─────────────────────────────────────┐
│ Crear Ticket                        │
├─────────────────────────────────────┤
│ Branch: [Main Office]        🔒     │  ← Auto (current_user.primary_branch_id), disabled
│ Contact: [Juan Pérez]        🔒     │  ← Auto (current_user.full_name), disabled
│                                     │
│ Subject: [____________]             │  ← Editable, requerido
│ Description: [____________]         │  ← Editable, requerido
│ Attachments: [Seleccionar...] 📎    │  ← Opcional, múltiples archivos
│                                     │
│ Priority: [Low ▼]                   │  ← Editable (Low, Medium, High, Urgent)
│ Workgroup: [Soporte Técnico ▼]     │  ← Editable, requerido, dropdown de workgroups
│                                     │
│          [Crear Ticket]             │
└─────────────────────────────────────┘
```

**Lógica frontend:**
```javascript
const defaultValues = {
  branch_id: currentUser.primary_branch_id,
  contact_id: currentUser.id,
  priority: 'low',
  // workgroup_id: usuario selecciona
}

// Campos ocultos/disabled:
// - branch_id (disabled)
// - contact_id (disabled)
// - assignee_id (no visible para contact)
// - status (siempre "new" al crear)
```

**Endpoint:**
```http
POST /api/tickets
Content-Type: multipart/form-data
Authorization: Bearer {token}

Fields:
- subject (string)
- description (string)
- priority (string)
- workgroup_id (optional)
- assignee_id (optional)
- attachments: one or more files (multipart field name `attachments`)
```

**Behavior:** This endpoint accepts either JSON (existing behavior) or multipart/form-data. When the request includes a `description`, the backend will always create a `first_message` whose `content` is the ticket `description`. If files are uploaded (multipart), those files are stored and attached to the `first_message`. Attachment validation enforces a maximum of **5 files** and **10MB** per file. When a `first_message` is created, the response includes both the created `ticket` and the `first_message` with attachment metadata and downloadable `url`.

**Response:**
```json
{
  "ticket": {
    "id": "ticket-123",
    "subject": "Sistema lento",
    "description": "Desde ayer el sistema está muy lento",
    "priority": "medium",
    "status": "new",
    "branch_id": "branch-main",
    "workgroup_id": "wg-soporte-tecnico",
    "assignee_id": null,
    "contact_id": 5,
    "due_date": "2026-02-12T10:00:00Z",
    "created_by_id": 5,
    "created_at": "2026-02-07T10:00:00Z",
    "updated_at": "2026-02-07T10:00:00Z"
  },
  "first_message": {
    "id": "msg-456",
    "ticket_id": "ticket-123",
    "sender_id": 5,
    "sender_type": "contact",
    "content": "Desde ayer el sistema está muy lento",
    "attachments": [
      {
        "path": "uploads/messages/msg-456/abcd123_screenshot.png",
        "url": "/api/attachments/messages/uploads%2Fmessages%2Fmsg-456%2Fabcd123_screenshot.png",
        "name": "screenshot.png",
        "type": "image/png",
        "size": 1234567
      }
    ],
    "created_at": "2026-02-07T10:00:00Z"
  }
}
```

---

### 5.2. Agent/Admin - `/agent/tickets/new` o `/admin/tickets/new`

**Formulario:**
```
┌─────────────────────────────────────┐
│ Crear Ticket                        │
├─────────────────────────────────────┤
│ Branch: [Seleccionar ▼]             │  ← Editable, dropdown de branches
│ Contact: [Buscar cliente...]        │  ← Editable, búsqueda de contacts
│                                     │
│ Subject: [____________]             │
│ Description: [____________]         │
│ Attachments: [Seleccionar...] 📎    │
│                                     │
│ Priority: [Low ▼]                   │
│ Workgroup: [Soporte Técnico ▼]     │  ← Condicional (ver lógica abajo)
│ Assignee: [Unassigned ▼]            │  ← Condicional (ver lógica abajo)
│                                     │
│          [Crear Ticket]             │
└─────────────────────────────────────┘
```

**Lógica condicional de Workgroup/Assignee:**

```javascript
// Estado inicial
const [workgroupId, setWorkgroupId] = useState(null)
const [assigneeId, setAssigneeId] = useState(null)
const [workgroupDisabled, setWorkgroupDisabled] = useState(false)
const [assigneeDisabled, setAssigneeDisabled] = useState(false)

// Cuando selecciona Workgroup:
const onWorkgroupChange = (wgId) => {
  setWorkgroupId(wgId)
  setAssigneeId(null)              // Resetea assignee
  setAssigneeDisabled(true)        // Deshabilita assignee
  // Assignee muestra "Unassigned" (disabled)
}

// Cuando selecciona Assignee:
const onAssigneeChange = (agentId) => {
  if (agentId) {
    // Buscar el agent seleccionado
    const agent = agents.find(a => a.id === agentId)

    if (agent.user_type === 'agent') {
      // Si es agent, tomar su workgroup
      setWorkgroupId(agent.workgroup_id)
      setWorkgroupDisabled(true)     // Deshabilita workgroup
    } else if (agent.user_type === 'admin') {
      // Si es admin, dejar workgroup disabled sin valor o "General"
      setWorkgroupId(null) // o "general"
      setWorkgroupDisabled(true)
    }

    setAssigneeId(agentId)
  } else {
    // Si deselecciona assignee
    setAssigneeId(null)
    setWorkgroupDisabled(false)
    // Puede volver a seleccionar workgroup
  }
}

// Resetear todo:
const onReset = () => {
  setWorkgroupId(null)
  setAssigneeId(null)
  setWorkgroupDisabled(false)
  setAssigneeDisabled(false)
}
```

**Reglas de seguridad:**
1. Si selecciona **Workgroup** → **Assignee** se deshabilita con valor "Unassigned"
2. Si selecciona **Assignee (agent)** → **Workgroup** se deshabilita y toma el workgroup del agent
3. Si selecciona **Assignee (admin)** → **Workgroup** se deshabilita con valor null o "General"
4. Si deselecciona uno, el otro se habilita nuevamente

**Endpoint:**
```http
POST /api/tickets
Content-Type: multipart/form-data
Authorization: Bearer {token}

{
  "branch_id": "branch-main",
  "contact_id": 5,
  "subject": "Problema urgente",
  "description": "...",
  "priority": "high",
  "workgroup_id": "wg-soporte-tecnico",  // O null si asignó directo a admin
  "assignee_id": null,  // O ID del agent/admin si lo asignó directo
  "attachments": [...]
}
```

---

## 6. Flujos por tipo de usuario

### 6.1. CONTACT - Portal de cliente

**Dashboard:** `/portal/dashboard`

**Vistas principales:**
- `/portal/tickets` → Mis tickets
- `/portal/tickets/new` → Crear ticket
- `/portal/tickets/:id` → Ver/responder ticket
- `/portal/profile` → Mi perfil

**Flujo típico:**

```
1. Contact login → /portal/dashboard

2. Click "Nuevo Ticket" → /portal/tickets/new

3. Completa formulario:
   - Branch: [Main Office] 🔒
   - Contact: [Juan Pérez] 🔒
   - Subject: "No puedo acceder"
   - Description: "Error al hacer login..."
   - Attachments: screenshot.png
   - Priority: Medium
   - Workgroup: "Soporte Técnico"

4. Submit → POST /api/tickets

5. Backend:
   - Crea ticket (status="new", assignee=null, due_date calculado)
   - Crea primer mensaje con description + attachments

6. Redirect → /portal/tickets/ticket-123

7. Ve su ticket + primer mensaje

8. Puede agregar mensajes desde el chat
```

**Lista de tickets:**
```
GET /api/tickets?contact_id={current_user.id}

┌─────────────────────────────────────┐
│ Mis Tickets                         │
├─────────────────────────────────────┤
│ ┌───────────────────────────────┐   │
│ │ 🟢 [#123] No puedo acceder    │   │
│ │    Medium · Vence en 3 días   │   │
│ └───────────────────────────────┘   │
│ ┌───────────────────────────────┐   │
│ │ 🔵 [#120] Problema resuelto   │   │
│ │    Low · Respondido           │   │
│ └───────────────────────────────┘   │
│ ┌───────────────────────────────┐   │
│ │ ⚫ [#115] Error en reporte    │   │
│ │    High · Cerrado             │   │
│ └───────────────────────────────┘   │
└─────────────────────────────────────┘
```

---

### 6.2. AGENT - Dashboard de soporte

**Dashboard:** `/agent/dashboard`

**Vistas principales:**
- `/agent/tickets` → Lista de tickets con filtros
- `/agent/tickets/:id` → Ver/responder ticket
- `/agent/tickets/new` → Crear ticket para un cliente
- `/agent/profile` → Mi perfil

**Filtros de tickets:**

```
GET /api/tickets?filters

┌─────────────────────────────────────┐
│ Tickets                             │
├─────────────────────────────────────┤
│ Filtros:                            │
│ 🟢 New         → 5 tickets          │
│ 🔵 My Tickets  → 3 tickets          │
│ ⚪ Unassigned  → 8 tickets          │
└─────────────────────────────────────┘
```

**Queries por filtro:**

```http
# 🟢 New tickets (del workgroup del agent)
GET /api/tickets?status=new&workgroup_id={current_user.workgroup_id}

# 🔵 My tickets (asignados a mí)
GET /api/tickets?assignee_id={current_user.id}

# ⚪ Unassigned (sin asignar, del workgroup)
GET /api/tickets?assignee_id=null&workgroup_id={current_user.workgroup_id}
```

**Flujo: Agent toma ticket y responde**

```
1. Agent login → /agent/tickets

2. Ve filtro 🟢 New → 5 tickets del workgroup

3. Click en ticket #123 → /agent/tickets/123

4. Ve:
   - Subject, priority, due_date
   - Primer mensaje del contact con attachments
   - Status: "new"

5. Agent escribe respuesta:
   "Hola, estamos revisando tu acceso. Por favor intenta..."
   [Adjunta: guia.pdf]

6. Submit → POST /api/tickets/123/messages

7. Backend automático:
   a) Crea mensaje (sender_id=agent.id, sender_type="agent")
   b) Actualiza ticket:
      - status: "new" → "open"
      - assignee_id: null → agent.id
      - updated_at: now()

8. Ticket ahora aparece en 🔵 My Tickets

9. Contact recibe notificación
```

**Vista detalle de ticket:**
```
GET /api/tickets/{id}
GET /api/tickets/{id}/messages

┌─────────────────────────────────────┐
│ Ticket #123                         │
│ No puedo acceder al sistema         │
├─────────────────────────────────────┤
│ Status: 🟢 New                      │
│ Priority: Medium                    │
│ Vence: 3 días (🟢)                  │
│ Workgroup: Soporte Técnico          │
│ Assignee: Unassigned                │
├─────────────────────────────────────┤
│ Conversación:                       │
│ ┌───────────────────────────────┐   │
│ │ Juan Pérez (Contact)          │   │
│ │ 10:00 AM                      │   │
│ │ Desde esta mañana no puedo... │   │
│ │ 📎 screenshot.png             │   │
│ └───────────────────────────────┘   │
├─────────────────────────────────────┤
│ Responder:                          │
│ [___________________________]       │
│ 📎 Adjuntar         [Enviar]        │
├─────────────────────────────────────┤
│ Acciones:                           │
│ [Tomar Ticket] [Cambiar Priority]   │
│ [Cerrar Ticket]                     │
└─────────────────────────────────────┘
```

---

### 6.3. ADMIN - Dashboard administrativo

**Dashboard:** `/admin/dashboard`

**Vistas principales:**
- `/admin/users` → Gestionar admins y agents
- `/admin/customers` → Ver/gestionar contacts
- `/admin/branches` → Gestionar sucursales
- `/admin/workgroups` → Gestionar equipos
- `/admin/tickets` → Ver todos los tickets
- `/admin/settings` → Configuración del sistema

**Permisos:**
- CRUD completo de users (cualquier tipo)
- CRUD completo de branches, workgroups
- Asignar agents a workgroups
- Ver/editar todos los tickets
- Acceso a analytics y reportes

**Endpoints clave:**

```http
# Gestión de usuarios
GET /api/users/team → Admins y Agents
GET /api/users/customers → Contacts
POST /api/users → Crear usuario
PATCH /api/users/{id} → Editar usuario
DELETE /api/users/{id} → Eliminar usuario

# Gestión de recursos
GET /api/branches
POST /api/branches
GET /api/workgroups
POST /api/workgroups

# Todos los tickets
GET /api/tickets → Sin filtros de workgroup
```

---

## 7. Gestión de mensajes

### 7.1. Crear mensaje

**Endpoint:**
```http
POST /api/tickets/{ticket_id}/messages
Content-Type: multipart/form-data
Authorization: Bearer {token}

{
  "content": "Hola, estamos revisando tu solicitud...",
  "attachments": [File, File, ...]
}
```

**Response:**
```json
{
  "message": {
    "id": "msg-789",
    "ticket_id": "ticket-123",
    "sender_id": 2,
    "sender_type": "agent",
    "content": "Hola, estamos revisando tu solicitud...",
    "attachments": [
      {
        "name": "guia.pdf",
        "url": "/uploads/guia.pdf",
        "size": 456789
      }
    ],
    "created_at": "2026-02-07T11:30:00Z"
  },
  "ticket_updated": {
    "status": "open",
    "assignee_id": 2,
    "updated_at": "2026-02-07T11:30:00Z"
  }
}
```

**Backend automático:**
```python
# Al crear mensaje por primera vez (si es agent):
if ticket.status == "new" and sender.user_type == "agent":
    ticket.status = "open"
    if ticket.assignee_id is None:
        ticket.assignee_id = sender.id
    ticket.updated_at = now()
```

---

### 7.2. Listar mensajes

**Endpoint:**
```http
GET /api/tickets/{ticket_id}/messages
Authorization: Bearer {token}
```

**Response:**
```json
{
  "messages": [
    {
      "id": "msg-456",
      "ticket_id": "ticket-123",
      "sender_id": 5,
      "sender_type": "contact",
      "sender_name": "Juan Pérez",
      "content": "Desde ayer el sistema está muy lento",
      "attachments": [
        {
          "name": "screenshot.png",
          "url": "/uploads/screenshot.png",
          "size": 1234567
        }
      ],
      "created_at": "2026-02-07T10:00:00Z"
    },
    {
      "id": "msg-789",
      "ticket_id": "ticket-123",
      "sender_id": 2,
      "sender_type": "agent",
      "sender_name": "María García",
      "content": "Hola, estamos revisando tu solicitud...",
      "attachments": [],
      "created_at": "2026-02-07T11:30:00Z"
    }
  ]
}
```

---

## 8. Endpoints principales

### 8.1. Autenticación

```http
POST /api/auth/login
POST /api/auth/logout
POST /api/auth/refresh
GET /api/auth/me
```

---

### 8.2. Users

```http
# Listar usuarios
GET /api/users/team           # Admin y Agents
GET /api/users/customers      # Contacts
GET /api/users                # Todos (admin only)

# CRUD
GET /api/users/{id}
POST /api/users
PATCH /api/users/{id}
DELETE /api/users/{id}
```

---

### 8.3. Tickets

```http
# Listar con filtros
GET /api/tickets?status=new
GET /api/tickets?assignee_id={id}
GET /api/tickets?contact_id={id}
GET /api/tickets?workgroup_id={id}
GET /api/tickets?priority=high

# CRUD
GET /api/tickets/{id}
POST /api/tickets
PATCH /api/tickets/{id}
DELETE /api/tickets/{id}

# Acciones
PATCH /api/tickets/{id}/assign    # Asignar a agent
PATCH /api/tickets/{id}/close     # Cerrar ticket
```

---

### 8.4. Messages

```http
GET /api/tickets/{ticket_id}/messages
POST /api/tickets/{ticket_id}/messages
```

---

### 8.5. Branches

```http
GET /api/branches
GET /api/branches/{id}
POST /api/branches           # Admin only
PATCH /api/branches/{id}     # Admin only
DELETE /api/branches/{id}    # Admin only
```

---

### 8.6. Workgroups

```http
GET /api/workgroups
GET /api/workgroups/{id}
POST /api/workgroups         # Admin only
PATCH /api/workgroups/{id}   # Admin only
DELETE /api/workgroups/{id}  # Admin only
```

---

## 9. Componentes frontend sugeridos

### 9.1. Componente TicketCard

```jsx
<TicketCard
  ticket={ticket}
  showStatus={true}
  showDueDate={true}
  onClick={() => navigate(`/tickets/${ticket.id}`)}
/>

// Renderiza:
// 🟢 [#123] No puedo acceder
//    Medium · Vence en 3 días
```

---

### 9.2. Componente MessageThread

```jsx
<MessageThread
  messages={messages}
  currentUserId={user.id}
  onSendMessage={(content, files) => {
    // POST /api/tickets/{id}/messages
  }}
/>

// Renderiza chat estilo WhatsApp/Slack
```

---

### 9.3. Componente TicketFilters

```jsx
<TicketFilters
  filters={['new', 'my_tickets', 'unassigned']}
  counts={{ new: 5, my_tickets: 3, unassigned: 8 }}
  activeFilter="new"
  onFilterChange={(filter) => {
    // Actualiza query y recarga tickets
  }}
/>
```

---

### 9.4. Componente DueDateBadge

```jsx
<DueDateBadge dueDate={ticket.due_date} />

// Muestra:
// 🟢 Vence en 5 días
// 🟡 Vence en 1 día
// 🔴 Vencido hace 2 días
```

---

## 10. Notas de implementación

### 10.1. Primer mensaje automático

Al crear un ticket, el backend debe:
1. Crear el registro del ticket
2. Crear automáticamente el primer mensaje con:
   - `content` = ticket.description
   - `attachments` = archivos subidos
   - `sender_id` = ticket.created_by_id
   - `sender_type` = user que creó el ticket

Esto asegura que siempre haya al menos un mensaje en la conversación.

---

### 10.2. Auto-asignación de tickets

Cuando un agent responde por primera vez a un ticket con `status="new"`:
1. Backend cambia `status` a "open"
2. Backend asigna `assignee_id` = agent que respondió
3. Ticket aparece en 🔵 My Tickets del agent

---

### 10.3. Cálculo de due_date

```python
from datetime import datetime, timedelta

PRIORITY_SLA_DAYS = {
    "low": 7,
    "medium": 5,
    "high": 3,
    "urgent": 1
}

def calculate_due_date(priority: str, created_at: datetime) -> datetime:
    days = PRIORITY_SLA_DAYS.get(priority, 7)
    return created_at + timedelta(days=days)
```

---

### 10.4. Upload de archivos

**Storage recomendado:**
- Desarrollo: Local filesystem (`/uploads`)
- Producción: S3, CloudStorage, etc.

**Formato de attachments (JSON):**
```json
[
  {
    "name": "screenshot.png",
    "url": "/uploads/abc123-screenshot.png",
    "size": 1234567,
    "mime_type": "image/png"
  }
]
```

---

### 10.5. Validaciones frontend

**Crear ticket:**
- Subject: requerido, max 200 chars
- Description: requerido, max 2000 chars
- Priority: requerido, enum
- Workgroup: requerido (para contact)
- Attachments: max 5 archivos, max 10MB c/u

**Crear mensaje:**
- Content: requerido (si no hay attachments), max 2000 chars
- Attachments: max 5 archivos, max 10MB c/u

---

## 11. Casos de uso completos

### 11.1. Contact crea ticket y recibe respuesta

```
1. Contact login → /portal/dashboard
2. Click "Nuevo Ticket"
3. Completa:
   - Subject: "Error en exportación"
   - Description: "Al exportar a Excel me da error..."
   - Attachments: error.png
   - Priority: High
   - Workgroup: "Soporte Técnico"
4. Submit → Ticket creado (status="new", assignee=null)
5. Agent del workgroup ve ticket en 🟢 New
6. Agent abre ticket y responde
7. Backend auto-asigna ticket al agent (status="open")
8. Contact recibe notificación
9. Contact abre ticket y ve respuesta
10. Contact responde de vuelta
11. Conversación continúa hasta resolver
12. Agent cierra ticket (status="closed")
```

---

### 11.2. Agent crea ticket para cliente

```
1. Agent login → /agent/dashboard
2. Click "Crear Ticket"
3. Completa:
   - Branch: "Sucursal Norte"
   - Contact: "María López" (busca)
   - Subject: "Solicitud de reporte"
   - Description: "Cliente solicitó reporte mensual..."
   - Priority: Low
   - Workgroup: "Reportes" (selecciona)
   - Assignee: Unassigned (disabled)
4. Submit → Ticket creado para el cliente
5. Agents del workgroup "Reportes" ven ticket en 🟢 New
6. Cualquier agent puede tomarlo
```

---

### 11.3. Admin asigna ticket directo a agent específico

```
1. Admin login → /admin/tickets
2. Click "Crear Ticket"
3. Completa:
   - Branch: "Main Office"
   - Contact: "Carlos Ruiz"
   - Subject: "VIP - Configuración urgente"
   - Description: "Cliente VIP necesita..."
   - Priority: Urgent
   - Assignee: "Juan Rodríguez" (agent específico)
   - Workgroup: [disabled] → Se toma del agent
4. Submit → Ticket creado y asignado directo
5. Agent "Juan Rodríguez" ve ticket inmediatamente en 🔵 My Tickets
```

---

## 12. Resumen de cambios clave

### Consolidación de usuarios
- ✅ Una sola tabla `users` con `user_type`
- ✅ Eliminadas tablas `agents` y `contacts`
- ✅ Email único en todo el sistema

### Tickets mejorados
- ✅ Campo `workgroup_id` agregado
- ✅ Status default: "new" (no "open")
- ✅ Primer mensaje automático con description + attachments
- ✅ SLA automático por priority

### Formularios simplificados
- ✅ Contact: solo ve Workgroup (no Assignee)
- ✅ Agent/Admin: lógica condicional Workgroup ↔ Assignee
- ✅ Status no editable al crear (siempre "new")

### Auto-asignación inteligente
- ✅ Agent responde → ticket se asigna automáticamente
- ✅ Status cambia de "new" a "open"

---

## Apéndice: Ejemplos de queries

### Filtros para agent dashboard

```sql
-- 🟢 New tickets
SELECT * FROM tickets
WHERE status = 'new'
  AND workgroup_id = 'wg-agent-workgroup'
ORDER BY created_at DESC;

-- 🔵 My tickets
SELECT * FROM tickets
WHERE assignee_id = 123
ORDER BY updated_at DESC;

-- ⚪ Unassigned
SELECT * FROM tickets
WHERE assignee_id IS NULL
  AND workgroup_id = 'wg-agent-workgroup'
ORDER BY created_at DESC;
```

### Tickets por vencer

```sql
SELECT * FROM tickets
WHERE status IN ('new', 'open')
  AND due_date <= NOW() + INTERVAL '1 day'
ORDER BY due_date ASC;
```

---

**Fin del documento de integración**
