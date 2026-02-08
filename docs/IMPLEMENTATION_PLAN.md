# Plan de Implementación: Backend MVP WorkHub

**Estado:** En Desarrollo
**Versión:** 1.0
**Fecha:** 2026-02-07

---

## Resumen Ejecutivo

Refactorizar el backend existente para alinearlo con el esquema DB unificado y los endpoints que espera el frontend. Se elimina la migración de datos por no haber datos de producción.

**Cambios críticos:**
1. Consolidar 3 tablas (`users`, `agents`, `contacts`) en una con `user_type` enum
2. Actualizar modelo de tickets (status default "new", agregar `workgroup_id`, SLA automático)
3. Implementar 5 endpoints esenciales
4. Auto-asignación de tickets cuando agent responde

---

## 5 Pasos de Implementación

### Paso 1: Modelos y Schemas
**Archivo:** `main.py` (líneas 201-302)

#### 1.1 Actualizar UserModel
```python
class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[Optional[str]] = mapped_column(String, unique=True, index=True, nullable=True)  # NULL para contacts
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String)
    hashed_password: Mapped[str] = mapped_column(String)
    user_type: Mapped[str] = mapped_column(String)  # 'admin', 'agent', 'contact'
    phone: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    workgroup_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Solo agents
    primary_branch_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # Solo contacts
    external_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    # created_at, no role
```

#### 1.2 Eliminar Tablas
- ❌ `AgentModel` (líneas 240-250)
- ❌ `ContactModel` (líneas 261-272)

#### 1.3 Actualizar TicketModel
```python
class TicketModel(Base):
    __tablename__ = "tickets"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    subject: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[str] = mapped_column(String)
    priority: Mapped[str] = mapped_column(String, default="medium")
    status: Mapped[str] = mapped_column(String, default="new")  # Cambiar de "open" a "new"
    resolution: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    branch_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    workgroup_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # NUEVO
    assignee_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Cambiar de assignee_agent_id
    contact_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # Cambiar FK a users
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
```

#### 1.4 Actualizar MessageModel
```python
class MessageModel(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    ticket_id: Mapped[str] = mapped_column(String, index=True)
    sender_id: Mapped[int] = mapped_column(Integer, nullable=True)  # NUEVO: FK users
    sender_type: Mapped[str] = mapped_column(String)  # 'admin', 'agent', 'contact'
    content: Mapped[str] = mapped_column(String)
    attachments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    # Eliminar sender_name
```

#### 1.5 Agregar UserType Enum
```python
from enum import Enum

class UserType(str, Enum):
    ADMIN = "admin"
    AGENT = "agent"
    CONTACT = "contact"
```

#### 1.6 Actualizar Schemas

**UserCreate:**
```python
class UserCreate(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=50)  # NULL para contacts
    email: str
    full_name: str
    password: str = Field(..., min_length=8)
    user_type: UserType
    phone: Optional[str] = None
    workgroup_id: Optional[str] = None  # Requerido si user_type='agent'
    primary_branch_id: Optional[str] = None  # Requerido si user_type='contact'
    external_id: Optional[str] = None

    @validator('workgroup_id')
    def validate_workgroup(cls, v, values):
        if values.get('user_type') == UserType.AGENT and not v:
            raise ValueError('workgroup_id requerido para agents')
        return v

    @validator('primary_branch_id')
    def validate_branch(cls, v, values):
        if values.get('user_type') == UserType.CONTACT and not v:
            raise ValueError('primary_branch_id requerido para contacts')
        return v

    @validator('username')
    def validate_username(cls, v, values):
        if values.get('user_type') in [UserType.ADMIN, UserType.AGENT] and not v:
            raise ValueError('username requerido para admin y agent')
        return v
```

**UserResponse:**
```python
class UserResponse(BaseModel):
    id: int
    username: Optional[str]
    email: str
    full_name: str
    user_type: str
    phone: Optional[str]
    is_active: bool
    workgroup_id: Optional[str]
    primary_branch_id: Optional[str]
    external_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
```

**LoginRequest:**
```python
class LoginRequest(BaseModel):
    username_or_email: str
    password: str
```

**TicketCreate:**
```python
class TicketCreate(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=5000)
    priority: str = Field(default="medium", pattern="^(low|medium|high|urgent)$")
    status: str = Field(default="new", pattern="^(new|open|closed)$")
    resolution: Optional[str] = None
    branch_id: Optional[str] = None
    workgroup_id: Optional[str] = None
    assignee_id: Optional[int] = None
    contact_id: Optional[int] = None
```

---

### Paso 2: Helpers y Constantes
**Archivo:** `main.py` (después de las configuraciones iniciales)

#### 2.1 Agregar SLA Constantes
```python
# SLA Configuration (después de línea 73)
PRIORITY_SLA_DAYS = {
    "urgent": 1,    # 1 día
    "high": 3,      # 3 días
    "medium": 5,    # 5 días
    "low": 7        # 7 días
}
```

#### 2.2 Agregar Función de Cálculo de SLA
```python
def calculate_due_date(priority: str, created_at: datetime) -> datetime:
    """Calcula la fecha de vencimiento basada en la SLA de prioridad."""
    days = PRIORITY_SLA_DAYS.get(priority, 7)
    return created_at + timedelta(days=days)
```

#### 2.3 Actualizar Helpers de Permisos

**require_admin():**
```python
def require_admin(current_user: Optional[UserModel]) -> UserModel:
    """Verifica que el usuario actual es admin."""
    if not current_user:
        raise HTTPException(status_code=403, detail="Admin access required")
    if current_user.user_type != "admin":  # Cambiar de 'role'
        raise HTTPException(status_code=403, detail="Admin access required")
    return current_user
```

**require_agent_or_admin():**
```python
def require_agent_or_admin(current_user: Optional[UserModel]) -> UserModel:
    """Verifica que el usuario actual es agent o admin."""
    if not current_user:
        raise HTTPException(status_code=403, detail="Agent or admin access required")
    if current_user.user_type not in ["admin", "agent"]:  # Cambiar de 'role'
        raise HTTPException(status_code=403, detail="Agent or admin access required")
    return current_user
```

**can_access_ticket():**
```python
def can_access_ticket(ticket: TicketModel, current_user: Optional[UserModel]) -> bool:
    """Verifica si el usuario actual puede acceder al ticket."""
    if not current_user:
        return False

    # Admin y agent pueden ver todos los tickets
    if current_user.user_type in ["admin", "agent"]:
        return True

    # Contact solo puede ver sus propios tickets
    if current_user.user_type == "contact":
        return ticket.contact_id == current_user.id

    return False
```

---

### Paso 3: Endpoints Nuevos
**Archivo:** `main.py`

#### 3.1 POST /api/auth/login
Reemplaza `/api/token`. Soporta login con username O email.

```python
@app.post("/api/auth/login", tags=["Authentication"])
@limiter.limit(RATE_LIMIT)
async def login(credentials: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login con username o email y obtener token JWT."""
    try:
        user = db.query(UserModel).filter(
            or_(
                UserModel.username == credentials.username_or_email,
                UserModel.email == credentials.username_or_email,
            )
        ).first()

        if not user or not verify_password(credentials.password, to_str(user.hashed_password)):
            log_audit(db, None, "LOGIN", "User", credentials.username_or_email, "FAILED", request.client.host)
            raise HTTPException(status_code=401, detail="Invalid credentials")

        if not user.is_active:
            raise HTTPException(status_code=401, detail="User inactive")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username or user.email},
            expires_delta=access_token_expires
        )

        log_audit(db, user.id, "LOGIN", "User", str(user.id), "SUCCESS", request.client.host)

        return {
            "access_token": access_token,
            "token_type": "bearer",
            "user": {
                "id": user.id,
                "email": user.email,
                "full_name": user.full_name,
                "username": user.username,
                "user_type": user.user_type,
                "workgroup_id": user.workgroup_id,
                "primary_branch_id": user.primary_branch_id
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        log_audit(db, None, "LOGIN", "User", credentials.username_or_email, "ERROR", request.client.host)
        raise HTTPException(status_code=500, detail="Login error")
```

#### 3.2 GET /api/users/team
Lista admins y agents.

```python
@app.get("/api/users/team", tags=["Users"])
@limiter.limit(RATE_LIMIT)
async def list_team_members(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Lista todos los admins y agents."""
    current_user = require_agent_or_admin(current_user)

    offset = (page - 1) * limit
    total = db.query(UserModel).filter(
        UserModel.user_type.in_(['admin', 'agent'])
    ).count()

    users = db.query(UserModel).filter(
        UserModel.user_type.in_(['admin', 'agent'])
    ).order_by(UserModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [
        {
            "id": u.id,
            "username": u.username,
            "email": u.email,
            "full_name": u.full_name,
            "user_type": u.user_type,
            "phone": u.phone,
            "workgroup_id": u.workgroup_id,
            "is_active": u.is_active,
            "created_at": u.created_at
        }
        for u in users
    ]

    log_audit(db, current_user.id, "READ", "User", None, "SUCCESS", request.client.host)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }
```

#### 3.3 GET /api/users/customers
Lista contacts (clientes).

```python
@app.get("/api/users/customers", tags=["Users"])
@limiter.limit(RATE_LIMIT)
async def list_customers(
    request: Request,
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Lista todos los contacts (clientes)."""
    current_user = require_agent_or_admin(current_user)

    offset = (page - 1) * limit
    total = db.query(UserModel).filter(
        UserModel.user_type == 'contact'
    ).count()

    users = db.query(UserModel).filter(
        UserModel.user_type == 'contact'
    ).order_by(UserModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [
        {
            "id": u.id,
            "email": u.email,
            "full_name": u.full_name,
            "user_type": u.user_type,
            "phone": u.phone,
            "primary_branch_id": u.primary_branch_id,
            "is_active": u.is_active,
            "created_at": u.created_at
        }
        for u in users
    ]

    log_audit(db, current_user.id, "READ", "User", None, "SUCCESS", request.client.host)

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }
```

#### 3.4 PATCH /api/tickets/{id}/assign
Asignar ticket a agent.

```python
@app.patch("/api/tickets/{ticket_id}/assign", tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def assign_ticket(
    ticket_id: str,
    assignee_id: int,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Asigna un ticket a un agent."""
    current_user = require_agent_or_admin(current_user)

    try:
        ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket no encontrado")

        # Verificar que assignee es agent o admin
        assignee = db.query(UserModel).filter(UserModel.id == assignee_id).first()
        if not assignee or assignee.user_type not in ['admin', 'agent']:
            raise HTTPException(status_code=400, detail="Assignee debe ser admin o agent")

        # Actualizar ticket
        ticket.assignee_id = assignee_id
        if ticket.status == "new":
            ticket.status = "open"
        ticket.updated_at = datetime.now(timezone.utc)

        # Si assignee es agent, copiar su workgroup_id
        if assignee.user_type == 'agent' and assignee.workgroup_id:
            ticket.workgroup_id = assignee.workgroup_id

        db.commit()
        db.refresh(ticket)

        log_audit(db, current_user.id, "UPDATE", "Ticket", ticket_id, "SUCCESS", request.client.host)

        return {
            "id": ticket.id,
            "status": ticket.status,
            "assignee_id": ticket.assignee_id,
            "workgroup_id": ticket.workgroup_id,
            "updated_at": ticket.updated_at
        }
    except HTTPException:
        raise
    except Exception as e:
        log_audit(db, current_user.id, "UPDATE", "Ticket", ticket_id, "FAILED", request.client.host)
        raise HTTPException(status_code=500, detail="Error al asignar ticket")
```

#### 3.5 PATCH /api/tickets/{id}/close
Cerrar ticket con resolución.

```python
@app.patch("/api/tickets/{ticket_id}/close", tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def close_ticket(
    ticket_id: str,
    resolution: str = Field(..., pattern="^(resolved|cancelled|duplicate|wontfix)$"),
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Cierra un ticket con resolución."""
    current_user = require_agent_or_admin(current_user)

    try:
        ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket no encontrado")

        ticket.status = "closed"
        ticket.resolution = resolution
        ticket.updated_at = datetime.now(timezone.utc)

        db.commit()
        db.refresh(ticket)

        log_audit(db, current_user.id, "UPDATE", "Ticket", ticket_id, "SUCCESS", request.client.host)

        return {
            "id": ticket.id,
            "status": ticket.status,
            "resolution": ticket.resolution,
            "updated_at": ticket.updated_at
        }
    except HTTPException:
        raise
    except Exception as e:
        log_audit(db, current_user.id, "UPDATE", "Ticket", ticket_id, "FAILED", request.client.host)
        raise HTTPException(status_code=500, detail="Error al cerrar ticket")
```

---

### Paso 4: Actualizar Lógica Existente
**Archivo:** `main.py`

#### 4.1 Modificar POST /api/tickets
Auto-calcular SLA y auto-populate para contacts.

```python
@app.post("/api/tickets", tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def create_ticket(
    ticket: TicketCreate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Crea un nuevo ticket."""
    if not current_user:
        raise HTTPException(status_code=401, detail="Authentication required")

    try:
        # Auto-calcular due_date
        created_at = datetime.now(timezone.utc)
        due_date = calculate_due_date(ticket.priority, created_at)

        ticket_data = ticket.dict()

        # Si es contact, auto-populate branch y contact
        if current_user.user_type == 'contact':
            ticket_data['branch_id'] = current_user.primary_branch_id
            ticket_data['contact_id'] = current_user.id

        db_ticket = TicketModel(
            id=str(uuid.uuid4()),
            created_by_id=current_user.id,
            due_date=due_date,
            **ticket_data
        )
        db.add(db_ticket)
        db.commit()
        db.refresh(db_ticket)

        log_audit(db, current_user.id, "CREATE", "Ticket", db_ticket.id, "SUCCESS", request.client.host)

        return {
            "id": db_ticket.id,
            "subject": db_ticket.subject,
            "status": db_ticket.status,
            "priority": db_ticket.priority,
            "due_date": db_ticket.due_date,
            "created_at": db_ticket.created_at
        }
    except Exception as e:
        log_audit(db, current_user.id, "CREATE", "Ticket", None, "FAILED", request.client.host)
        raise HTTPException(status_code=500, detail="Error creating ticket")
```

#### 4.2 Modificar POST /api/tickets/{id}/messages
Agregar lógica de auto-asignación.

```python
# En el endpoint create_ticket_message, después de crear el mensaje:

# Auto-asignación: Si agent responde a ticket "new"
if current_user and current_user.user_type == 'agent' and ticket.status == 'new':
    ticket.assignee_id = current_user.id
    ticket.status = 'open'
    ticket.updated_at = datetime.now(timezone.utc)

    # Copiar workgroup_id del agent si no existe
    if not ticket.workgroup_id and current_user.workgroup_id:
        ticket.workgroup_id = current_user.workgroup_id

db.commit()
```

#### 4.3 Eliminar Endpoints Deprecados
Remover estos grupos de endpoints:
- ❌ Todos los endpoints `/api/agents/*` (CRUD)
- ❌ Todos los endpoints `/api/contacts/*` (CRUD)

Reemplazarlos con:
- ✅ `GET /api/users/team` (lista agents)
- ✅ `GET /api/users/customers` (lista contacts)

#### 4.4 Actualizar Filtros de Tickets
Cambiar las referencias de `role` a `user_type`:

```python
# Antes:
if current_user.role in ["admin", "agent"]:
    # Ver todos

# Después:
if current_user.user_type in ["admin", "agent"]:
    # Ver todos
```

---

### Paso 5: Testing
**Checklists de validación**

#### 5.1 Setup Inicial
- [ ] Eliminar `workhub.db` existente
- [ ] Reiniciar servidor (FastAPI recreará tablas)
- [ ] Verificar que no hay errores de schema

#### 5.2 Auth
- [ ] `POST /api/auth/login` con username (admin/agent)
- [ ] `POST /api/auth/login` con email (todos los tipos)
- [ ] Login devuelve `user` con `user_type` correcto
- [ ] Redirect logic funciona based on `user_type`

#### 5.3 Users
- [ ] `GET /api/users/team` retorna solo admin+agent
- [ ] `GET /api/users/customers` retorna solo contacts
- [ ] `POST /api/users` valida `user_type` correctamente
- [ ] No se puede crear agent sin `workgroup_id`
- [ ] No se puede crear contact sin `primary_branch_id`

#### 5.4 Tickets
- [ ] `POST /api/tickets` calcula `due_date` correcto (priority → SLA)
- [ ] Contact crea ticket → auto-populated `branch_id`, `contact_id`
- [ ] Agent responde → auto-asignación y status "new" → "open"
- [ ] `PATCH /api/tickets/{id}/assign` funciona
- [ ] `PATCH /api/tickets/{id}/close` funciona
- [ ] Workgroup copiado de agent cuando se asigna

#### 5.5 Permisos
- [ ] Admin ve todos los tickets
- [ ] Agent solo ve tickets de su workgroup
- [ ] Contact solo ve sus propios tickets
- [ ] No se puede asignar ticket a contact
- [ ] Contact no puede ver tickets de otros

---

## Validaciones Críticas

### User Creation
```
✓ user_type requerido, enum válido
✓ email único en toda la tabla
✓ username único (si no es NULL) y requerido para admin/agent
✓ workgroup_id requerido para agent
✓ primary_branch_id requerido para contact
✓ password mínimo 8 caracteres
```

### Ticket Creation
```
✓ priority enum: low/medium/high/urgent
✓ status default: "new"
✓ due_date auto-calculado según priority
✓ assignee_id debe ser user con user_type IN ['admin', 'agent']
✓ contact_id debe ser user con user_type='contact'
✓ Si user es contact: auto-populate branch_id y contact_id
```

### Message Creation
```
✓ sender_id debe ser user válido
✓ ticket_id debe existir
✓ Si agent responde a "new": auto-asignar y cambiar a "open"
✓ Copiar workgroup_id del agent si falta
```

---

## Cambios de Breaking

### Para el Frontend
1. **Auth endpoint:** `/api/token` → `/api/auth/login`
2. **Auth response:** Incluye `user` object con `user_type`
3. **Ticket status:** Default cambió de `"open"` a `"new"`
4. **Endpoints eliminados:** `/api/agents/*`, `/api/contacts/*`
   - Usar `GET /api/users/team` (agents)
   - Usar `GET /api/users/customers` (contacts)
5. **Ticket fields:**
   - `assignee_agent_id` → `assignee_id`
   - Agregado: `workgroup_id`

### Compatibilidad
- Mantener `/api/token` como alias deprecado (apunta a `/api/auth/login`)
- Documentar migration guide

---

## Rollback

Si algo falla:
1. Eliminar `workhub.db`
2. Revertir cambios en `main.py`
3. Reiniciar servidor

---

## Checklists de Implementación

### Pre-Implementación
- [ ] Revisar archivos: DATABASE_SCHEMA.md, FRONTEND_INTEGRATION.md
- [ ] Backup de main.py actual
- [ ] Entender estructura monolítica existente

### Durante (Paso 1-5)
- [ ] Paso 1: Modelos + Schemas compilar sin errores
- [ ] Paso 2: Helpers funcionan (SLA, permisos)
- [ ] Paso 3: Endpoints nuevos accesibles
- [ ] Paso 4: Lógica existente integrada
- [ ] Paso 5: Testing crítico pasa

### Post-Implementación
- [ ] Documentar API changes en CHANGELOG
- [ ] Comunicar breaking changes al frontend
- [ ] Mantener docs/API_CONTRACT.md actualizado

---

**Próximo:** Comenzar con Paso 1 - Actualizar Modelos y Schemas
