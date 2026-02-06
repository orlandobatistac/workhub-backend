import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Any
import json
from functools import lru_cache

from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, UploadFile, File
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import StaticPool
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load environment variables (optional - works without .env file)
try:
    from python_dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Configuration
# Generate secure default if not provided
DEFAULT_SECRET = os.getenv("SECRET_KEY", None)
if not DEFAULT_SECRET:
    import secrets
    DEFAULT_SECRET = secrets.token_urlsafe(32)

SECRET_KEY = DEFAULT_SECRET
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))
RATE_LIMIT = os.getenv("RATE_LIMIT", "100/minute")
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./workhub.db")
ALLOWED_ORIGINS_STR = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000,https://friendly-winner-v6xg6vv757qcwv55-5000.app.github.dev")
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_STR.split(",")]

# File Upload Setup
UPLOAD_DIR = "uploads/tickets"
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Security Settings for File Uploads
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
MAX_FILES_PER_MESSAGE = 5
ALLOWED_MIME_TYPES = {
    "image/jpeg", "image/png", "image/gif", "image/webp",
    "application/pdf",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain", "text/csv"
}

ALLOWED_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp",  # Images
    ".pdf",  # PDF
    ".doc", ".docx",  # Word
    ".xls", ".xlsx",  # Excel
    ".txt", ".csv"  # Text
}

# Map MIME types to expected extensions (for double validation)
MIME_TO_EXTENSIONS = {
    "image/jpeg": {".jpg", ".jpeg"},
    "image/png": {".png"},
    "image/gif": {".gif"},
    "image/webp": {".webp"},
    "application/pdf": {".pdf"},
    "application/msword": {".doc"},
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": {".docx"},
    "application/vnd.ms-excel": {".xls"},
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": {".xlsx"},
    "text/plain": {".txt"},
    "text/csv": {".csv"}
}

def sanitize_filename(filename: str) -> str:
    """Sanitize filename to prevent path traversal and malicious names."""
    # Remove path components
    filename = os.path.basename(filename)
    # Remove any remaining path separators
    filename = filename.replace("..", "").replace("/", "").replace("\\", "")
    # Limit length
    name, ext = os.path.splitext(filename)
    name = name[:100]
    return f"{name}{ext}"

async def validate_upload_file(file: UploadFile) -> None:
    """Validate uploaded file for security."""
    # Get file extension
    _, ext = os.path.splitext(file.filename)
    ext = ext.lower()
    
    # Check file extension
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '{ext}' not allowed. Allowed: {', '.join(sorted(ALLOWED_EXTENSIONS))}"
        )
    
    # Check MIME type
    if file.content_type not in ALLOWED_MIME_TYPES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File type '{file.content_type}' not allowed. Allowed types: images, PDF, Word, Excel, text files."
        )
    
    # Validate MIME type matches extension (double-check for spoofing)
    expected_extensions = MIME_TO_EXTENSIONS.get(file.content_type, set())
    if expected_extensions and ext not in expected_extensions:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"File extension '{ext}' does not match content type '{file.content_type}'"
        )
    
    # Check file size
    content = await file.read()
    if len(content) > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size: {MAX_FILE_SIZE / (1024*1024)}MB"
        )
    
    # Reset file pointer for later reading
    await file.seek(0)
    return content

# Database Setup
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {},
    poolclass=StaticPool if "sqlite" in DATABASE_URL else None,
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Password Context (Argon2)
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """Hash a password using Argon2."""
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    return pwd_context.verify(plain_password, hashed_password)


# ============================================================================
# DATABASE MODELS
# ============================================================================

class UserModel(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    role = Column(String, default="user")  # admin, agent, user
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLogModel(Base):
    __tablename__ = "audit_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, nullable=True)
    username = Column(String)
    action = Column(String)  # CREATE, READ, UPDATE, DELETE
    resource = Column(String)  # Branch, Agent, etc.
    resource_id = Column(String, nullable=True)
    details = Column(Text, nullable=True)
    status = Column(String)  # SUCCESS, FAILED
    ip_address = Column(String, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class BranchModel(Base):
    __tablename__ = "branches"

    id = Column(String, primary_key=True, index=True)
    branch_code = Column(String, unique=True, index=True)
    name = Column(String, index=True)
    address = Column(String)
    status = Column(String, default="active")
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class AgentModel(Base):
    __tablename__ = "agents"

    id = Column(String, primary_key=True, index=True)
    agent_id = Column(String, unique=True, index=True)
    name = Column(String, index=True)
    role = Column(String, default="Agent")
    workgroup_id = Column(String, nullable=True)
    external_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class WorkgroupModel(Base):
    __tablename__ = "workgroups"

    id = Column(String, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ContactModel(Base):
    __tablename__ = "contacts"

    id = Column(String, primary_key=True, index=True)
    contact_id = Column(String, unique=True, index=True)
    name = Column(String, index=True)
    primary_branch_id = Column(String)
    external_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class TicketModel(Base):
    __tablename__ = "tickets"

    id = Column(String, primary_key=True, index=True)
    subject = Column(String, index=True)
    description = Column(String)
    priority = Column(String, default="medium")
    status = Column(String, default="open")
    branch_id = Column(String, nullable=True)
    assignee_agent_id = Column(String, nullable=True)
    contact_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class MessageModel(Base):
    __tablename__ = "messages"

    id = Column(String, primary_key=True, index=True)
    ticket_id = Column(String, index=True)
    sender_name = Column(String)
    sender_type = Column(String)
    content = Column(String)
    attachments = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


# Create tables
Base.metadata.create_all(bind=engine)

# ============================================================================
# PYDANTIC SCHEMAS
# ============================================================================

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username must be 3-50 chars")
    email: str = Field(..., description="Valid email required")
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name required")
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")
    role: str = "user"
    
    model_config = {"json_schema_extra": {"example": {"username": "john_doe", "email": "john@example.com", "full_name": "John Doe", "password": "SecurePass123!"}}}


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    is_active: bool
    created_at: datetime


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str


class BranchCreate(BaseModel):
    branch_code: str = Field(..., min_length=1, max_length=20)
    name: str = Field(..., min_length=1, max_length=100)
    address: str = Field(..., min_length=1, max_length=255)
    status: str = Field(default="active", pattern="^(active|inactive|archived)$")


class BranchUpdate(BaseModel):
    branch_code: Optional[str] = None
    name: Optional[str] = None
    address: Optional[str] = None
    status: Optional[str] = None


class BranchResponse(BaseModel):
    id: str
    branch_code: str
    name: str
    address: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class AgentCreate(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=50)
    name: str = Field(..., min_length=1, max_length=100)
    role: str = Field(default="Agent", min_length=1, max_length=50)
    workgroup_id: Optional[str] = None
    external_id: Optional[str] = None


class AgentUpdate(BaseModel):
    agent_id: Optional[str] = None
    name: Optional[str] = None
    role: Optional[str] = None
    workgroup_id: Optional[str] = None
    external_id: Optional[str] = None


class AgentResponse(BaseModel):
    id: str
    agent_id: str
    name: str
    role: str
    workgroup_id: Optional[str]
    external_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class WorkgroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: str = Field(..., min_length=1, max_length=500)


class WorkgroupUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None


class WorkgroupResponse(BaseModel):
    id: str
    name: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True


class ContactCreate(BaseModel):
    contact_id: str = Field(..., min_length=1, max_length=50)
    name: str = Field(..., min_length=1, max_length=100)
    primary_branch_id: str = Field(..., min_length=1)
    external_id: Optional[str] = None


class ContactUpdate(BaseModel):
    contact_id: Optional[str] = None
    name: Optional[str] = None
    primary_branch_id: Optional[str] = None
    external_id: Optional[str] = None


class ContactResponse(BaseModel):
    id: str
    contact_id: str
    name: str
    primary_branch_id: str
    external_id: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class TicketCreate(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=5000)
    priority: str = Field(default="medium")
    status: str = Field(default="open")
    branch_id: Optional[str] = None
    assignee_agent_id: Optional[str] = None
    contact_id: Optional[str] = None


class TicketUpdate(BaseModel):
    subject: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    branch_id: Optional[str] = None
    assignee_agent_id: Optional[str] = None
    contact_id: Optional[str] = None


class TicketResponse(BaseModel):
    id: str
    subject: str
    description: str
    priority: str
    status: str
    branch_id: Optional[str]
    assignee_agent_id: Optional[str]
    contact_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MessageCreate(BaseModel):
    sender_name: str = Field(..., min_length=1, max_length=100)
    sender_type: str = Field(..., pattern="^(user|agent|system)$")
    content: str = Field(..., min_length=1, max_length=10000)


class MessageResponse(BaseModel):
    id: str
    ticket_id: str
    sender_name: str
    sender_type: str
    content: str
    attachments: Optional[List[dict]] = None
    created_at: datetime

    class Config:
        from_attributes = True
    
    @classmethod
    def model_validate(cls, obj):
        """Custom validator to parse JSON attachments field."""
        if hasattr(obj, 'attachments') and obj.attachments:
            if isinstance(obj.attachments, str):
                try:
                    obj.attachments = json.loads(obj.attachments)
                except (json.JSONDecodeError, TypeError):
                    obj.attachments = None
        return super().model_validate(obj)


class AuditLogResponse(BaseModel):
    id: int
    user_id: Optional[int]
    username: str
    action: str
    resource: str
    resource_id: Optional[str]
    details: Optional[str]
    status: str
    ip_address: Optional[str]
    timestamp: datetime

    class Config:
        from_attributes = True


class PaginationMeta(BaseModel):
    page: int
    limit: int
    total: int
    totalPages: int


class PaginatedResponse(BaseModel):
    data: List[Any]
    pagination: PaginationMeta


# ============================================================================
# FASTAPI APP SETUP
# ============================================================================

app = FastAPI(
    title="WorkHub API",
    description="Production-ready REST API with Security Features",
    version="1.0.0",
)

# Rate Limiter
limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={"message": "Rate limit exceeded. Max 100 requests per minute.", "status": 429},
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"message": str(exc.detail), "status": exc.status_code},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=400,
        content={"message": "Invalid request data", "status": 400},
    )


# Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,  # Restrict to specific origins
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization"],
)

# ============================================================================
# AUTHENTICATION & SECURITY
# ============================================================================


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


def get_db():
    """Dependency to get database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_current_user(request: Request, db: Session = Depends(get_db)) -> UserModel:
    """Validate JWT token and return current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise credentials_exception
    
    try:
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise credentials_exception
    except ValueError:
        raise credentials_exception
    
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    
    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise credentials_exception
    
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User inactive")
    
    return user


async def get_optional_user(request: Request, db: Session = Depends(get_db)) -> Optional[UserModel]:
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    try:
        scheme, token = auth_header.split()
        if scheme.lower() != "bearer":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    except ValueError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User inactive")

    return user


def log_audit(
    user_id: Optional[int],
    username: str,
    action: str,
    resource: str,
    resource_id: Optional[str],
    status: str,
    db: Session,
    details: Optional[str] = None,
    ip_address: Optional[str] = None,
):
    """Log audit event to database and file."""
    audit_log = AuditLogModel(
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        resource_id=resource_id,
        details=details,
        status=status,
        ip_address=ip_address,
    )
    db.add(audit_log)
    db.commit()
    
    # Also log to file
    with open("audit.log", "a") as f:
        f.write(
            f"{datetime.now(timezone.utc).isoformat()} | "
            f"User: {username} | "
            f"Action: {action} | "
            f"Resource: {resource} | "
            f"Status: {status} | "
            f"IP: {ip_address}\n"
        )


def log_audit_optional(
    current_user: Optional[UserModel],
    action: str,
    resource: str,
    resource_id: Optional[str],
    status: str,
    db: Session,
    request: Request,
    details: Optional[str] = None,
):
    if current_user:
        user_id = current_user.id
        username = current_user.username
    else:
        user_id = None
        username = "anonymous"

    log_audit(
        user_id=user_id,
        username=username,
        action=action,
        resource=resource,
        resource_id=resource_id,
        status=status,
        db=db,
        details=details,
        ip_address=request.client.host if request.client else None,
    )


# ============================================================================
# SYSTEM ENDPOINTS
# ============================================================================

@app.get("/api/health", tags=["System"])
@limiter.limit(RATE_LIMIT)
async def health_check(request: Request):
    """Health check endpoint."""
    return {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/seed", tags=["System"])
@limiter.limit(RATE_LIMIT)
async def seed_data(
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Seed demo data for frontend development."""
    created = {
        "branches": 0,
        "workgroups": 0,
        "agents": 0,
        "contacts": 0,
        "tickets": 0,
        "messages": 0,
    }

    # Store created objects for relationships instead of querying
    branches_list = []
    workgroups_list = []
    agents_list = []
    contacts_list = []

    if db.query(BranchModel).count() == 0:
        branches = []
        for idx in range(1, 6):
            branches.append(
                BranchModel(
                    id=str(uuid.uuid4()),
                    branch_code=f"BR-{idx:03d}",
                    name=f"Branch {idx}",
                    address=f"Address {idx}",
                    status="active",
                )
            )
        db.add_all(branches)
        branches_list = branches
        created["branches"] = len(branches)

    if db.query(WorkgroupModel).count() == 0:
        workgroups = []
        for idx in range(1, 6):
            workgroups.append(
                WorkgroupModel(
                    id=str(uuid.uuid4()),
                    name=f"Workgroup {idx}",
                    description=f"Demo workgroup {idx}",
                )
            )
        db.add_all(workgroups)
        workgroups_list = workgroups
        created["workgroups"] = len(workgroups)

    if db.query(AgentModel).count() == 0:
        workgroups = workgroups_list if workgroups_list else db.query(WorkgroupModel).all()
        agents = []
        for idx in range(1, 11):
            workgroup = workgroups[(idx - 1) % len(workgroups)] if workgroups else None
            agents.append(
                AgentModel(
                    id=str(uuid.uuid4()),
                    agent_id=f"AG-{idx:03d}",
                    name=f"Agent {idx}",
                    role="Admin" if idx == 1 else "Agent",
                    workgroup_id=workgroup.id if workgroup else None,
                    external_id=None,
                )
            )
        db.add_all(agents)
        agents_list = agents
        created["agents"] = len(agents)

    if db.query(ContactModel).count() == 0:
        branches = branches_list if branches_list else db.query(BranchModel).all()
        contacts = []
        for idx in range(1, 31):
            branch = branches[(idx - 1) % len(branches)] if branches else None
            contacts.append(
                ContactModel(
                    id=str(uuid.uuid4()),
                    contact_id=f"CT-{idx:03d}",
                    name=f"Contact {idx}",
                    primary_branch_id=branch.id if branch else None,
                    external_id=None,
                )
            )
        db.add_all(contacts)
        contacts_list = contacts
        created["contacts"] = len(contacts)

    if db.query(TicketModel).count() == 0:
        branches = branches_list if branches_list else db.query(BranchModel).all()
        contacts = contacts_list if contacts_list else db.query(ContactModel).all()
        agents = agents_list if agents_list else db.query(AgentModel).all()
        
        statuses = ["open", "in_progress", "closed", "resolved"]
        priorities = ["low", "medium", "high", "critical"]
        
        tickets = []
        for idx in range(1, 61):
            branch = branches[(idx - 1) % len(branches)] if branches else None
            contact = contacts[(idx - 1) % len(contacts)] if contacts else None
            # Assign agents to tickets (not all tickets get an agent)
            agent = agents[(idx - 1) % len(agents)] if agents and idx % 3 != 0 else None
            
            tickets.append(
                TicketModel(
                    id=str(uuid.uuid4()),
                    subject=f"Issue #{idx}: {['Bug Fix', 'Feature Request', 'Enhancement', 'Support Request'][idx % 4]}",
                    description=f"This is ticket #{idx}. Status: {statuses[idx % 4]}. Priority: {priorities[idx % 4]}",
                    priority=priorities[idx % 4],
                    status=statuses[idx % 4],
                    branch_id=branch.id if branch else None,
                    assignee_agent_id=agent.id if agent else None,
                    contact_id=contact.id if contact else None,
                )
            )
        db.add_all(tickets)
        created["tickets"] = len(tickets)

    if db.query(MessageModel).count() == 0:
        db.flush()  # Ensure tickets are visible in this session
        messages = []
        tickets = db.query(TicketModel).all()
        for ticket in tickets:
            # Create contextual messages based on ticket status
            status_messages = {
                "open": "Ticket created and awaiting assignment.",
                "in_progress": "Ticket assigned to agent. Work in progress.",
                "closed": "Ticket closed by agent.",
                "resolved": "Issue resolved successfully.",
            }
            
            message_content = status_messages.get(ticket.status, "Ticket created.")
            
            messages.append(
                MessageModel(
                    id=str(uuid.uuid4()),
                    ticket_id=ticket.id,
                    sender_name="System",
                    sender_type="system",
                    content=message_content,
                )
            )
        if messages:
            db.add_all(messages)
        created["messages"] = len(messages)

    db.commit()

    log_audit_optional(
        current_user=current_user,
        action="CREATE",
        resource="Seed",
        resource_id=None,
        status="SUCCESS",
        db=db,
        details="Seed data created",
        request=request,
    )

    return {"message": "Seed completed", "data": created}


@app.post("/api/register", response_model=UserResponse, tags=["Authentication"])
@limiter.limit(RATE_LIMIT)
async def register(user: UserCreate, request: Request, db: Session = Depends(get_db)):
    """Register a new user."""
    try:
        # Check if user exists
        existing_user = db.query(UserModel).filter(
            (UserModel.username == user.username) | (UserModel.email == user.email)
        ).first()
        
        if existing_user:
            log_audit(
                user_id=None,
                username=user.username,
                action="CREATE",
                resource="User",
                resource_id=None,
                status="FAILED",
                db=db,
                details="User already exists",
                ip_address=request.client.host,
            )
            raise HTTPException(status_code=400, detail="User already exists")
        
        # Create new user
        hashed_password = get_password_hash(user.password)
        db_user = UserModel(
            username=user.username,
            email=user.email,
            full_name=user.full_name,
            hashed_password=hashed_password,
            role=user.role,
        )
        db.add(db_user)
        db.commit()
        db.refresh(db_user)
        
        log_audit(
            user_id=db_user.id,
            username=db_user.username,
            action="CREATE",
            resource="User",
            resource_id=db_user.id,
            status="SUCCESS",
            db=db,
            details="New user registered",
            ip_address=request.client.host,
        )
        
        return db_user
    except Exception as e:
        log_audit(
            user_id=None,
            username=user.username,
            action="CREATE",
            resource="User",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            ip_address=request.client.host,
        )
        raise


@app.post("/api/token", response_model=TokenResponse, tags=["Authentication"])
@limiter.limit(RATE_LIMIT)
async def login(credentials: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login and get access token."""
    try:
        user = db.query(UserModel).filter(UserModel.username == credentials.username).first()
        
        if not user or not verify_password(credentials.password, user.hashed_password):
            log_audit(
                user_id=None,
                username=credentials.username,
                action="LOGIN",
                resource="Authentication",
                resource_id=None,
                status="FAILED",
                db=db,
                details="Invalid credentials",
                ip_address=request.client.host,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        if not user.is_active:
            log_audit(
                user_id=user.id,
                username=user.username,
                action="LOGIN",
                resource="Authentication",
                resource_id=user.id,
                status="FAILED",
                db=db,
                details="User inactive",
                ip_address=request.client.host,
            )
            raise HTTPException(status_code=403, detail="User inactive")
        
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires,
        )
        
        log_audit(
            user_id=user.id,
            username=user.username,
            action="LOGIN",
            resource="Authentication",
            resource_id=user.id,
            status="SUCCESS",
            db=db,
            details="User logged in",
            ip_address=request.client.host,
        )
        
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        log_audit(
            user_id=None,
            username=credentials.username,
            action="LOGIN",
            resource="Authentication",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            ip_address=request.client.host,
        )
        raise


@app.post("/api/test-token", tags=["Auth"])
@limiter.limit(RATE_LIMIT)
async def get_test_token(
    request: Request,
    db: Session = Depends(get_db)
):
    """
    ⚠️  DEVELOPMENT ONLY - Get a test token without credentials
    
    Returns a valid JWT token for the default admin user.
    This endpoint is intended for frontend development and testing.
    Should be disabled or removed in production.
    """
    # Get admin user from database
    admin_user = db.query(UserModel).filter(UserModel.username == "admin").first()
    
    if not admin_user:
        raise HTTPException(
            status_code=500,
            detail="Admin user not found. Run server to initialize seed data."
        )
    
    # Create token for admin user
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": admin_user.username},
        expires_delta=access_token_expires,
    )
    
    log_audit(
        user_id=admin_user.id,
        username=admin_user.username,
        action="TEST_TOKEN",
        resource="Authentication",
        resource_id=admin_user.id,
        status="SUCCESS",
        db=db,
        details="Test token generated (development only)",
        ip_address=request.client.host,
    )
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": admin_user.id,
            "username": admin_user.username,
            "role": admin_user.role
        }
    }


# ============================================================================
# AUDIT LOG ENDPOINTS
# ============================================================================

@app.get("/api/audit-logs", response_model=PaginatedResponse, tags=["Audit"])
@limiter.limit(RATE_LIMIT)
async def list_audit_logs(
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: UserModel = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List audit logs (admin only)."""
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    offset = (page - 1) * limit
    total = db.query(AuditLogModel).count()
    logs = db.query(AuditLogModel).offset(offset).limit(limit).all()

    data = [AuditLogResponse.model_validate(log) for log in logs]
    
    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


# ============================================================================
# BRANCH ENDPOINTS
# ============================================================================

@app.post("/api/branches", response_model=BranchResponse, tags=["Branches"])
@limiter.limit(RATE_LIMIT)
async def create_branch(
    branch: BranchCreate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a new branch."""
    try:
        db_branch = BranchModel(id=str(uuid.uuid4()), **branch.dict())
        db.add(db_branch)
        db.commit()
        db.refresh(db_branch)

        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Branch",
            resource_id=db_branch.id,
            status="SUCCESS",
            db=db,
            details=f"Branch: {branch.name}",
            request=request,
        )
        
        return db_branch
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Branch",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.get("/api/branches", response_model=PaginatedResponse, tags=["Branches"])
@limiter.limit(RATE_LIMIT)
async def list_branches(
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all branches."""
    offset = (page - 1) * limit
    total = db.query(BranchModel).count()
    branches = db.query(BranchModel).offset(offset).limit(limit).all()

    data = [BranchResponse.model_validate(branch) for branch in branches]

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@app.get("/api/branches/{branch_id}", response_model=BranchResponse, tags=["Branches"])
@limiter.limit(RATE_LIMIT)
async def get_branch(
    branch_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get a specific branch."""
    branch = db.query(BranchModel).filter(BranchModel.id == branch_id).first()
    if not branch:
        raise HTTPException(status_code=404, detail="Branch not found")
    return branch


@app.put("/api/branches/{branch_id}", response_model=BranchResponse, tags=["Branches"])
@limiter.limit(RATE_LIMIT)
async def update_branch(
    branch_id: str,
    branch_update: BranchUpdate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Update a branch."""
    try:
        branch = db.query(BranchModel).filter(BranchModel.id == branch_id).first()
        if not branch:
            raise HTTPException(status_code=404, detail="Branch not found")
        
        for key, value in branch_update.dict(exclude_unset=True).items():
            setattr(branch, key, value)
        
        db.commit()
        db.refresh(branch)
        
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Branch",
            resource_id=branch_id,
            status="SUCCESS",
            db=db,
            details=str(branch_update),
            request=request,
        )
        
        return branch
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Branch",
            resource_id=branch_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.delete("/api/branches/{branch_id}", status_code=204, tags=["Branches"])
@limiter.limit(RATE_LIMIT)
async def delete_branch(
    branch_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete a branch."""
    try:
        branch = db.query(BranchModel).filter(BranchModel.id == branch_id).first()
        if not branch:
            raise HTTPException(status_code=404, detail="Branch not found")
        
        db.delete(branch)
        db.commit()
        
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Branch",
            resource_id=branch_id,
            status="SUCCESS",
            db=db,
            details="Branch deleted",
            request=request,
        )
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Branch",
            resource_id=branch_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


# ============================================================================
# AGENT ENDPOINTS
# ============================================================================

@app.post("/api/agents", response_model=AgentResponse, tags=["Agents"])
@limiter.limit(RATE_LIMIT)
async def create_agent(
    agent: AgentCreate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a new agent."""
    try:
        db_agent = AgentModel(id=str(uuid.uuid4()), **agent.dict())
        db.add(db_agent)
        db.commit()
        db.refresh(db_agent)

        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Agent",
            resource_id=db_agent.id,
            status="SUCCESS",
            db=db,
            details=f"Agent: {agent.name}",
            request=request,
        )
        
        return db_agent
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Agent",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.get("/api/agents", response_model=PaginatedResponse, tags=["Agents"])
@limiter.limit(RATE_LIMIT)
async def list_agents(
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all agents."""
    offset = (page - 1) * limit
    total = db.query(AgentModel).count()
    agents = db.query(AgentModel).offset(offset).limit(limit).all()

    data = [AgentResponse.model_validate(agent) for agent in agents]
    
    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@app.get("/api/agents/{agent_id}", response_model=AgentResponse, tags=["Agents"])
@limiter.limit(RATE_LIMIT)
async def get_agent(
    agent_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get a specific agent."""
    agent = db.query(AgentModel).filter(AgentModel.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    return agent


@app.put("/api/agents/{agent_id}", response_model=AgentResponse, tags=["Agents"])
@limiter.limit(RATE_LIMIT)
async def update_agent(
    agent_id: str,
    agent_update: AgentUpdate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Update an agent."""
    try:
        agent = db.query(AgentModel).filter(AgentModel.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        for key, value in agent_update.dict(exclude_unset=True).items():
            setattr(agent, key, value)
        
        db.commit()
        db.refresh(agent)
        
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Agent",
            resource_id=agent_id,
            status="SUCCESS",
            db=db,
            details=str(agent_update),
            request=request,
        )
        
        return agent
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Agent",
            resource_id=agent_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.delete("/api/agents/{agent_id}", status_code=204, tags=["Agents"])
@limiter.limit(RATE_LIMIT)
async def delete_agent(
    agent_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete an agent."""
    try:
        agent = db.query(AgentModel).filter(AgentModel.id == agent_id).first()
        if not agent:
            raise HTTPException(status_code=404, detail="Agent not found")
        
        db.delete(agent)
        db.commit()
        
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Agent",
            resource_id=agent_id,
            status="SUCCESS",
            db=db,
            details="Agent deleted",
            request=request,
        )
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Agent",
            resource_id=agent_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


# ============================================================================
# WORKGROUP ENDPOINTS
# ============================================================================

@app.post("/api/workgroups", response_model=WorkgroupResponse, tags=["Workgroups"])
@limiter.limit(RATE_LIMIT)
async def create_workgroup(
    workgroup: WorkgroupCreate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a new workgroup."""
    try:
        db_workgroup = WorkgroupModel(id=str(uuid.uuid4()), **workgroup.dict())
        db.add(db_workgroup)
        db.commit()
        db.refresh(db_workgroup)

        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Workgroup",
            resource_id=db_workgroup.id,
            status="SUCCESS",
            db=db,
            details=f"Workgroup: {workgroup.name}",
            request=request,
        )
        
        return db_workgroup
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Workgroup",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.get("/api/workgroups", response_model=PaginatedResponse, tags=["Workgroups"])
@limiter.limit(RATE_LIMIT)
async def list_workgroups(
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all workgroups."""
    offset = (page - 1) * limit
    total = db.query(WorkgroupModel).count()
    workgroups = db.query(WorkgroupModel).offset(offset).limit(limit).all()

    data = [WorkgroupResponse.model_validate(workgroup) for workgroup in workgroups]
    
    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@app.get("/api/workgroups/{workgroup_id}", response_model=WorkgroupResponse, tags=["Workgroups"])
@limiter.limit(RATE_LIMIT)
async def get_workgroup(
    workgroup_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get a specific workgroup."""
    workgroup = db.query(WorkgroupModel).filter(WorkgroupModel.id == workgroup_id).first()
    if not workgroup:
        raise HTTPException(status_code=404, detail="Workgroup not found")
    return workgroup


@app.put("/api/workgroups/{workgroup_id}", response_model=WorkgroupResponse, tags=["Workgroups"])
@limiter.limit(RATE_LIMIT)
async def update_workgroup(
    workgroup_id: str,
    workgroup_update: WorkgroupUpdate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Update a workgroup."""
    try:
        workgroup = db.query(WorkgroupModel).filter(WorkgroupModel.id == workgroup_id).first()
        if not workgroup:
            raise HTTPException(status_code=404, detail="Workgroup not found")
        
        for key, value in workgroup_update.dict(exclude_unset=True).items():
            setattr(workgroup, key, value)
        
        db.commit()
        db.refresh(workgroup)
        
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Workgroup",
            resource_id=workgroup_id,
            status="SUCCESS",
            db=db,
            details=str(workgroup_update),
            request=request,
        )
        
        return workgroup
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Workgroup",
            resource_id=workgroup_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.delete("/api/workgroups/{workgroup_id}", status_code=204, tags=["Workgroups"])
@limiter.limit(RATE_LIMIT)
async def delete_workgroup(
    workgroup_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete a workgroup."""
    try:
        workgroup = db.query(WorkgroupModel).filter(WorkgroupModel.id == workgroup_id).first()
        if not workgroup:
            raise HTTPException(status_code=404, detail="Workgroup not found")
        
        db.delete(workgroup)
        db.commit()
        
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Workgroup",
            resource_id=workgroup_id,
            status="SUCCESS",
            db=db,
            details="Workgroup deleted",
            request=request,
        )
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Workgroup",
            resource_id=workgroup_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


# ============================================================================
# CONTACT ENDPOINTS
# ============================================================================

@app.post("/api/contacts", response_model=ContactResponse, tags=["Contacts"])
@limiter.limit(RATE_LIMIT)
async def create_contact(
    contact: ContactCreate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a new contact."""
    try:
        db_contact = ContactModel(id=str(uuid.uuid4()), **contact.dict())
        db.add(db_contact)
        db.commit()
        db.refresh(db_contact)

        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Contact",
            resource_id=db_contact.id,
            status="SUCCESS",
            db=db,
            details=f"Contact: {contact.name}",
            request=request,
        )
        
        return db_contact
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Contact",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.get("/api/contacts", response_model=PaginatedResponse, tags=["Contacts"])
@limiter.limit(RATE_LIMIT)
async def list_contacts(
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all contacts."""
    offset = (page - 1) * limit
    total = db.query(ContactModel).count()
    contacts = db.query(ContactModel).offset(offset).limit(limit).all()

    data = [ContactResponse.model_validate(contact) for contact in contacts]
    
    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@app.get("/api/contacts/{contact_id}", response_model=ContactResponse, tags=["Contacts"])
@limiter.limit(RATE_LIMIT)
async def get_contact(
    contact_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get a specific contact."""
    contact = db.query(ContactModel).filter(ContactModel.id == contact_id).first()
    if not contact:
        raise HTTPException(status_code=404, detail="Contact not found")
    return contact


@app.put("/api/contacts/{contact_id}", response_model=ContactResponse, tags=["Contacts"])
@limiter.limit(RATE_LIMIT)
async def update_contact(
    contact_id: str,
    contact_update: ContactUpdate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Update a contact."""
    try:
        contact = db.query(ContactModel).filter(ContactModel.id == contact_id).first()
        if not contact:
            raise HTTPException(status_code=404, detail="Contact not found")
        
        for key, value in contact_update.dict(exclude_unset=True).items():
            setattr(contact, key, value)
        
        db.commit()
        db.refresh(contact)
        
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Contact",
            resource_id=contact_id,
            status="SUCCESS",
            db=db,
            details=str(contact_update),
            request=request,
        )
        
        return contact
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Contact",
            resource_id=contact_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.delete("/api/contacts/{contact_id}", status_code=204, tags=["Contacts"])
@limiter.limit(RATE_LIMIT)
async def delete_contact(
    contact_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete a contact."""
    try:
        contact = db.query(ContactModel).filter(ContactModel.id == contact_id).first()
        if not contact:
            raise HTTPException(status_code=404, detail="Contact not found")
        
        db.delete(contact)
        db.commit()
        
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Contact",
            resource_id=contact_id,
            status="SUCCESS",
            db=db,
            details="Contact deleted",
            request=request,
        )
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Contact",
            resource_id=contact_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


# ============================================================================
# TICKET ENDPOINTS
# ============================================================================

@app.post("/api/tickets", response_model=TicketResponse, tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def create_ticket(
    ticket: TicketCreate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a new ticket."""
    try:
        db_ticket = TicketModel(id=str(uuid.uuid4()), **ticket.dict())
        db.add(db_ticket)
        db.commit()
        db.refresh(db_ticket)

        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Ticket",
            resource_id=db_ticket.id,
            status="SUCCESS",
            db=db,
            details=f"Ticket: {ticket.subject}",
            request=request,
        )
        
        return db_ticket
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Ticket",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.get("/api/tickets", response_model=PaginatedResponse, tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def list_tickets(
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all tickets."""
    offset = (page - 1) * limit
    total = db.query(TicketModel).count()
    tickets = db.query(TicketModel).offset(offset).limit(limit).all()

    data = [TicketResponse.model_validate(ticket) for ticket in tickets]
    
    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@app.get("/api/tickets/{ticket_id}", response_model=TicketResponse, tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def get_ticket(
    ticket_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get a specific ticket."""
    ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")
    return ticket


@app.put("/api/tickets/{ticket_id}", response_model=TicketResponse, tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def update_ticket(
    ticket_id: str,
    ticket_update: TicketUpdate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Update a ticket."""
    try:
        ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")
        
        for key, value in ticket_update.dict(exclude_unset=True).items():
            setattr(ticket, key, value)
        
        ticket.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(ticket)
        
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Ticket",
            resource_id=ticket_id,
            status="SUCCESS",
            db=db,
            details=str(ticket_update),
            request=request,
        )
        
        return ticket
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="UPDATE",
            resource="Ticket",
            resource_id=ticket_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


@app.delete("/api/tickets/{ticket_id}", status_code=204, tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def delete_ticket(
    ticket_id: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete a ticket."""
    try:
        ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")
        
        db.delete(ticket)
        db.commit()
        
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Ticket",
            resource_id=ticket_id,
            status="SUCCESS",
            db=db,
            details="Ticket deleted",
            request=request,
        )
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="DELETE",
            resource="Ticket",
            resource_id=ticket_id,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


# ============================================================================
# MESSAGE ENDPOINTS
# ============================================================================

@app.get("/api/tickets/{ticket_id}/messages", response_model=PaginatedResponse, tags=["Messages"])
@limiter.limit(RATE_LIMIT)
async def list_ticket_messages(
    ticket_id: str,
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List messages for a ticket."""
    offset = (page - 1) * limit
    total = db.query(MessageModel).filter(MessageModel.ticket_id == ticket_id).count()
    messages = (
        db.query(MessageModel)
        .filter(MessageModel.ticket_id == ticket_id)
        .offset(offset)
        .limit(limit)
        .all()
    )

    data = [MessageResponse.model_validate(message) for message in messages]

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@app.post("/api/tickets/{ticket_id}/messages", response_model=MessageResponse, tags=["Messages"])
@limiter.limit(RATE_LIMIT)
async def create_ticket_message(
    ticket_id: str,
    sender_name: str = Form(...),
    sender_type: str = Form(...),
    content: str = Form(...),
    attachments: List[UploadFile] = File(default=[]),
    request: Request = None,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a message for a ticket with optional file attachments."""
    try:
        # Filter out empty files
        attachments = [f for f in attachments if f.filename]
        
        # Validate number of files
        if len(attachments) > MAX_FILES_PER_MESSAGE:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Too many files. Maximum {MAX_FILES_PER_MESSAGE} files allowed."
            )
        
        attachment_metadata = []
        
        # Validate and save files
        for file in attachments:
            # Validate file
            content_bytes = await validate_upload_file(file)
            
            # Sanitize filename
            safe_filename = sanitize_filename(file.filename)
            unique_filename = f"{uuid.uuid4()}_{safe_filename}"
            filepath = os.path.join(UPLOAD_DIR, unique_filename)
            
            # Ensure path is within UPLOAD_DIR (prevent path traversal)
            abs_filepath = os.path.abspath(filepath)
            abs_upload_dir = os.path.abspath(UPLOAD_DIR)
            if not abs_filepath.startswith(abs_upload_dir):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid file path"
                )
            
            # Save file
            with open(filepath, "wb") as f:
                f.write(content_bytes)
            
            attachment_metadata.append({
                "name": safe_filename,
                "type": file.content_type,
                "size": len(content_bytes),
                "path": unique_filename
            })
        
        db_message = MessageModel(
            id=str(uuid.uuid4()),
            ticket_id=ticket_id,
            sender_name=sender_name,
            sender_type=sender_type,
            content=content,
            attachments=json.dumps(attachment_metadata) if attachment_metadata else None,
        )
        db.add(db_message)
        db.commit()
        db.refresh(db_message)

        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Message",
            resource_id=db_message.id,
            status="SUCCESS",
            db=db,
            details="Message created",
            request=request,
        )
        
        # Parse attachments JSON for response
        parsed_attachments = None
        if db_message.attachments:
            try:
                parsed_attachments = json.loads(db_message.attachments)
            except (json.JSONDecodeError, TypeError):
                parsed_attachments = None
        
        # Return response with parsed attachments
        return MessageResponse(
            id=db_message.id,
            ticket_id=db_message.ticket_id,
            sender_name=db_message.sender_name,
            sender_type=db_message.sender_type,
            content=db_message.content,
            attachments=parsed_attachments,
            created_at=db_message.created_at
        )
    except Exception as e:
        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Message",
            resource_id=None,
            status="FAILED",
            db=db,
            details=str(e),
            request=request,
        )
        raise


# ============================================================================
# STARTUP EVENT - SEED DATA
# ============================================================================

@app.on_event("startup")
def startup_event():
    """Create seed data on startup."""
    db = SessionLocal()
    
    # Check if admin user already exists
    admin_exists = db.query(UserModel).filter(UserModel.username == "admin").first()
    if not admin_exists:
        admin = UserModel(
            username="admin",
            email="admin@workhub.com",
            full_name="Administrator",
            hashed_password=get_password_hash("admin123"),
            role="admin",
            is_active=True,
        )
        db.add(admin)
    
    # Check if agent user already exists
    agent_exists = db.query(UserModel).filter(UserModel.username == "agent").first()
    if not agent_exists:
        agent = UserModel(
            username="agent",
            email="agent@workhub.com",
            full_name="Agent User",
            hashed_password=get_password_hash("agent123"),
            role="agent",
            is_active=True,
        )
        db.add(agent)
    
    db.commit()
    db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
