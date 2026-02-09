import os
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Any
import json
from functools import lru_cache

from fastapi import FastAPI, Depends, HTTPException, status, Request, Form, UploadFile, File, Query
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey, or_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session, Mapped, mapped_column
from sqlalchemy.pool import StaticPool
from pydantic import BaseModel, Field
from passlib.context import CryptContext
from jose import JWTError, jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load environment variables (optional - works without .env file)
try:
    from dotenv import load_dotenv
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
ALLOWED_ORIGINS_STR = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8000,http://localhost:5000")
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_STR.split(",")]

# By default, accepts all origins ending in .github.dev, .github.io and localhost with any port
# Useful for development in GitHub Codespaces, GitHub Pages, and local development
CORS_PATTERN = os.getenv("CORS_PATTERN", r"https?://(localhost(:\d+)?|.*\.github\.(dev|io)|.*\.orlandobatista\.dev)")

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

async def validate_upload_file(file: UploadFile) -> bytes:
    """Validate uploaded file for security."""
    # Get file extension
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Filename is required"
        )
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
# TYPE CONVERSION HELPERS (for SQLAlchemy Column types to Python primitives)
# ============================================================================

def to_int(value: Any) -> Optional[int]:
    """Safely convert a value (potentially Column[int]) to int."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def to_str(value: Any) -> str:
    """Safely convert a value (potentially Column[str]) to str."""
    if value is None:
        return ""
    return str(value)


def to_optional_str(value: Any) -> Optional[str]:
    """Safely convert a value (potentially Column[str]) to Optional[str]."""
    if value is None:
        return None
    return str(value)


# ============================================================================
# DATABASE MODELS
# ============================================================================

class UserModel(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    username: Mapped[str] = mapped_column(String, unique=True, index=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    full_name: Mapped[str] = mapped_column(String)
    hashed_password: Mapped[str] = mapped_column(String)
    role: Mapped[str] = mapped_column(String, default="contact")  # admin, agent, contact
    # Optional external identifier for legacy agent mapping (agent.agent_id)
    agent_external_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Optional workgroup association for agent users
    workgroup_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class AuditLogModel(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    username: Mapped[str] = mapped_column(String)
    action: Mapped[str] = mapped_column(String)  # CREATE, READ, UPDATE, DELETE
    resource: Mapped[str] = mapped_column(String)  # Branch, Agent, etc.
    resource_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String)  # SUCCESS, FAILED
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class BranchModel(Base):
    __tablename__ = "branches"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    branch_code: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    address: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String, default="active")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class WorkgroupModel(Base):
    __tablename__ = "workgroups"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[str] = mapped_column(String)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class ContactModel(Base):
    __tablename__ = "contacts"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    contact_id: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[str] = mapped_column(String, index=True)
    email: Mapped[Optional[str]] = mapped_column(String, nullable=True, index=True)
    phone: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    primary_branch_id: Mapped[str] = mapped_column(String)
    external_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Optional link to a users.id when the contact registers
    user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class TicketModel(Base):
    __tablename__ = "tickets"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    subject: Mapped[str] = mapped_column(String, index=True)
    description: Mapped[str] = mapped_column(String)
    priority: Mapped[str] = mapped_column(String, default="medium")
    status: Mapped[str] = mapped_column(String, default="open")
    resolution: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # resolved, cancelled, duplicate, wontfix
    branch_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Canonical assignee: user id (nullable)
    assignee_user_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    contact_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    # Optional secret token for unauthenticated updates (public tickets)
    secret_token: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    due_date: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)  # User ID who created the ticket
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


class MessageModel(Base):
    __tablename__ = "messages"

    id: Mapped[str] = mapped_column(String, primary_key=True, index=True)
    ticket_id: Mapped[str] = mapped_column(String, index=True)
    sender_name: Mapped[str] = mapped_column(String)
    sender_type: Mapped[str] = mapped_column(String)
    content: Mapped[str] = mapped_column(String)
    attachments: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=lambda: datetime.now(timezone.utc))


# Create tables
Base.metadata.create_all(bind=engine)

# ---------------------------------------------------------------------------
# Helper: Apply sorting safely to SQLAlchemy queries
# ---------------------------------------------------------------------------

def apply_sorting(query, model, sort_by: Optional[str], sort_order: Optional[str]):
    """Apply ordering to a SQLAlchemy query using a validated column name.

    - Ensures only real column names are accepted (prevents injection).
    - Returns the ordered query.
    """
    if not sort_by:
        return query

    # Allowed columns are the table's column names
    allowed = {c.name for c in model.__table__.columns}
    if sort_by not in allowed:
        raise HTTPException(status_code=400, detail=f"Invalid sort_by: {sort_by}. Allowed: {', '.join(sorted(allowed))}")

    column = getattr(model, sort_by)
    if sort_order and sort_order.lower() == "desc":
        return query.order_by(column.desc())
    return query.order_by(column.asc())

# ============================================================================
# PYDANTIC SCHEMAS
# ============================================================================

class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Username must be 3-50 chars")
    email: str = Field(..., description="Valid email required")
    full_name: str = Field(..., min_length=2, max_length=100, description="Full name required")
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")
    role: str = "contact"
    agent_external_id: Optional[str] = Field(None, description="External agent identifier for legacy mapping")
    workgroup_id: Optional[str] = Field(None, description="Workgroup assignment for agent users")

    model_config = {"json_schema_extra": {"example": {"username": "john_doe", "email": "john@example.com", "full_name": "John Doe", "password": "SecurePass123!"}}}


class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    full_name: str
    role: str
    agent_external_id: Optional[str]
    workgroup_id: Optional[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class UserUpdate(BaseModel):
    email: Optional[str] = Field(None, description="Valid email required")
    full_name: Optional[str] = Field(None, min_length=2, max_length=100, description="Full name")
    password: Optional[str] = Field(None, min_length=8, description="Password must be at least 8 characters")
    role: Optional[str] = Field(None, pattern="^(contact|agent|admin)$", description="User role: contact, agent, or admin")
    agent_external_id: Optional[str] = Field(None, description="External agent identifier for legacy mapping")
    workgroup_id: Optional[str] = Field(None, description="Workgroup assignment for agent users")
    is_active: Optional[bool] = Field(None, description="Account active status")


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
    email: Optional[str] = Field(None, pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    phone: Optional[str] = Field(None, min_length=7, max_length=20)
    primary_branch_id: str = Field(..., min_length=1)
    external_id: Optional[str] = None
    # Optional user linkage when contact corresponds to a registered user
    user_id: Optional[int] = None


class ContactUpdate(BaseModel):
    contact_id: Optional[str] = None
    name: Optional[str] = None
    email: Optional[str] = Field(None, pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    phone: Optional[str] = Field(None, min_length=7, max_length=20)
    primary_branch_id: Optional[str] = None
    external_id: Optional[str] = None


class ContactResponse(BaseModel):
    id: str
    contact_id: str
    name: str
    email: Optional[str]
    phone: Optional[str]
    primary_branch_id: str
    external_id: Optional[str]
    user_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


class TicketCreate(BaseModel):
    subject: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1, max_length=5000)
    priority: str = Field(default="medium", pattern="^(low|medium|high|critical)$")
    status: str = Field(default="open", pattern="^(open|in_progress|closed)$")
    resolution: Optional[str] = Field(None, pattern="^(resolved|cancelled|duplicate|wontfix)$")
    branch_id: Optional[str] = None
    assignee_user_id: Optional[int] = None
    contact_id: Optional[str] = None
    due_date: Optional[datetime] = None


class TicketUpdate(BaseModel):
    subject: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = Field(None, pattern="^(low|medium|high|critical)$")
    status: Optional[str] = Field(None, pattern="^(open|in_progress|closed)$")
    resolution: Optional[str] = Field(None, pattern="^(resolved|cancelled|duplicate|wontfix)$")
    branch_id: Optional[str] = None
    assignee_user_id: Optional[int] = None
    contact_id: Optional[str] = None
    secret_token: Optional[str] = None
    due_date: Optional[datetime] = None


class TicketResponse(BaseModel):
    id: str
    subject: str
    description: str
    priority: str
    status: str
    resolution: Optional[str]
    branch_id: Optional[str]
    assignee_user_id: Optional[int]
    contact_id: Optional[str]
    secret_token: Optional[str]
    due_date: Optional[datetime]
    created_by_id: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MessageCreate(BaseModel):
    """Schema for message creation (Note: sender fields are derived server-side from auth)."""
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
    version="1.0.1",
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
    allow_origins=ALLOWED_ORIGINS,  # Lista específica de orígenes
    allow_origin_regex=CORS_PATTERN,  # Patrón regex adicional
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["Content-Length", "X-RateLimit-Limit", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
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
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise credentials_exception

    # Convert Column[bool] to bool explicitly
    is_active = bool(user.is_active) if hasattr(user.is_active, '__bool__') else user.is_active
    if not is_active:
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
        username: Optional[str] = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    user = db.query(UserModel).filter(UserModel.username == username).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    # Convert Column[bool] to bool explicitly
    is_active = bool(user.is_active) if hasattr(user.is_active, '__bool__') else user.is_active
    if not is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="User inactive")

    return user


# ============================================================================
# PERMISSION HELPERS
# ============================================================================

def require_admin(current_user: Optional[UserModel]) -> UserModel:
    """Verify that the current user is an admin. Returns the user if valid, raises HTTPException otherwise."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    # Convert Column[str] to str for comparison
    role = to_str(current_user.role)
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user


def require_agent_or_admin(current_user: Optional[UserModel]) -> UserModel:
    """Verify that the current user is an agent or admin. Returns the user if valid, raises HTTPException otherwise."""
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent or admin access required"
        )
    # Convert Column[str] to str for comparison
    role = to_str(current_user.role)
    if role not in ["admin", "agent"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Agent or admin access required"
        )
    return current_user


def can_access_ticket(ticket: TicketModel, current_user: Optional[UserModel]) -> bool:
    """Check if the current user can access the given ticket.

    Rules:
    - Admin and agent: can access all tickets
    - User: can only access their own tickets (created_by_id)
    """
    if not current_user:
        return False

    # Convert Column[str] to str for comparison
    role = to_str(current_user.role)

    # Admin and agent can see all tickets
    if role in ["admin", "agent"]:
        return True

    # User can only see their own tickets
    if role == "contact":
        # Compare values, not Column objects
        user_id_value = getattr(current_user, 'id', None)
        return ticket.created_by_id == user_id_value

    return False


def can_modify_ticket(ticket: TicketModel, current_user: Optional[UserModel]) -> bool:
    """Check if the current user can modify the given ticket.

    Rules:
    - Admin: can modify all tickets
    - Agent: can modify all tickets
    - User: can only modify their own tickets (created_by_id)
    """
    if not current_user:
        return False

    # Convert Column[str] to str for comparison
    role = to_str(current_user.role)

    # Admin can modify all tickets
    if role == "admin":
        return True

    # Agent can modify all tickets
    if role == "agent":
        return True

    # Contact can only modify their own tickets
    if role == "contact":
        # Compare values, not Column objects
        user_id_value = getattr(current_user, 'id', None)
        return ticket.created_by_id == user_id_value

    return False


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
    # Convert any Column types to primitive types
    clean_user_id = to_int(user_id) if user_id is not None else None
    clean_username = to_str(username)
    clean_resource_id = to_optional_str(resource_id)
    clean_details = to_optional_str(details)
    clean_ip_address = to_optional_str(ip_address)

    audit_log = AuditLogModel(
        user_id=clean_user_id,
        username=clean_username,
        action=action,
        resource=resource,
        resource_id=clean_resource_id,
        details=clean_details,
        status=status,
        ip_address=clean_ip_address,
    )
    db.add(audit_log)
    db.commit()

    # Also log to file
    with open("audit.log", "a") as f:
        f.write(
            f"{datetime.now(timezone.utc).isoformat()} | "
            f"User: {clean_username} | "
            f"Action: {action} | "
            f"Resource: {resource} | "
            f"Status: {status} | "
            f"IP: {clean_ip_address}\n"
        )


def log_audit_optional(
    current_user: Optional[UserModel],
    action: str,
    resource: str,
    resource_id: Optional[str],
    status: str,
    db: Session,
    request: Optional[Request],
    details: Optional[str] = None,
):
    if current_user:
        user_id = to_int(current_user.id)
        username = to_str(current_user.username)
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
        ip_address=request.client.host if (request and request.client) else None,
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
        "users": 0,
        "branches": 0,
        "workgroups": 0,
        "contacts": 0,
        "tickets": 0,
        "messages": 0,
    }

    # Store created objects for relationships instead of querying
    users_list = []
    branches_list = []
    workgroups_list = []
    contacts_list = []

    # Create demo users first (for ticket ownership)
    if db.query(UserModel).count() == 0:
        users = [
            UserModel(
                username="admin",
                email="admin@workhub.local",
                full_name="System Administrator",
                hashed_password=get_password_hash("admin123"),
                role="admin",
                is_active=True,
            ),
            UserModel(
                username="agent1",
                email="agent1@workhub.local",
                full_name="Agent Smith",
                hashed_password=get_password_hash("agent123"),
                role="agent",
                is_active=True,
            ),
            UserModel(
                username="agent2",
                email="agent2@workhub.local",
                full_name="Agent Johnson",
                hashed_password=get_password_hash("agent123"),
                role="agent",
                is_active=True,
            ),
            UserModel(
                username="user1",
                email="user1@workhub.local",
                full_name="John User",
                hashed_password=get_password_hash("user123"),
                role="contact",
                is_active=True,
            ),
            UserModel(
                username="user2",
                email="user2@workhub.local",
                full_name="Jane User",
                hashed_password=get_password_hash("user123"),
                role="contact",
                is_active=True,
            ),
        ]
        db.add_all(users)
        db.flush()  # Flush to get IDs
        users_list = users
        created["users"] = len(users)

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
                    email=f"contact{idx}@example.com" if idx % 2 == 0 else None,
                    phone=f"+1-555-{1000 + idx:04d}" if idx % 3 == 0 else None,
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
        users = users_list if users_list else db.query(UserModel).all()

        statuses = ["open", "in_progress", "closed"]
        resolutions = ["resolved", "cancelled", "duplicate", "wontfix"]
        priorities = ["low", "medium", "high", "critical"]

        tickets = []
        for idx in range(1, 61):
            branch = branches[(idx - 1) % len(branches)] if branches else None
            contact = contacts[(idx - 1) % len(contacts)] if contacts else None
            # Assign agent users to tickets (not all tickets get an agent)
            agent_user = users[(idx - 1) % len(users)] if users and idx % 3 != 0 and users else None
            # Assign creator: rotate between available users
            creator = users[(idx - 1) % len(users)] if users else None

            status = statuses[idx % 3]
            resolution = None
            # Only assign resolution when status is closed
            if status == "closed":
                resolution = resolutions[(idx // 3) % 4]

            # Add due_date to some tickets (50% of tickets)
            due_date = None
            if idx % 2 == 0:
                # Some overdue (past), some upcoming (future)
                days_delta = (idx % 20) - 10  # Range from -10 to +10 days
                due_date = datetime.now(timezone.utc) + timedelta(days=days_delta)

            tickets.append(
                TicketModel(
                    id=str(uuid.uuid4()),
                    subject=f"Issue #{idx}: {['Bug Fix', 'Feature Request', 'Enhancement', 'Support Request'][idx % 4]}",
                    description=f"This is ticket #{idx}. Status: {status}. Priority: {priorities[idx % 4]}",
                    priority=priorities[idx % 4],
                    status=status,
                    resolution=resolution,
                    branch_id=branch.id if branch else None,
                    assignee_user_id=agent_user.id if agent_user else None,
                    contact_id=contact.id if contact else None,
                    due_date=due_date,
                    created_by_id=creator.id if creator else None,  # Assign creator
                )
            )
        db.add_all(tickets)
        created["tickets"] = len(tickets)

    if db.query(MessageModel).count() == 0:
        db.flush()  # Ensure tickets are visible in this session
        messages = []
        tickets = db.query(TicketModel).all()
        for ticket in tickets:
            # Create contextual messages based on ticket status and resolution
            # Get actual string values from Column attributes
            ticket_status = str(ticket.status) if ticket.status else "open"
            ticket_resolution = str(ticket.resolution) if ticket.resolution else None

            if ticket_status == "closed" and ticket_resolution:
                resolution_messages = {
                    "resolved": "Issue resolved successfully.",
                    "cancelled": "Ticket cancelled by request.",
                    "duplicate": "Ticket closed as duplicate.",
                    "wontfix": "Ticket closed as won't fix.",
                }
                message_content = resolution_messages.get(ticket_resolution, "Ticket closed.")
            else:
                status_messages = {
                    "open": "Ticket created and awaiting assignment.",
                    "in_progress": "Ticket assigned to agent. Work in progress.",
                    "closed": "Ticket closed.",
                }
                message_content = status_messages.get(ticket_status, "Ticket created.")

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
                ip_address=request.client.host if request.client else None,
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
            user_id=to_int(db_user.id),
            username=to_str(db_user.username),
            action="CREATE",
            resource="User",
            resource_id=str(db_user.id),
            status="SUCCESS",
            db=db,
            details="New user registered",
            ip_address=request.client.host if request.client else None,
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
            ip_address=request.client.host if request.client else None,
        )
        raise


@app.post("/api/token", response_model=TokenResponse, tags=["Authentication"])
@limiter.limit(RATE_LIMIT)
async def login(credentials: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """Login and get access token."""
    try:
        user = db.query(UserModel).filter(
            or_(
                UserModel.username == credentials.username,
                UserModel.email == credentials.username,
            )
        ).first()

        if not user or not verify_password(credentials.password, to_str(user.hashed_password)):
            log_audit(
                user_id=None,
                username=credentials.username,
                action="LOGIN",
                resource="Authentication",
                resource_id=None,
                status="FAILED",
                db=db,
                details="Invalid credentials",
                ip_address=request.client.host if request.client else None,
            )
            raise HTTPException(status_code=401, detail="Invalid credentials")

        # Convert Column[bool] to bool explicitly
        is_active = bool(user.is_active) if hasattr(user.is_active, '__bool__') else user.is_active
        if not is_active:
            log_audit(
                user_id=to_int(user.id),
                username=to_str(user.username),
                action="LOGIN",
                resource="Authentication",
                resource_id=str(user.id),
                status="FAILED",
                db=db,
                details="User inactive",
                ip_address=request.client.host if request.client else None,
            )
            raise HTTPException(status_code=403, detail="User inactive")

        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username},
            expires_delta=access_token_expires,
        )

        log_audit(
            user_id=to_int(user.id),
            username=to_str(user.username),
            action="LOGIN",
            resource="Authentication",
            resource_id=str(user.id),
            status="SUCCESS",
            db=db,
            details="User logged in",
            ip_address=request.client.host if request.client else None,
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
            ip_address=request.client.host if request.client else None,
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
        user_id=to_int(admin_user.id),
        username=to_str(admin_user.username),
        action="TEST_TOKEN",
        resource="Authentication",
        resource_id=str(admin_user.id),
        status="SUCCESS",
        db=db,
        details="Test token generated (development only)",
        ip_address=request.client.host if request.client else None,
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


@app.get("/api/me", response_model=UserResponse, tags=["Authentication"])
@limiter.limit(RATE_LIMIT)
async def get_current_user_info(
    request: Request,
    current_user: UserModel = Depends(get_current_user)
):
    """Get current authenticated user information."""
    return current_user


# ============================================================================
# USER MANAGEMENT ENDPOINTS (PHASE 3 - RBAC)
# ============================================================================

@app.get("/api/users", response_model=PaginatedResponse, tags=["Users"])
@limiter.limit(RATE_LIMIT)
async def list_users(
    request: Request,
    page: int = 1,
    limit: int = 10,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all users. Agent can view (read-only), Admin can manage."""
    current_user = require_agent_or_admin(current_user)

    offset = (page - 1) * limit
    total = db.query(UserModel).count()
    users = db.query(UserModel).order_by(UserModel.created_at.desc()).offset(offset).limit(limit).all()

    data = [UserResponse.model_validate(user) for user in users]

    # Log the action
    log_audit(
        user_id=current_user.id,
        username=current_user.username,
        action="list",
        resource="users",
        resource_id=None,
        status="success",
        db=db,
        details=f"Listed {len(data)} users (page {page})"
    )

    return {
        "data": data,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "totalPages": (total + limit - 1) // limit,
        },
    }


@app.post("/api/users", response_model=UserResponse, tags=["Users"], status_code=201)
@limiter.limit(RATE_LIMIT)
async def create_user(
    user: UserCreate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a new user. Admin only."""
    current_user = require_admin(current_user)

    # Check if user exists
    existing_user = db.query(UserModel).filter(
        (UserModel.username == user.username) | (UserModel.email == user.email)
    ).first()

    if existing_user:
        log_audit(
            user_id=current_user.id,
            username=current_user.username,
            action="create",
            resource="users",
            resource_id=None,
            status="failed",
            db=db,
            details=f"User already exists: {user.username}",
            ip_address=request.client.host if request.client else None,
        )
        raise HTTPException(status_code=400, detail="Username or email already exists")

    # Validate role
    if user.role not in ["contact", "agent", "admin"]:
        raise HTTPException(status_code=400, detail="Invalid role. Must be: contact, agent, or admin")

    # Create new user
    hashed_password = get_password_hash(user.password)
    db_user = UserModel(
        username=user.username,
        email=user.email,
        full_name=user.full_name,
        hashed_password=hashed_password,
        role=user.role,
        agent_external_id=user.agent_external_id,
        workgroup_id=user.workgroup_id,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)

    log_audit(
        user_id=current_user.id,
        username=current_user.username,
        action="create",
        resource="users",
        resource_id=str(db_user.id),
        status="success",
        db=db,
        details=f"Created user: {db_user.username} with role: {db_user.role}",
        ip_address=request.client.host if request.client else None,
    )

    return db_user


@app.get("/api/users/{user_id}", response_model=UserResponse, tags=["Users"])
@limiter.limit(RATE_LIMIT)
async def get_user(
    user_id: int,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Get user details. Admin only."""
    current_user = require_admin(current_user)

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        log_audit(
            user_id=current_user.id,
            username=current_user.username,
            action="get",
            resource="users",
            resource_id=str(user_id),
            status="failed",
            db=db,
            details="User not found"
        )
        raise HTTPException(status_code=404, detail="User not found")

    log_audit(
        user_id=current_user.id,
        username=current_user.username,
        action="get",
        resource="users",
        resource_id=str(user_id),
        status="success",
        db=db,
        details=f"Retrieved user: {user.username}"
    )

    return user


@app.put("/api/users/{user_id}", response_model=UserResponse, tags=["Users"])
@limiter.limit(RATE_LIMIT)
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Update user (change role, password, status). Admin only."""
    current_user = require_admin(current_user)

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        log_audit(
            user_id=current_user.id,
            username=current_user.username,
            action="update",
            resource="users",
            resource_id=str(user_id),
            status="failed",
            db=db,
            details="User not found"
        )
        raise HTTPException(status_code=404, detail="User not found")

    # Track changes for audit log
    changes = []

    # Update email (check uniqueness)
    if user_update.email is not None and user_update.email != user.email:
        existing_user = db.query(UserModel).filter(
            UserModel.email == user_update.email,
            UserModel.id != user_id
        ).first()
        if existing_user:
            log_audit(
                user_id=current_user.id,
                username=current_user.username,
                action="update",
                resource="users",
                resource_id=str(user_id),
                status="failed",
                db=db,
                details=f"Email {user_update.email} already in use"
            )
            raise HTTPException(status_code=400, detail="Email already in use")
        changes.append(f"email: {user.email} -> {user_update.email}")
        setattr(user, 'email', user_update.email)

    # Update full name
    if user_update.full_name is not None and user_update.full_name != user.full_name:
        changes.append(f"full_name: {user.full_name} -> {user_update.full_name}")
        setattr(user, 'full_name', user_update.full_name)

    # Update password (hash it)
    if user_update.password is not None:
        setattr(user, 'hashed_password', get_password_hash(user_update.password))
        changes.append("password: [UPDATED]")

    # Update role
    if user_update.role is not None and user_update.role != user.role:
        changes.append(f"role: {user.role} -> {user_update.role}")
        setattr(user, 'role', user_update.role)

    # Update active status
    if user_update.is_active is not None and user_update.is_active != user.is_active:
        changes.append(f"is_active: {user.is_active} -> {user_update.is_active}")
        setattr(user, 'is_active', user_update.is_active)

    # Update agent_external_id
    if user_update.agent_external_id is not None:
        if user.agent_external_id != user_update.agent_external_id:
            changes.append(f"agent_external_id: {user.agent_external_id} -> {user_update.agent_external_id}")
        setattr(user, 'agent_external_id', user_update.agent_external_id)

    # Update workgroup_id
    if user_update.workgroup_id is not None:
        if user.workgroup_id != user_update.workgroup_id:
            changes.append(f"workgroup_id: {user.workgroup_id} -> {user_update.workgroup_id}")
        setattr(user, 'workgroup_id', user_update.workgroup_id)

    if not changes:
        log_audit(
            user_id=current_user.id,
            username=current_user.username,
            action="update",
            resource="users",
            resource_id=str(user_id),
            status="success",
            db=db,
            details="No changes made"
        )
        return user

    db.commit()
    db.refresh(user)

    log_audit(
        user_id=current_user.id,
        username=current_user.username,
        action="update",
        resource="users",
        resource_id=str(user_id),
        status="success",
        db=db,
        details=f"Updated user {user.username}: {', '.join(changes)}"
    )

    return user


@app.delete("/api/users/{user_id}", status_code=204, tags=["Users"])
@limiter.limit(RATE_LIMIT)
async def delete_user(
    user_id: int,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Delete user. Admin only. Cannot delete self."""
    current_user = require_admin(current_user)

    # Prevent admin from deleting themselves
    if current_user.id == user_id:
        log_audit(
            user_id=current_user.id,
            username=current_user.username,
            action="delete",
            resource="users",
            resource_id=str(user_id),
            status="failed",
            db=db,
            details="Cannot delete yourself"
        )
        raise HTTPException(status_code=400, detail="Cannot delete yourself")

    user = db.query(UserModel).filter(UserModel.id == user_id).first()
    if not user:
        log_audit(
            user_id=current_user.id,
            username=current_user.username,
            action="delete",
            resource="users",
            resource_id=str(user_id),
            status="failed",
            db=db,
            details="User not found"
        )
        raise HTTPException(status_code=404, detail="User not found")

    username = user.username
    db.delete(user)
    db.commit()

    log_audit(
        user_id=current_user.id,
        username=current_user.username,
        action="delete",
        resource="users",
        resource_id=str(user_id),
        status="success",
        db=db,
        details=f"Deleted user: {username}"
    )

    return None


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
            resource_id=str(db_branch.id),
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
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all branches."""
    offset = (page - 1) * limit
    base_query = db.query(BranchModel)
    total = base_query.count()

    # Apply sorting if requested
    if sort_by:
        if sort_order and sort_order.lower() not in ("asc", "desc"):
            raise HTTPException(status_code=400, detail="sort_order must be 'asc' or 'desc'")
        base_query = apply_sorting(base_query, BranchModel, sort_by, sort_order)

    branches = base_query.offset(offset).limit(limit).all()

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
            resource_id=str(db_workgroup.id),
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
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all workgroups."""
    offset = (page - 1) * limit
    base_query = db.query(WorkgroupModel)
    total = base_query.count()

    if sort_by:
        if sort_order and sort_order.lower() not in ("asc", "desc"):
            raise HTTPException(status_code=400, detail="sort_order must be 'asc' or 'desc'")
        base_query = apply_sorting(base_query, WorkgroupModel, sort_by, sort_order)

    workgroups = base_query.offset(offset).limit(limit).all()

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
            resource_id=str(db_contact.id),
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
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List all contacts."""
    offset = (page - 1) * limit
    base_query = db.query(ContactModel)
    total = base_query.count()

    if sort_by:
        if sort_order and sort_order.lower() not in ("asc", "desc"):
            raise HTTPException(status_code=400, detail="sort_order must be 'asc' or 'desc'")
        base_query = apply_sorting(base_query, ContactModel, sort_by, sort_order)

    contacts = base_query.offset(offset).limit(limit).all()

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
    """Create a new ticket. Requires authentication."""
    # Require authentication
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to create tickets"
        )

    try:
        payload = ticket.dict()

        db_ticket = TicketModel(
            id=str(uuid.uuid4()),
            created_by_id=current_user.id,
            **payload
        )
        db.add(db_ticket)
        db.commit()
        db.refresh(db_ticket)

        log_audit_optional(
            current_user=current_user,
            action="CREATE",
            resource="Ticket",
            resource_id=str(db_ticket.id),
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


# Public contact registration endpoint
class PublicContactRegister(BaseModel):
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$", description="Email must match an existing contact")
    password: str = Field(..., min_length=8, description="Password must be at least 8 characters")
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Optional username (defaults to email prefix)")


@app.post("/api/public/register", response_model=TokenResponse, tags=["Public"])
@limiter.limit(RATE_LIMIT)
async def register_contact(
    registration: PublicContactRegister,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Register a contact to create a user account.
    The contact must already exist (created via public ticket submission).
    Creates a user account with role='contact' and links it to the contact.
    """
    try:
        # 1. Find contact by email
        contact = db.query(ContactModel).filter(ContactModel.email == registration.email).first()
        if not contact:
            raise HTTPException(
                status_code=404,
                detail="Contact not found. Please create a ticket first to register your email."
            )

        # 2. Check if contact already has a user account
        if contact.user_id is not None:
            raise HTTPException(
                status_code=400,
                detail="This email is already registered. Please use the login endpoint."
            )

        # 3. Generate username if not provided
        username = registration.username
        if not username:
            # Use email prefix as username
            username = registration.email.split('@')[0]
            # If username exists, append random suffix
            existing = db.query(UserModel).filter(UserModel.username == username).first()
            if existing:
                username = f"{username}_{uuid.uuid4().hex[:6]}"

        # 4. Check username and email availability
        existing_user = db.query(UserModel).filter(
            or_(UserModel.username == username, UserModel.email == registration.email)
        ).first()
        if existing_user:
            raise HTTPException(
                status_code=400,
                detail="Username or email already taken by another user account."
            )

        # 5. Create user account with role='contact' (not staff)
        hashed_password = get_password_hash(registration.password)
        new_user = UserModel(
            username=username,
            email=registration.email,
            full_name=contact.name,
            hashed_password=hashed_password,
            role="contact",
            is_active=True,
        )
        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        # 6. Link contact to user
        contact.user_id = new_user.id
        db.commit()
        db.refresh(contact)

        # 7. Create access token
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": new_user.username}, expires_delta=access_token_expires
        )

        # 8. Audit log
        log_audit_optional(
            current_user=None,
            action="CREATE",
            resource="User",
            resource_id=str(new_user.id),
            status="SUCCESS",
            db=db,
            details=f"Public registration: {new_user.username} linked to contact {contact.id}",
            request=request,
        )

        return {
            "access_token": access_token,
            "token_type": "bearer"
        }

    except HTTPException:
        raise
    except Exception as e:
        log_audit_optional(
            current_user=None,
            action="CREATE",
            resource="User",
            resource_id=None,
            status="FAILED",
            db=db,
            details=f"Public registration failed: {str(e)}",
            request=request,
        )
        raise HTTPException(status_code=500, detail="Registration failed. Please try again.")


# Public tickets endpoint
class PublicTicketCreate(BaseModel):
    name: str = Field(..., min_length=1)
    email: str = Field(..., pattern=r"^[\w\.-]+@[\w\.-]+\.\w+$")
    subject: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    branch_id: Optional[str] = None
    primary_branch_id: Optional[str] = None


@app.post("/api/public/tickets", tags=["Public"], status_code=200)
async def create_public_ticket(ticket: PublicTicketCreate, request: Request, db: Session = Depends(get_db)):
    """Create a ticket from the public portal (no authentication required). Returns ticket id and secret token."""
    # Find or create contact by email
    contact = None
    if ticket.email:
        contact = db.query(ContactModel).filter(ContactModel.email == ticket.email).first()
    if not contact:
        contact = ContactModel(
            id=str(uuid.uuid4()),
            contact_id=f"C-{int(uuid.uuid4().int % 1000000):06d}",
            name=ticket.name,
            email=ticket.email,
            phone=None,
            primary_branch_id=ticket.primary_branch_id or "public",
            external_id=None,
            user_id=None,
        )
        db.add(contact)
        db.commit()
        db.refresh(contact)

    # Create ticket with secret token
    token = uuid.uuid4().hex
    db_ticket = TicketModel(
        id=str(uuid.uuid4()),
        subject=ticket.subject,
        description=ticket.description,
        branch_id=ticket.branch_id,
        contact_id=contact.id,
        secret_token=token,
    )
    db.add(db_ticket)
    db.commit()
    db.refresh(db_ticket)

    # Audit log
    log_audit_optional(
        current_user=None,
        action="CREATE",
        resource="Ticket",
        resource_id=str(db_ticket.id),
        status="SUCCESS",
        db=db,
        details="Public ticket created",
        request=request,
    )

    return {"id": db_ticket.id, "secret_token": token}


@app.get("/api/tickets", response_model=PaginatedResponse, tags=["Tickets"])
@limiter.limit(RATE_LIMIT)
async def list_tickets(
    request: Request,
    page: int = 1,
    limit: int = 10,
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List tickets (filtered by role).

    - Users: only see their own tickets
    - Agents/Admins: see all tickets

    Defaults: sort_by=updated_at, sort_order=desc when parameters are omitted.
    """
    # Require authentication
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required to view tickets"
        )

    offset = (page - 1) * limit
    base_query = db.query(TicketModel)

    # Filter by role
    if current_user.role == "contact":
        # Contacts only see their own tickets
        base_query = base_query.filter(TicketModel.created_by_id == current_user.id)
    # Admin and agent see all tickets (no additional filter)

    total = base_query.count()

    # Default ordering for tickets when not provided
    if not sort_by:
        sort_by = "updated_at"
    if not sort_order:
        sort_order = "desc"

    if sort_order and sort_order.lower() not in ("asc", "desc"):
        raise HTTPException(status_code=400, detail="sort_order must be 'asc' or 'desc'")

    base_query = apply_sorting(base_query, TicketModel, sort_by, sort_order)

    tickets = base_query.offset(offset).limit(limit).all()

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
    """Get a specific ticket. Access controlled by role."""
    # Require authentication
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
    if not ticket:
        raise HTTPException(status_code=404, detail="Ticket not found")

    # Check permissions
    if not can_access_ticket(ticket, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: You can only view your own tickets"
        )

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
    """Update a ticket. Access controlled by role."""
    # Require authentication
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")

        # Check permissions
        if not can_modify_ticket(ticket, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You can only modify your own tickets"
            )

        payload = ticket_update.dict(exclude_unset=True)

        for key, value in payload.items():
            setattr(ticket, key, value)

        setattr(ticket, 'updated_at', datetime.now(timezone.utc))
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
    """Delete a ticket. Access controlled by role."""
    # Require authentication
    if not current_user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )

    try:
        ticket = db.query(TicketModel).filter(TicketModel.id == ticket_id).first()
        if not ticket:
            raise HTTPException(status_code=404, detail="Ticket not found")

        # Check permissions
        if not can_modify_ticket(ticket, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied: You can only delete your own tickets"
            )

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
    sort_by: Optional[str] = None,
    sort_order: Optional[str] = None,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """List messages for a ticket."""
    offset = (page - 1) * limit
    base_query = db.query(MessageModel).filter(MessageModel.ticket_id == ticket_id)
    total = base_query.count()

    if sort_by:
        if sort_order and sort_order.lower() not in ("asc", "desc"):
            raise HTTPException(status_code=400, detail="sort_order must be 'asc' or 'desc'")
        base_query = apply_sorting(base_query, MessageModel, sort_by, sort_order)

    messages = base_query.offset(offset).limit(limit).all()

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
    request: Request,
    content: str = Form(...),
    attachments: List[UploadFile] = File(default=[]),
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Create a message for a ticket with optional file attachments."""
    try:
        # Derive sender information from authenticated user
        if current_user:
            sender_name = current_user.full_name or current_user.username
            sender_type = "contact" if current_user.role == "contact" else "agent"
        else:
            # Allow unauthenticated messages as anonymous users
            sender_name = "Anonymous"
            sender_type = "contact"

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
            # Ensure filename exists (double-check)
            if not file.filename:
                continue

            # Validate file
            content_bytes = await validate_upload_file(file)

            # Sanitize filename (now guaranteed to be str)
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
                "path": unique_filename,
                "url": f"/api/attachments/tickets/{unique_filename}"
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
            resource_id=str(db_message.id),
            status="SUCCESS",
            db=db,
            details="Message created",
            request=request,
        )

        # Parse attachments JSON for response
        parsed_attachments = None
        # Convert Column[str] to str explicitly
        attachments_str = str(db_message.attachments) if db_message.attachments else None
        if attachments_str:
            try:
                parsed_attachments = json.loads(attachments_str)
            except (json.JSONDecodeError, TypeError):
                parsed_attachments = None

        # Return response with parsed attachments
        # Convert Column types to primitive types explicitly
        return MessageResponse(
            id=str(db_message.id),
            ticket_id=str(db_message.ticket_id),
            sender_name=str(db_message.sender_name),
            sender_type=str(db_message.sender_type),
            content=str(db_message.content),
            attachments=parsed_attachments,
            created_at=db_message.created_at  # datetime is fine
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
# ATTACHMENT DOWNLOAD ENDPOINT
# ============================================================================

@app.get("/api/attachments/tickets/{path}", tags=["Attachments"])
@limiter.limit(RATE_LIMIT)
async def download_attachment(
    path: str,
    request: Request,
    current_user: Optional[UserModel] = Depends(get_optional_user),
    db: Session = Depends(get_db),
):
    """Download a ticket attachment file."""
    # Security: prevent path traversal
    if ".." in path or "/" in path or "\\" in path:
        raise HTTPException(status_code=400, detail="Invalid file path")

    # Construct full path
    filepath = os.path.join(UPLOAD_DIR, path)

    # Ensure path is within UPLOAD_DIR (prevent path traversal)
    abs_filepath = os.path.abspath(filepath)
    abs_upload_dir = os.path.abspath(UPLOAD_DIR)
    if not abs_filepath.startswith(abs_upload_dir):
        raise HTTPException(status_code=400, detail="Invalid file path")

    # Check if file exists
    if not os.path.isfile(filepath):
        raise HTTPException(status_code=404, detail="File not found")

    # Extract original filename (after UUID prefix)
    # Format is: {uuid}_{original_name}
    original_name = "_".join(path.split("_")[1:]) if "_" in path else path

    # Return file with proper headers
    return FileResponse(
        path=filepath,
        filename=original_name,
        media_type=None  # Let FileResponse infer from file extension
    )


# ============================================================================
# STARTUP EVENT - SEED DATA
# ============================================================================

def ensure_contact_columns() -> None:
    if not DATABASE_URL.startswith("sqlite:///"):
        return

    db_path = DATABASE_URL.replace("sqlite:///", "", 1)
    if not db_path:
        return

    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute("PRAGMA table_info(contacts)")
        columns = {row[1] for row in cursor.fetchall()}
        if "email" not in columns:
            conn.execute("ALTER TABLE contacts ADD COLUMN email VARCHAR")
        if "phone" not in columns:
            conn.execute("ALTER TABLE contacts ADD COLUMN phone VARCHAR")
        conn.commit()
    finally:
        conn.close()


@app.on_event("startup")
def startup_event():
    """Create seed data on startup."""
    ensure_contact_columns()
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

    # Check if demo user already exists
    user_exists = db.query(UserModel).filter(UserModel.username == "contact_demo").first()
    if not user_exists:
        user = UserModel(
            username="contact_demo",
            email="contact@workhub.com",
            full_name="Demo Contact",
            hashed_password=get_password_hash("contact123"),
            role="contact",
            is_active=True,
        )
        db.add(user)

    db.commit()
    db.close()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
