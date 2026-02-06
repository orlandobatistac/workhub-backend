# Guía de Autenticación - WorkHub Backend

## Resumen

El sistema ya tiene implementado autenticación JWT completa con los siguientes componentes:

## Tabla de Usuarios

**Tabla:** `users`

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    full_name VARCHAR NOT NULL,
    hashed_password VARCHAR NOT NULL,
    role VARCHAR DEFAULT 'user',  -- valores: admin, agent, user
    is_active BOOLEAN DEFAULT true,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Endpoints Disponibles

### 1. Registro de Usuario
**POST** `/api/register`

Crea una nueva cuenta de usuario en el sistema.

**Request Body:**
```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "full_name": "John Doe",
  "password": "SecurePass123!",
  "role": "user"
}
```

**Validaciones:**
- username: 3-50 caracteres
- email: formato válido
- full_name: 2-100 caracteres
- password: mínimo 8 caracteres
- role: "admin" | "agent" | "user" (default: "user")

**Response 201:**
```json
{
  "id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "full_name": "John Doe",
  "role": "user",
  "is_active": true,
  "created_at": "2026-02-06T10:00:00Z"
}
```

**Errores:**
- 400: Usuario o email ya existe
- 422: Datos de validación incorrectos

---

### 2. Login (Obtener Token)
**POST** `/api/token`

Autentica al usuario y retorna un JWT token.

**Request Body:**
```json
{
  "username": "john_doe",
  "password": "SecurePass123!"
}
```

**Response 200:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer"
}
```

**Errores:**
- 401: Credenciales inválidas
- 403: Usuario inactivo (is_active=false)

**Nota:** El token expira en 30 minutos (configurable en ACCESS_TOKEN_EXPIRE_MINUTES)

---

### 3. Obtener Usuario Actual
**GET** `/api/me`

Retorna información del usuario autenticado.

**Headers:**
```
Authorization: Bearer <access_token>
```

**Response 200:**
```json
{
  "id": 1,
  "username": "john_doe",
  "email": "john@example.com",
  "full_name": "John Doe",
  "role": "user",
  "is_active": true,
  "created_at": "2026-02-06T10:00:00Z"
}
```

**Errores:**
- 401: Token inválido o expirado
- 403: Usuario inactivo

---

## Integración Frontend

### Flujo Completo de Autenticación

```javascript
// 1. REGISTRO (opcional - solo para nuevos usuarios)
async function register(userData) {
  const response = await fetch('http://localhost:8000/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      username: userData.username,
      email: userData.email,
      full_name: userData.fullName,
      password: userData.password,
      role: 'user'
    })
  });
  
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.detail);
  }
  
  return await response.json();
}

// 2. LOGIN
async function login(username, password) {
  const response = await fetch('http://localhost:8000/api/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  });
  
  if (!response.ok) {
    throw new Error('Credenciales inválidas');
  }
  
  const data = await response.json();
  
  // Guardar token en localStorage o sessionStorage
  localStorage.setItem('access_token', data.access_token);
  
  return data;
}

// 3. OBTENER DATOS DEL USUARIO ACTUAL
async function getCurrentUser() {
  const token = localStorage.getItem('access_token');
  
  if (!token) {
    throw new Error('No autenticado');
  }
  
  const response = await fetch('http://localhost:8000/api/me', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (!response.ok) {
    if (response.status === 401) {
      // Token expirado o inválido
      localStorage.removeItem('access_token');
      throw new Error('Sesión expirada');
    }
    throw new Error('Error al obtener usuario');
  }
  
  return await response.json();
}

// 4. LOGOUT
function logout() {
  localStorage.removeItem('access_token');
  // Redirigir a página de login
  window.location.href = '/login';
}

// 5. FUNCIÓN HELPER PARA REQUESTS AUTENTICADOS
async function authenticatedRequest(url, options = {}) {
  const token = localStorage.getItem('access_token');
  
  if (!token) {
    throw new Error('No autenticado');
  }
  
  const headers = {
    ...options.headers,
    'Authorization': `Bearer ${token}`
  };
  
  const response = await fetch(url, {
    ...options,
    headers
  });
  
  if (response.status === 401) {
    // Token expirado
    localStorage.removeItem('access_token');
    window.location.href = '/login';
    throw new Error('Sesión expirada');
  }
  
  return response;
}

// EJEMPLO DE USO
async function loadTickets() {
  try {
    const response = await authenticatedRequest('http://localhost:8000/api/tickets');
    const data = await response.json();
    return data;
  } catch (error) {
    console.error('Error:', error);
  }
}
```

---

## Ejemplo Completo: Página de Login

```html
<!DOCTYPE html>
<html>
<head>
  <title>WorkHub Login</title>
  <style>
    .container { max-width: 400px; margin: 50px auto; padding: 20px; }
    .form-group { margin-bottom: 15px; }
    label { display: block; margin-bottom: 5px; }
    input { width: 100%; padding: 8px; }
    button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; cursor: pointer; }
    .error { color: red; margin-top: 10px; }
  </style>
</head>
<body>
  <div class="container">
    <h2>Login</h2>
    <form id="loginForm">
      <div class="form-group">
        <label>Username:</label>
        <input type="text" id="username" required>
      </div>
      <div class="form-group">
        <label>Password:</label>
        <input type="password" id="password" required>
      </div>
      <button type="submit">Iniciar Sesión</button>
      <div id="error" class="error"></div>
    </form>
  </div>

  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const username = document.getElementById('username').value;
      const password = document.getElementById('password').value;
      const errorDiv = document.getElementById('error');
      
      errorDiv.textContent = '';
      
      try {
        // 1. Login
        const response = await fetch('http://localhost:8000/api/token', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        });
        
        if (!response.ok) {
          throw new Error('Credenciales inválidas');
        }
        
        const { access_token, token_type } = await response.json();
        
        // 2. Guardar token
        localStorage.setItem('access_token', access_token);
        
        // 3. Obtener datos del usuario
        const userResponse = await fetch('http://localhost:8000/api/me', {
          headers: { 'Authorization': `Bearer ${access_token}` }
        });
        
        const user = await userResponse.json();
        
        // 4. Redirigir a dashboard
        console.log('Usuario autenticado:', user);
        window.location.href = '/dashboard.html';
        
      } catch (error) {
        errorDiv.textContent = error.message;
      }
    });
  </script>
</body>
</html>
```

---

## Roles de Usuario

El sistema soporta 3 roles:

| Role | Descripción | Uso |
|------|-------------|-----|
| `user` | Usuario estándar | Puede crear tickets, ver sus propios tickets |
| `agent` | Agente de soporte | Puede gestionar tickets asignados, responder mensajes |
| `admin` | Administrador | Acceso completo al sistema |

Para implementar autorización por roles en endpoints específicos, usa el middleware `get_current_user` que ya está configurado.

---

## Seguridad

- **Password Hashing:** Bcrypt con salt automático
- **Token JWT:** HS256 algorithm
- **Token Expiration:** 30 minutos (configurable)
- **Rate Limiting:** 100 requests/min por IP
- **Audit Log:** Todos los intentos de login/registro se registran

---

## Variables de Entorno

```bash
SECRET_KEY="your-secret-key-here-change-in-production"
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

---

## Testing

```bash
# 1. Registrar usuario de prueba
curl -X POST http://localhost:8000/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "full_name": "Test User",
    "password": "TestPass123!"
  }'

# 2. Login
curl -X POST http://localhost:8000/api/token \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "password": "TestPass123!"
  }'

# 3. Usar token (reemplazar <TOKEN>)
curl -X GET http://localhost:8000/api/me \
  -H "Authorization: Bearer <TOKEN>"
```

---

## FAQ

**P: ¿Cómo renovar un token expirado?**  
R: El usuario debe hacer login nuevamente con `/api/token`. Para implementar refresh tokens, se requeriría desarrollo adicional.

**P: ¿Cómo cerrar sesión?**  
R: Simplemente elimina el token del localStorage en el frontend. El token expirará automáticamente en el servidor.

**P: ¿Puedo cambiar la duración del token?**  
R: Sí, modifica `ACCESS_TOKEN_EXPIRE_MINUTES` en la configuración.

**P: ¿Cómo resetear contraseña?**  
R: Actualmente no está implementado. Se requeriría agregar endpoints para solicitar reset y confirmar con email.
