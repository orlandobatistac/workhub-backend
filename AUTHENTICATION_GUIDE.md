# Authentication Guide - WorkHub Backend

## Summary

The system already has a complete JWT authentication implementation with the following components:

## Users Table

**Table:** `users`

```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username VARCHAR UNIQUE NOT NULL,
    email VARCHAR UNIQUE NOT NULL,
    full_name VARCHAR NOT NULL,
    hashed_password VARCHAR NOT NULL,
    role VARCHAR DEFAULT 'user',  -- values: admin, agent, user
    is_active BOOLEAN DEFAULT true,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## Available Endpoints

### 1. User Registration
**POST** `/api/register`

Creates a new user account in the system.

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

**Validations:**
- username: 3-50 characters
- email: valid format
- full_name: 2-100 characters
- password: minimum 8 characters
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

**Errors:**
- 400: User or email already exists
- 422: Invalid validation data

---

### 2. Login (Get Token)
**POST** `/api/token`

Authenticates the user and returns a JWT token.

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

**Errors:**
- 401: Invalid credentials
- 403: Inactive user (is_active=false)

**Note:** Token expires in 30 minutes (configurable via ACCESS_TOKEN_EXPIRE_MINUTES)

---

### 3. Get Current User
**GET** `/api/me`

Returns authenticated user information.

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

**Errors:**
- 401: Invalid or expired token
- 403: Inactive user

---

## Frontend Integration

### Complete Authentication Flow

```javascript
// 1. REGISTER (optional - for new users only)
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
    throw new Error('Invalid credentials');
  }
  
  const data = await response.json();
  
  // Save token in localStorage or sessionStorage
  localStorage.setItem('access_token', data.access_token);
  
  return data;
}

// 3. GET CURRENT USER DATA
async function getCurrentUser() {
  const token = localStorage.getItem('access_token');
  
  if (!token) {
    throw new Error('Not authenticated');
  }
  
  const response = await fetch('http://localhost:8000/api/me', {
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });
  
  if (!response.ok) {
    if (response.status === 401) {
      // Expired or invalid token
      localStorage.removeItem('access_token');
      throw new Error('Session expired');
    }
    throw new Error('Error fetching user');
  }
  
  return await response.json();
}

// 4. LOGOUT
function logout() {
  localStorage.removeItem('access_token');
  // Redirect to login page
  window.location.href = '/login';
}

// 5. HELPER FUNCTION FOR AUTHENTICATED REQUESTS
async function authenticatedRequest(url, options = {}) {
  const token = localStorage.getItem('access_token');
  
  if (!token) {
    throw new Error('Not authenticated');
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
    // Expired token
    localStorage.removeItem('access_token');
    window.location.href = '/login';
    throw new Error('Session expired');
  }
  
  return response;
}

// USAGE EXAMPLE
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

## Complete Example: Login Page

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
      <button type="submit">Sign In</button>
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
          throw new Error('Invalid credentials');
        }
        
        const { access_token, token_type } = await response.json();
        
        // 2. Save token
        localStorage.setItem('access_token', access_token);
        
        // 3. Get user data
        const userResponse = await fetch('http://localhost:8000/api/me', {
          headers: { 'Authorization': `Bearer ${access_token}` }
        });
        
        const user = await userResponse.json();
        
        // 4. Redirect to dashboard
        console.log('Authenticated user:', user);
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

## User Roles

The system supports 3 roles:

| Role | Description | Use |
|------|-------------|-----|
| `user` | Standard user | Can create tickets, view own tickets |
| `agent` | Support agent | Can manage assigned tickets, respond to messages |
| `admin` | Administrator | Full system access |

To implement role-based authorization on specific endpoints, use the `get_current_user` middleware that is already configured.

---

## Security

- **Password Hashing:** Bcrypt with automatic salt
- **JWT Token:** HS256 algorithm
- **Token Expiration:** 30 minutes (configurable)
- **Rate Limiting:** 100 requests/min per IP
- **Audit Log:** All login/registration attempts are logged

---

## Environment Variables

```bash
SECRET_KEY="your-secret-key-here-change-in-production"
ACCESS_TOKEN_EXPIRE_MINUTES=30
```

---

## Testing

```bash
# 1. Register test user
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

# 3. Use token (replace <TOKEN>)
curl -X GET http://localhost:8000/api/me \
  -H "Authorization: Bearer <TOKEN>"
```

---

## FAQ

**Q: How to renew an expired token?**  
A: Users must login again with `/api/token`. Implementing refresh tokens would require additional development.

**Q: How to logout?**  
A: Simply remove the token from localStorage on the frontend. The token will automatically expire on the server.

**Q: Can I change the token duration?**  
A: Yes, modify `ACCESS_TOKEN_EXPIRE_MINUTES` in the configuration.

**Q: How to reset password?**  
A: Currently not implemented. Would require adding endpoints to request reset and confirm via email.

