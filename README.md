# SecureShield - Role-Based Access Control (RBAC) API

A secure, production-ready Flask API demonstrating authentication with JWT (JSON Web Tokens) and role-based access control (RBAC). This project implements best practices for secure password storage, token management, and defensive logging.

## 🎯 Project Overview

SecureShield is a comprehensive RBAC implementation that covers:

### Part 1: Authentication & Identity (50 Points)
- ✅ **Secure Password Storage**: Bcrypt salting and hashing
- ✅ **JWT Issuance**: Token generation on successful login
- ✅ **Token Validation**: Middleware protection for secure routes

### Part 2: Access Control & Authorization (50 Points)
- ✅ **Role-Based Routing**: User and Admin access levels
- ✅ **Token Revocation**: Logout with token blacklisting
- ✅ **Defensive Logging**: Security event tracking

## 📋 Project Structure

```
SecureShield/
├── app.py                      # Main Flask application
├── models.py                   # Database models (SQLite)
├── auth.py                     # JWT and password utilities
├── middleware.py               # Security decorators and logging
├── requirements.txt            # Python dependencies
├── test_api.py                 # Automated test suite
├── database.db                 # SQLite database (auto-created)
├── security.log                # Security events log (auto-created)
├── REPORT.md                   # Technical report
└── README.md                   # This file
```

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Git (for version control)

### Installation

```bash
# 1. Navigate to project directory
cd SecureShield

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows PowerShell:
venv\Scripts\Activate.ps1

# Windows CMD:
venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt
```

### Running the Server

```bash
# Start Flask development server
python app.py
```

Output:
```
🚀 SecureShield API starting...
📍 Server: http://localhost:5000
📖 Documentation: http://localhost:5000/
 * Running on http://127.0.0.1:5000
```

## 📡 API Endpoints

### Authentication Endpoints

#### 1. User Registration
```
POST /register
Content-Type: application/json

{
    "username": "john_doe",
    "password": "securepassword123"
}

Response (201 Created):
{
    "message": "User registered successfully",
    "user_id": 2,
    "username": "john_doe",
    "role": "User"
}
```

#### 2. User Login
```
POST /login
Content-Type: application/json

{
    "username": "john_doe",
    "password": "securepassword123"
}

Response (200 OK):
{
    "message": "Login successful",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "username": "john_doe",
    "role": "User"
}
```

#### 3. User Logout
```
POST /logout
Authorization: Bearer <token>

Response (200 OK):
{
    "message": "Logout successful, token has been revoked"
}
```

### Protected Endpoints

#### 4. Get User Profile (User & Admin)
```
GET /profile
Authorization: Bearer <token>

Response (200 OK):
{
    "id": 2,
    "username": "john_doe",
    "role": "User",
    "created_at": "2026-05-02 10:30:45"
}
```

#### 5. Delete User (Admin Only)
```
DELETE /user/<user_id>
Authorization: Bearer <admin_token>

Response (200 OK):
{
    "message": "User 3 deleted successfully"
}

Response (403 Forbidden) - if not Admin:
{
    "message": "Admin access required"
}
```

## 🔒 Security Features

### 1. Secure Password Storage
- **Bcrypt Hashing**: Automatically generates random salt for each password
- **Cost Factor**: 12 rounds (2^12) of hashing
- **Rainbow Table Resistant**: Each password has unique salt

### 2. JWT Authentication
- **Algorithm**: HS256 (HMAC SHA-256)
- **Expiration**: 24 hours
- **Payload**: Contains username, role, and timestamp
- **Signature**: Verified on every protected request

### 3. Token Blacklisting
- **On Logout**: Token added to SQLite blacklist
- **On Request**: All requests check blacklist
- **Prevents**: Token replay attacks after logout

### 4. Role-Based Access Control
- **Decorator Pattern**: `@token_required`, `@admin_required`
- **Principle of Least Privilege**: Users can't access admin routes
- **Separation**: GET /profile (public), DELETE /user (admin)

### 5. Defensive Logging
- **Log File**: `security.log` (UTF-8 encoded)
- **Events Tracked**:
  - Registration attempts
  - Successful/failed logins
  - Unauthorized access attempts
  - Admin actions
  - Token operations

## 🧪 Testing

### Automated Test Suite

Run comprehensive tests covering all requirements:

```bash
# Terminal 1: Start the server
python app.py

# Terminal 2: Run tests
pip install requests  # If not already installed
python test_api.py
```

#### Test Coverage
- ✅ User registration and duplicate prevention
- ✅ Password security (can't register as Admin)
- ✅ JWT token generation and validation
- ✅ Token tamper detection
- ✅ Role-based access control (403 for non-admin)
- ✅ Token blacklisting on logout
- ✅ Security logging verification

### Manual Testing with cURL

```bash
# 1. Register a user
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"test123"}'

# 2. Login
curl -X POST http://localhost:5000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"test123"}'

# 3. Save the token (replace TOKEN below)
export TOKEN="your_jwt_token_here"

# 4. Access protected profile
curl -X GET http://localhost:5000/profile \
  -H "Authorization: Bearer $TOKEN"

# 5. Try admin-only delete (should fail with 403)
curl -X DELETE http://localhost:5000/user/2 \
  -H "Authorization: Bearer $TOKEN"

# 6. Logout (blacklist token)
curl -X POST http://localhost:5000/logout \
  -H "Authorization: Bearer $TOKEN"

# 7. Try to use blacklisted token (should fail with 401)
curl -X GET http://localhost:5000/profile \
  -H "Authorization: Bearer $TOKEN"
```

## 🎬 Video Demo Requirements

### For YouTube Video (2-5 minutes)

1. **Successful Login**
   - Show registration of new user
   - Show successful login receiving JWT token
   - Decode JWT at jwt.io to show payload contents

2. **Access Denied (403 Forbidden)**
   - Login as regular user (role: "User")
   - Attempt DELETE /user/<id> endpoint
   - Show 403 Forbidden response
   - Demonstrate that non-admin cannot delete users

3. **Tamper Test**
   - Get valid JWT token
   - Go to jwt.io
   - Decode the token
   - Modify the "role" from "User" to "Admin" in payload
   - Notice signature becomes invalid (shows red)
   - Try to send modified token to server
   - Show server rejects it with 401 error

## 📊 Default Users

On first run, the system creates a default admin:

```
Username: admin
Password: admin123
Role: Admin
```

**Important**: Change these credentials in production!

## 📁 Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Token Blacklist Table
```sql
CREATE TABLE token_blacklist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    blacklisted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

## 📝 Security Log Example

```
[2026-05-02 10:15:30] REGISTRATION | User: john_doe | Action: /register | Status: Success
[2026-05-02 10:15:45] LOGIN_SUCCESS | User: john_doe | Action: /login | Status: Role: User
[2026-05-02 10:20:10] FORBIDDEN | User: john_doe | Action: /user/2 | Status: User role 'User' attempted admin action
[2026-05-02 10:25:15] LOGOUT | User: john_doe | Action: /logout | Status: Token blacklisted
```

## 🔐 Production Recommendations

1. **Environment Variables**
   - Move SECRET_KEY to `.env` file
   - Never commit secrets to GitHub
   - Rotate SECRET_KEY periodically

2. **HTTPS**
   - Always use HTTPS in production
   - Prevents token interception

3. **Database**
   - Use PostgreSQL or MySQL instead of SQLite
   - Implement database backups
   - Use connection pooling

4. **Token Expiration**
   - Consider shorter expiry (1-2 hours)
   - Implement refresh tokens for longer sessions

5. **Rate Limiting**
   - Prevent brute force attacks
   - Use Flask-Limiter

6. **CORS**
   - Configure properly for your frontend
   - Use Flask-CORS with whitelist

7. **Input Validation**
   - Validate username length (min 3, max 50)
   - Validate password strength
   - Sanitize all inputs

## 📚 References

- [JWT Best Practices](https://tools.ietf.org/html/rfc8949)
- [OWASP Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Bcrypt Algorithm](https://en.wikipedia.org/wiki/Bcrypt)
- [Flask Security](https://flask-security-too.readthedocs.io/)
- [JWT Debugger](https://jwt.io)

## 📄 License

This project is created for educational purposes.

## 👥 Team Information

**Team Name**: [Your Team Name]

**Team Members**:
- [Member 1 Name]
- [Member 2 Name]
- [Member 3 Name] (if applicable)

---

**Created**: May 2, 2026
**Deadline**: May 3, 2026 23:59
