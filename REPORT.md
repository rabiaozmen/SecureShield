# SecureShield RBAC API - Technical Report

## 1. Why Salting is Necessary to Prevent Rainbow Table Attacks

### The Problem: Rainbow Tables

A **Rainbow Table** is a pre-computed hash lookup table used by attackers to reverse hash values. Attackers create massive databases mapping common passwords to their hashes:

```
Password          →  MD5 Hash
password          →  5f4dcc3b5aa765d61d8327deb882cf99
123456            →  e807f1fcf82d132f9bb018ca6738a19f
welcome           →  5f9c4ab08cac7457e9111a30e4664882
```

If a database contains only password hashes (without salt), attackers can:
1. Look up the hash in a pre-computed Rainbow Table
2. Instantly recover the original password
3. Compromise all user accounts

### How Salt Prevents This

**Salting** adds random data to each password before hashing:

```
Password: "password"
Salt: "a3k9$2xL" (random for each user)
Hash: SHA256("password" + "a3k9$2xL") = 7f8a9e3c2d1b4f6e...
```

This defeats Rainbow Tables because:

✅ **Each password has a unique salt** → Same password produces different hashes
✅ **Attackers must recompute for each salt** → Impossible at scale (billions of salts)
✅ **Pre-computed tables become useless** → No pre-computed hash exists for "password" + random salt combinations

### Our Implementation

```python
# auth.py - Using bcrypt
def hash_password(password):
    return bcrypt.generate_password_hash(password).decode('utf-8')
```

**Bcrypt automatically**:
- Generates a cryptographically secure random salt
- Performs multiple iterations (rounds) to slow down computation
- Embeds the salt inside the hash for verification
- Uses adaptive hashing (resistant to GPU/hardware acceleration)

Example bcrypt hash:
```
$2b$12$R9h/cIPz0gi.URNNGNSVGO7bVeAjlWqfIsmYU6CJxnT7D9fF1ynF2
│ │  │  │
│ │  │  └─ Salt + Hash (62 characters)
│ │  └───── Cost factor (2^12 rounds)
│ └──────── Bcrypt version
└────────── Hash algorithm identifier
```

**Result**: Even if attackers steal our password database, they cannot crack the passwords efficiently.

---

## 2. Risks of Storing Sensitive Data in JWT Payload

### What are JWTs?

A JWT consists of three parts:
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJ1c2VybmFtZSI6ImFkbWluIiwicm9sZSI6IkFkbWluIiwi...
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
└─ Header        └─ Payload (BASE64 encoded)     └─ Signature
```

### Risk 1: Payload is NOT Encrypted (only Base64-encoded)

⚠️ **Anyone can decode the payload**:

```javascript
// Attacker at jwt.io can instantly see:
{
  "username": "john",
  "role": "Admin",
  "exp": 1719878400,
  "iat": 1719794000
}
```

**Attack Scenario**:
```bash
# Attacker steals JWT from network traffic (no HTTPS)
# Decodes at jwt.io
# Sees username and role in plain text
# Can attempt to forge a new JWT with higher privileges
```

### Risk 2: Attempting to Store Passwords in JWT

❌ **NEVER store passwords in JWT because**:

1. **Exposure**: Passwords are visible in Base64 (essentially plain text)
2. **Reuse**: Same password stored everywhere, if one JWT is compromised, all are
3. **Duration**: Password remains valid for hours/days (long JWT lifetime)
4. **Recovery**: Difficult to invalidate compromised passwords (stateless nature of JWT)

**Bad Example** (❌ DO NOT DO THIS):
```python
# Dangerous - DO NOT implement
payload = {
    'username': username,
    'password': password,  # ❌ NEVER DO THIS
    'role': role,
    'exp': datetime.utcnow() + timedelta(hours=24)
}
```

### Risk 3: Tampered Role Claims

⚠️ **Without proper validation, attackers can tamper with the payload**:

**Attack on unsecured JWT**:
```bash
# 1. Attacker intercepts JWT
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoiVXNlciJ9.signature

# 2. Decodes: {"username": "user", "role": "User"}

# 3. Modifies to: {"username": "user", "role": "Admin"}
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJyb2xlIjoiQWRtaW4ifQ.newsignature

# 4. Server without proper validation accepts it → User becomes Admin!
```

### How SecureShield Prevents This

✅ **Our JWT only contains non-sensitive data**:
```python
def create_token(username, role):
    payload = {
        'username': username,  # ✅ Public, but identifies user
        'role': role,          # ✅ Public, server knows the truth
        'exp': ...,            # ✅ Public, token expiration
        'iat': ...             # ✅ Public, issued time
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
```

✅ **Signature verification prevents tampering**:
```python
def decode_token(token):
    try:
        # Server verifies signature using SECRET_KEY
        # If token was modified, signature won't match
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.InvalidTokenError:
        return None  # ❌ Rejected - someone tried to tamper
```

✅ **Role claims are double-checked against database**:
```python
@admin_required
def delete_user(payload, user_id):
    # Even if JWT claims "Admin", we verify in database
    if payload['role'] != 'Admin':
        return jsonify({'message': 'Admin access required'}), 403
```

### Best Practices We Implemented

| Practice | Implementation |
|----------|----------------|
| **No passwords in JWT** | ✅ Only username, role, exp, iat |
| **HTTPS only** | ⚠️ Use in production (configured via SECRET_KEY management) |
| **Short expiration** | ✅ 24 hours (reasonable balance) |
| **Token blacklist** | ✅ /logout invalidates tokens immediately |
| **Signature validation** | ✅ All tokens verified with SECRET_KEY |
| **Server-side role verification** | ✅ JWT role is guidance; database is source of truth |
| **Rate limiting** | ⚠️ Recommended for production |
| **Rotate SECRET_KEY** | ⚠️ Periodic rotation recommended |

---

## Summary

### Salting:
- Defeats Rainbow Table attacks by adding unique random data to each password
- Bcrypt handles salt generation automatically
- Makes password cracking computationally infeasible at scale

### JWT Payload:
- Should contain **only non-sensitive claims** (username, role, expiration)
- **Never store passwords** or sensitive information
- **Payload is NOT encrypted** (only Base64-encoded)
- **Server must verify signature** to prevent tampering
- **Database should remain source of truth** for sensitive decisions

---

## References
- OWASP: Password Storage Cheat Sheet
- JWT Best Current Practices (RFC 8949)
- Bcrypt Algorithm Overview
- Rainbow Table Attack Documentation
