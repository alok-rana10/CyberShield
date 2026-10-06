# CyberShield API Specification — Authentication & RBAC (Phase 3)

## Base URL
All API endpoints are prefixed with `/api/v1`.

---

## 1. Authentication Endpoints

### 1.1 Register New User
- **Method**: `POST`
- **Path**: `/api/v1/auth/register`
- **Authentication**: None
- **Purpose**: Registers a new user account with Argon2id password hashing and audit logging.

#### Request Body
```json
{
  "email": "operator@example.com",
  "password": "CyberShield#2026!Secure",
  "full_name": "Alice Operator",
  "role": "analyst"
}
```

#### Password Requirements
- Minimum 8 characters, maximum 128 characters
- At least one lowercase letter (`[a-z]`)
- At least one uppercase letter (`[A-Z]`)
- At least one decimal digit (`[0-9]`)
- At least one special symbol (`[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`])

#### Response (`201 Created`)
```json
{
  "id": "c8a41249-1663-490f-9031-294b2a8d11c4",
  "email": "operator@example.com",
  "full_name": "Alice Operator",
  "role": "analyst",
  "is_active": true,
  "created_at": "2026-10-06T20:44:11.285568Z",
  "last_login_at": null
}
```

#### Error Responses
- `409 Conflict`: Email address is already registered.
- `422 Unprocessable Entity`: Password complexity failure or invalid email.

---

### 1.2 User Login
- **Method**: `POST`
- **Path**: `/api/v1/auth/login`
- **Authentication**: None
- **Purpose**: Authenticates user credentials and issues a signed JWT access token.

#### Request Body
```json
{
  "email": "operator@example.com",
  "password": "CyberShield#2026!Secure"
}
```

#### Response (`200 OK`)
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 1800,
  "user": {
    "id": "c8a41249-1663-490f-9031-294b2a8d11c4",
    "email": "operator@example.com",
    "full_name": "Alice Operator",
    "role": "analyst",
    "is_active": true,
    "created_at": "2026-10-06T20:44:11.285568Z",
    "last_login_at": "2026-10-06T20:45:00.123456Z"
  }
}
```

#### Error Responses
- `401 Unauthorized`: `"Invalid email or password."` (Generic message prevents account enumeration).
- `403 Forbidden`: Account is inactive or deactivated.

---

### 1.3 Get Current User Profile
- **Method**: `GET`
- **Path**: `/api/v1/auth/me`
- **Authentication**: `Bearer <token>`
- **Purpose**: Retrieves the authenticated user's profile.

#### Response (`200 OK`)
```json
{
  "id": "c8a41249-1663-490f-9031-294b2a8d11c4",
  "email": "operator@example.com",
  "full_name": "Alice Operator",
  "role": "analyst",
  "is_active": true,
  "created_at": "2026-10-06T20:44:11.285568Z",
  "last_login_at": "2026-10-06T20:45:00.123456Z"
}
```

#### Error Responses
- `401 Unauthorized`: Missing, expired, or invalid JWT access token.
- `403 Forbidden`: Inactive user account.

---

## 2. Role-Based Access Control (RBAC)

CyberShield defines three hierarchical roles:

| Role | Hierarchy / Capabilities |
| :--- | :--- |
| `admin` | Full administrative control, system auditing, baseline configuration |
| `analyst` | Authorized scanning, header evaluation, FIM verification, log analysis, finding status updates |
| `viewer` | Read-only observation of posture dashboard and exported security reports |

### Hierarchy Definition
- `admin` $\supset$ `analyst` $\supset$ `viewer`

---

## 3. Audit Logging Guarantees

Every security-sensitive event is automatically persisted in the `audit_logs` table:
- Actions: `USER_REGISTER_SUCCESS`, `USER_REGISTER_DUPLICATE`, `LOGIN_SUCCESS`, `LOGIN_FAILED_USER_NOT_FOUND`, `LOGIN_FAILED_PASSWORD_MISMATCH`, `AUTH_TOKEN_INVALID`, `AUTH_TOKEN_EXPIRED`, `AUTHORIZATION_DENIED`.
- **Zero-Credential Policy**: Passwords, tokens, authorization headers, and secrets are automatically redacted (`"[REDACTED]"`) prior to storage.
